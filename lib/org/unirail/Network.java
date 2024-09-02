//MIT License
//
//Copyright © 2020 Chikirev Sirguy, Unirail Group. All rights reserved.
//For inquiries, please contact:  al8v5C6HU4UtqE9@gmail.com
//GitHub Repository: https://github.com/AdHoc-Protocol
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to use,
//copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit others to do so, under the following conditions:
//
//1. The above copyright notice and this permission notice must be included in all
//   copies or substantial portions of the Software.
//
//2. Users of the Software must provide a clear acknowledgment in their user
//   documentation or other materials that their solution includes or is based on
//   this Software. This acknowledgment should be prominent and easily visible,
//   and can be formatted as follows:
//   "This product includes software developed by Chikirev Sirguy and the Unirail Group
//   (https://github.com/AdHoc-Protocol)."
//
//3. If you modify the Software and distribute it, you must include a prominent notice
//   stating that you have changed the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
//OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
package org.unirail;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ObjIntConsumer;

public interface Network {
	
	abstract class TCP< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > {
//#region > TCP code
//#endregion > Network.TCP
		
		public final           Channel< SRC, DST >                     channels;
		protected final        ThreadLocal< AdHoc.Pool< ByteBuffer > > buffers;
		protected static final long                                    FREE = -1;
		
		public final Function< TCP< SRC, DST >, Channel< SRC, DST > > new_channel;
		
		public       Duration timeout = Duration.ofMinutes( 5 );
		public final String   name;
		
		public TCP( String name, Function< TCP< SRC, DST >, Channel< SRC, DST > > new_channel, int buffer_size, Duration timeout ) {
			this.name    = name;
			this.timeout = timeout;
			channels     = ( this.new_channel = new_channel ).apply( this );
			buffers      = ThreadLocal.withInitial( () -> new AdHoc.Pool< ByteBuffer >( () -> ByteBuffer.allocateDirect( buffer_size ).order( ByteOrder.LITTLE_ENDIAN ) ) );
		}
		
		protected Channel< SRC, DST > allocate() {
			
			Channel< SRC, DST > ch = channels;
			for( ; !Channel.receive_time_.compareAndSet( ch, FREE, System.currentTimeMillis() ); ch = ch.next )
				if( ch.next == null ) {
					Channel< SRC, DST > ret = this.new_channel.apply( this );
					ret.receive_time = ret.transmit_time = System.currentTimeMillis();
					
					while( !Channel.next_.compareAndSet( ch, null, ret ) )
						ch = ch.next;
					
					return ret;
				}
			
			ch.transmit_time = System.currentTimeMillis();
			return ch;
		}
		
		public BiConsumer< Object, Throwable > onFailure = ( src, e ) ->
		{
			System.out.println( "onFailure" );
			if( AdHoc.debug_mode )
				System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( new Throwable( "onFailure" ) ) );
			
			System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( e ) );
		};
		
		public ObjIntConsumer< Channel< SRC, DST > > onEvent =
				( channel, event ) ->
				{
					if( AdHoc.debug_mode )
						System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( new Throwable( "onEvent" ) ) );
					
					switch( event ) {
						case Channel.Event.EXT_INT_CONNECT:
							System.out.println( channel.host + ":Received connection from " + channel.peer_ip );
							return;
						case Channel.Event.INT_EXT_CONNECT:
							System.out.println( channel.host + ":Connected  to " + channel.peer_ip );
							return;
						case Channel.Event.EXT_INT_DISCONNECT:
							System.out.println( channel.host + ":Remote peer " + channel.peer_ip + " has dropped the connection." );
							return;
						case Channel.Event.INT_EXT_DISCONNECT:
							System.out.println( channel.host + ":This host has dropped the connection to " + channel.peer_ip );
							return;
						case Channel.Event.TIMEOUT:
							System.out.println( channel.host + ":Timeout while receiving from " + channel.peer_ip );
							return;
						case ( int ) WebSocket.Event.EXT_INT_CONNECT:
							System.out.println( channel.host + ":Websocket from " + channel.peer_ip );
							return;
						case ( int ) WebSocket.Event.INT_EXT_CONNECT:
							System.out.println( channel.host + ":Websocket to " + channel.peer_ip );
							return;
						case ( int ) WebSocket.Event.PING:
							System.out.println( channel.host + ":PING from " + channel.peer_ip );
							return;
						case ( int ) WebSocket.Event.PONG:
							System.out.println( channel.host + ":PONG from " + channel.peer_ip );
							return;
						default:
							System.out.println( channel.host + ": from" + channel.peer_ip + " event: " + event );
					}
				};
		
		public static class Channel< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > implements CompletionHandler< Integer, Object >, Closeable {
//#region > Channel code
//#endregion > Network.TCP.Channel
			
			public @interface Event {
				int
						EXT_INT_CONNECT    = 0,
						INT_EXT_CONNECT    = 1,
						EXT_INT_DISCONNECT = 2,
						INT_EXT_DISCONNECT = 3,
						TIMEOUT            = 4;
			}
			
			public SocketAddress peer_ip;
			public long          peer_id    = 0;
			public long          session_id = 0;
			
			public AsynchronousSocketChannel ext;
			
			public ByteBuffer transmit_buffer;
			public ByteBuffer receive_buffer;
			
			public Duration timeout;
			
			public volatile long receive_time  = FREE;
			public          long transmit_time = FREE;
			
			public boolean is_active() { return 0 < receive_time; }
			
			public final TCP< SRC, DST > host;
			
			public Channel( TCP< SRC, DST > host ) { timeout = ( this.host = host ).timeout; }
			
			public long maintenance( long time ) {
				time -= timeout.toMillis();
				time = Math.min( receive_time - time, transmit_time - time );
				
				if( 500 < time ) return time;
				
				if( ext == null )
					close_and_dispose();
				else
					close();
				return Long.MAX_VALUE;
			}
			
			//close connections but preserve state
			public void close() {
				if( ext == null )
					return;
				
				if( ext.isOpen() )
					try {
						//!!!!!!!!! CRITICAL:
						//When using a connection-oriented Socket, always call the Shutdown method before
						//closing the Socket. This ensures that all data is sent and received on the
						//connected socket before it is closed.
						//
						//Call the Close method to free all managed and unmanaged resources associated
						//with the Socket. Do not attempt to reuse the Socket after closing.
						
						ext.shutdownInput();
						ext.shutdownOutput();
						ext.close();
						closing = false;
					} catch( IOException e ) {
						host.onFailure.accept( this, e );
					}
				
				ext           = null;
				transmit_lock = 1;
				host.onEvent.accept( this, Event.INT_EXT_DISCONNECT );
				
				if( ( transmitter == null || !transmitter.isOpen() ) && ( receiver == null || !receiver.isOpen() ) )
					close_and_dispose();
			}
			
			public Consumer< Channel< SRC, DST > > on_conneced;
			public Consumer< Channel< SRC, DST > > on_disposed;
			
			public void close_and_dispose() {
				
				if( receive_time_.getAndSet( this, FREE ) == FREE ) return;
				
				close();
				if( transmitter != null )
					try {
						transmitter.close();
					} catch( IOException e ) {
						host.onFailure.accept( this, e );
					}
				
				if( receiver != null )
					try {
						receiver.close();
					} catch( IOException e ) {
						host.onFailure.accept( this, e );
					}
				
				ext     = null;
				peer_ip = null;
				
				if( transmit_buffer != null ) {
					host.buffers.get().put( transmit_buffer.clear() );
					transmit_buffer = null;
				}
				
				if( receive_buffer != null ) {
					host.buffers.get().put( receive_buffer.clear() );
					receive_buffer = null;
				}
				
				if( on_disposed != null )
					on_disposed.accept( this );
			}
			
			@Override
			public void failed( Throwable e, Object o ) {
				if( e instanceof InterruptedByTimeoutException )
					host.onEvent.accept( this, Event.TIMEOUT );
				else
					host.onFailure.accept( this, e );
			}
			// Java socket API limitation:
			// The methods shutdownOutput() do not guarantee that all sent data has been transmitted to the peer.
			// To ensure that all outgoing data is fully transmitted to the peer, it's necessary to close the socket with a reasonable delay.
			
			void closing() {
				closing       = true;
				receive_time = transmit_time = System.currentTimeMillis() +  3000 - timeout.toMillis();
			}
			
			boolean closing = false;
			
			@Override
			public void completed( Integer result, Object internal ) {
				if( !closing )
					if( result == -1 ) {
						host.onEvent.accept( this, internal == transmitter ? Event.INT_EXT_DISCONNECT : Event.EXT_INT_DISCONNECT );
						close();
					} else if( internal == transmitter ) {
						transmit_time = System.currentTimeMillis();
						transmit();
					} else {
						receive_time = System.currentTimeMillis();
						receive_buffer.flip();
						receive();
					}
			}

//#region Receiver
			
			public          DST     receiver;
			public volatile boolean stop_receiving;
			
			public void start_receive() {
				if( stop_receiving )
					try {
						stop_receiving = false;
						ext.read( receive_buffer.clear(), receiver, this );
					} catch( Exception e ) {
						host.onFailure.accept( this, e );
					}
			}
			
			protected void receiver_connected( AsynchronousSocketChannel ext ) {
				this.ext     = ext;
				receive_time = System.currentTimeMillis();
				try {
					peer_ip = this.ext.getRemoteAddress();
				} catch( IOException e ) {
					host.onFailure.accept( this, e );
				}
				
				host.onEvent.accept( this, Event.EXT_INT_CONNECT );
				
				if( !ext.isOpen() ) { //The incoming connection is closed within the event handler.
					close_and_dispose();
					return;
				}
				
				final AdHoc.Pool< ByteBuffer > pool = host.buffers.get();
				if( receive_buffer == null )
					receive_buffer = pool.get();
				
				stop_receiving = false;
				
				
				if( transmitter == null ) {
					this.ext.read( receive_buffer, receiver, this ); //trigger receiving
					return;
				}
				
				transmit_lock = 0; //unlock
				if( transmit_buffer == null ) transmit_buffer = pool.get();
				this.ext.read( receive_buffer, receiver, this ); //trigger receiving
				if( on_conneced != null ) on_conneced.accept( this );
				transmitter.subscribe_on_new_bytes_to_transmit_arrive( this::on_new_bytes_to_transmit_arrive );
			}
			
			protected void receive() {
				
				try {
					if( stop_receiving ) {
						//ext.shutdownInput(); somehow affect on ext.write()
						return;
					}
					receive( receive_buffer );
					if( stop_receiving ) {
						//ext.shutdownInput();  somehow affect on ext.write()
						return;
					}
					
					ext.read( receive_buffer, receiver, this );
				} catch( Exception e ) {
					host.onFailure.accept( this, e );
				}
			}
			
			//manage ByteBuffer params
			protected ByteBuffer receive( ByteBuffer src ) throws Exception {
				receiver.write( src );
				return src.clear();
			}
//#endregion
//#region Transmitter
			
			public             SRC                             transmitter;
			protected volatile int                             transmit_lock = 1;
			public             Consumer< Channel< SRC, DST > > on_sent; //Event handler called when all available in socket bytes have been sent
			
			protected void transmitter_connected() {
				transmit_time = System.currentTimeMillis();
				try {
					peer_ip = ext.getRemoteAddress();
				} catch( IOException e ) {
					host.onFailure.accept( this, e );
				}
				host.onEvent.accept( this, Event.INT_EXT_CONNECT );
				
				final AdHoc.Pool< ByteBuffer > array = host.buffers.get();
				if( transmit_buffer == null ) transmit_buffer = array.get();
				
				transmit_lock = 0;
				transmitter.subscribe_on_new_bytes_to_transmit_arrive( this::on_new_bytes_to_transmit_arrive );
				
				if( receiver == null )
					return;
				if( receive_buffer == null )
					receive_buffer = array.get();
				
				if( on_conneced != null )
					on_conneced.accept( this );
				
				ext.read( receive_buffer, receiver, this ); //full duplex
			}
			
			protected void on_new_bytes_to_transmit_arrive( AdHoc.BytesSrc src ) { //Callback function called when new bytes in the source are available for transmission
				if( transmit_lock_.getAndIncrement( this ) == 0 )
					transmit();
			}
			
			void transmit() {
				do
					try {
						if( transmit( transmit_buffer.clear() ) ) {
							ext.write( transmit_buffer, transmitter, this );
							return;
						}
					} catch( Exception e ) {
						host.onFailure.accept( this, e );
					}
				while( transmit_lock_.getAndSet( this, 0 ) != 0 );
				
				if( on_sent != null )
					on_sent.accept( this );
			}
			
			//if return true: bytes in ByteBuffer dst are ready for sending
			protected boolean transmit( ByteBuffer dst ) throws Exception {
				boolean ret = 0 < transmitter.read( dst );
				dst.flip();
				return ret;
			}
//#endregion
			
			volatile               Channel< SRC, DST >                             next           = null;
			protected static final AtomicLongFieldUpdater< Channel >               receive_time_  = AtomicLongFieldUpdater.newUpdater( Channel.class, "receive_time" );
			protected static final AtomicIntegerFieldUpdater< Channel >            transmit_lock_ = AtomicIntegerFieldUpdater.newUpdater( Channel.class, "transmit_lock" );
			protected static final AtomicReferenceFieldUpdater< Channel, Channel > next_          = AtomicReferenceFieldUpdater.newUpdater( Channel.class, Channel.class, "next" );
		}
		
		public static class WebSocket< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > extends TCP.Channel< SRC, DST > {
//#region > WebSocket code
//#endregion > Network.TCP.WebSocket
			
			public @interface Event {
				int
						INT_EXT_CONNECT = 6,
						EXT_INT_CONNECT = 7,
						CLOSE           = OPCode.CLOSE,
						PING            = OPCode.PING,
						PONG            = OPCode.PONG,
						EMPTY_FRAME     = 11;
			}
			
			//Websocket need TCP server with buffers size at least 256 bytes
			public WebSocket( TCP< SRC, DST > host ) { super( host ); }
			
			public void close_gracefully( int code, String why ) {
				ControlFrameData frame_data = catch_urgent_frame(); //try reuse
				if( frame_data == null )
					frame_data = frames.get().get();
				
				frame_data.OPcode = OPCode.CLOSE;
				
				frame_data.buffer[ 0 ] = ( byte ) ( code >>> 8 ); //embed code
				frame_data.buffer[ 1 ] = ( byte ) code;
				if( why == null )
					frame_data.buffer_bytes = 2;
				else {
					for( int i = 0, max = why.length(); i < max; i++ )
					     frame_data.buffer[ i + 2 ] = ( byte ) why.charAt( i );
					
					frame_data.buffer_bytes = 2 + why.length();
				}
				
				recycle_frame( urgent.getAndSet( this, frame_data ) );
				on_new_bytes_to_transmit_arrive( null ); //trigger transmitting
			}
			
			public void ping( String msg ) {
				ControlFrameData frame_data = catch_urgent_frame(); //try reuse
				if( frame_data == null )
					frame_data = frames.get().get();
				
				if( msg == null )
					frame_data.buffer_bytes = 0;
				else {
					for( int i = 0, max = msg.length(); i < max; i++ )
					     frame_data.buffer[ i ] = ( byte ) msg.charAt( i );
					
					frame_data.buffer_bytes = msg.length();
				}
				
				recycle_frame( urgent.getAndSet( this, frame_data ) );
				on_new_bytes_to_transmit_arrive( null ); //trigger transmitting
			}
			
			@Override
			public void close() {
				state              = State.HANDSHAKE;
				sent_closing_frame = false;
				frame_bytes_left   = 0;
				if( frame_data != null )
					recycle_frame( frame_data );
				super.close();
			}
//#region Transmitting
			
			private  boolean          sent_closing_frame = false;
			volatile ControlFrameData urgent_frame_data;
			
			//if return true: bytes int ByteBuffer dst are ready for sending
			@Override
			protected boolean transmit( ByteBuffer dst ) throws Exception { //transmitting
				
				ControlFrameData frame_data = catch_urgent_frame(); //catch urgent
				
				if( frame_data == null ) {
					frame_data = WebSocket.frame.get( this );
					if( !catch_frame_send() )
						frame_data = null;
				}
				
				//https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
				
				//0                   1                   2                   3
				//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				//+-+-+-+-+-------+-+-------------+-------------------------------+
				//|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
				//|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
				//|N|V|V|V|       |S|             |   (if payload len==126/127)   |
				//| |1|2|3|       |K|             |                               |
				//+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
				
				int s = dst.position( ( frame_data != null ? frame_data.buffer_bytes + 2 : 0 ) + 10 ).position(); //offset 6 byte. preallocate place for max possible header length
				
				if( 0 < transmitter.read( dst ) ) { //receive data into `dst` start from s position
					
					dst.flip();
					final int len = dst.limit() - s;
					
					if( len < 126 ) { //if 0-125,
						dst.position( s -= 2 );
						dst.put( s, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) ); //always last and binary
						dst.put( s + 1, ( byte ) len );                          //that is the payload length
					} else if( len < 0x1_0000 ) {
						dst.position( s -= 4 );
						dst.put( s, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) ); //always last and binary
						dst.put( s + 1, ( byte ) 126 );                          //If 126,
						dst.put( s + 2, ( byte ) ( len >> 8 ) );                   //the following 2 bytes interpreted as a 16 -bit unsigned integer are the payload length.
						dst.put( s + 3, ( byte ) len );
					} else {
						dst.position( s -= 10 );
						dst.put( s, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) ); //always last and binary
						dst.put( s + 1, ( byte ) 127 );                          //If 127,
						dst.put( s + 2, ( byte ) 0 );                            //the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length.
						dst.put( s + 3, ( byte ) 0 );
						dst.put( s + 4, ( byte ) 0 );
						dst.put( s + 5, ( byte ) 0 );
						dst.put( s + 6, ( byte ) ( len >> 24 ) );
						dst.put( s + 7, ( byte ) ( len >> 16 ) );
						dst.put( s + 8, ( byte ) ( len >> 8 ) );
						dst.put( s + 9, ( byte ) len );
					}
					
					if( frame_data != null ) {
						sent_closing_frame = frame_data.OPcode == OPCode.CLOSE;
						recycle_frame( frame_data.get_frame( dst.position( s -= frame_data.buffer_bytes + 2 ) ) ); //write control frame into `dst` and recicle it
					}
					
					dst.position( s );
					return true;
				}
				
				if( frame_data == null )
					return false;
				
				sent_closing_frame = frame_data.OPcode == OPCode.CLOSE;
				recycle_frame( frame_data.get_frame( dst.position( 0 ) ) ); //write control frame into `dst` and recicle it
				dst.flip();
				return true;
			}
//#endregion
//#region Receiving
			
			int state = State.HANDSHAKE;
			int OPcode,
					frame_bytes_left,
					BYTE,
					xor0, xor1, xor2, xor3;
			
			volatile ControlFrameData frame_data;
			volatile int              frame_lock = 0;
			
			protected void allocate_frame_data( @OPCode int OPcode ) {
				if( !frame_locker.compareAndSet( this, FRAME_READY, FRAME_STANDBY ) ) //try to reuse
				{
					frame_locker.set( this, FRAME_STANDBY );
					frame.set( this, frames.get().get() );
				}
				
				frame_data.buffer_bytes = 0;
				frame_data.OPcode       = OPcode;
			}
			
			protected void recycle_frame( ControlFrameData frame_data ) {
				if( frame_data == null )
					return;
				
				WebSocket.frame.compareAndSet( this, frame_data, null );
				frames.get().put( frame_data );
			}
			
			protected void frame_ready() {
				frame_locker.set( this, FRAME_READY );
				on_new_bytes_to_transmit_arrive( null ); //trigger transmitting
			}
			
			protected static final AtomicIntegerFieldUpdater< WebSocket > frame_locker = AtomicIntegerFieldUpdater.newUpdater( WebSocket.class, "frame_lock" );
			
			protected boolean catch_frame_send() {
				return frame_locker.compareAndSet( this, FRAME_READY, 0 );
			}
			
			protected static final AtomicReferenceFieldUpdater< WebSocket, ControlFrameData > frame = AtomicReferenceFieldUpdater.newUpdater( WebSocket.class, ControlFrameData.class, "frame_data" );
			
			protected ControlFrameData catch_urgent_frame() {
				return urgent.getAndSet( this, null );
			}
			
			protected static final AtomicReferenceFieldUpdater< WebSocket, ControlFrameData > urgent = AtomicReferenceFieldUpdater.newUpdater( WebSocket.class, ControlFrameData.class, "urgent_frame_data" );
			
			protected static final int FRAME_STANDBY = 1, FRAME_READY = 2;
			
			protected static class ControlFrameData {
				@OPCode
				int OPcode;
				int buffer_bytes = 0;
				final byte[]        buffer = new byte[ 125 ]; //All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented. https://datatracker.ietf.org/doc/html/rfc6455#section-5.5
				final MessageDigest sha;
				
				{
					try {
						sha = MessageDigest.getInstance( "SHA-1" );
					} catch( NoSuchAlgorithmException e ) {
						throw new RuntimeException( e );
					}
				}
				
				public void put_UPGRAGE_WEBSOCKET_responce( ByteBuffer dst, int len ) throws Exception {
					dst.clear().put( HTTP );
					sha.update( buffer, 0, len );
					sha.update( GUID, 0, GUID.length );
					int bytes = sha.digest( buffer, 0, buffer.length );
					sha.reset();
					base64( buffer, 0, bytes, dst );
					dst.put( rnrn ).flip();
				}
				
				private void base64( byte[] src, int off, int end, ByteBuffer dst ) {
					
					for( int max = off + ( end - off ) / 3 * 3; off < max; ) {
						int bits = ( src[ off++ ] & 0xff ) << 16 | ( src[ off++ ] & 0xff ) << 8 | ( src[ off++ ] & 0xff );
						dst
								.put( byte2char[ ( bits >>> 18 ) & 0x3f ] )
								.put( byte2char[ ( bits >>> 12 ) & 0x3f ] )
								.put( byte2char[ ( bits >>> 6 ) & 0x3f ] )
								.put( byte2char[ bits & 0x3f ] );
					}
					if( off == end )
						return;
					
					int b = src[ off++ ] & 0xff;
					dst.put( byte2char[ b >> 2 ] );
					if( off == end )
						dst.put( byte2char[ ( b << 4 ) & 0x3f ] ).put( ( byte ) '=' ).put( ( byte ) '=' );
					else
						dst.put( byte2char[ ( b << 4 ) & 0x3f | ( ( b = src[ off ] & 0xff ) >> 4 ) ] ).put( byte2char[ ( b << 2 ) & 0x3f ] ).put( ( byte ) '=' );
				}
				
				private static final byte[] byte2char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes();
				
				ControlFrameData get_frame( ByteBuffer dst ) {
					
					dst.put( ( byte ) ( Mask.FIN | OPcode ) );
					dst.put( ( byte ) buffer_bytes ); //always buffer_bytes < 126
					
					if( 0 < buffer_bytes )
						dst.put( buffer, 0, buffer_bytes );
					return this;
				}
				
				void put_data( ByteBuffer src, int end ) {
					int bytes = end - src.position();
					src.get( buffer, buffer_bytes, bytes );
					buffer_bytes += bytes;
				}
				
				static final byte[] GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".getBytes();
				static final byte[] rnrn = "\r\n\r\n".getBytes();
				static final byte[] HTTP = ( "HTTP/1.1 101 Switching Protocols\r\n"
						+ "Server: AdHoc\r\n"
						+ "Connection: Upgrade\r\n"
						+ "Upgrade: websocket\r\n"
						+ "Sec-WebSocket-Accept: " )
						.getBytes();
			}
			
			protected static final ThreadLocal< AdHoc.Pool< ControlFrameData > > frames = ThreadLocal.withInitial( () -> new AdHoc.Pool< ControlFrameData >( ControlFrameData::new ) );
			
			@Override
			protected ByteBuffer receive( ByteBuffer src ) throws Exception {
receiving:
				for( int index = 0; ; )
					switch( state ) {
						case State.HANDSHAKE:
							int i = src.limit();
							if(
									src.get( i - 4 ) == ( byte ) '\r' &&
											src.get( i - 3 ) == ( byte ) '\n' &&
											src.get( i - 2 ) == ( byte ) '\r' &&
											src.get( i - 1 ) == ( byte ) '\n' ) {
								i = 0;
								for( int max = src.limit(); i < max; i++ )
									switch( src.get( i ) ) //search Sec-WebSocket-Key header
									{
										case 'S':
										case 's':
											if( src.get( i + 3 ) == '-' &&
													src.get( i + 13 ) == '-' &&
													src.get( i + 17 ) == ':' )
												switch( ( char ) src.get( i + 16 ) ) {
													case 'Y':
													case 'y':
														switch( ( char ) src.get( i + 15 ) ) {
															case 'E':
															case 'e':
																switch( ( char ) src.get( i + 14 ) ) {
																	case 'K':
																	case 'k':
																		for( i += 18; i < max; i++ )
																			if( src.get( i ) != ' ' ) {
																				final AdHoc.Pool< ControlFrameData > pool   = frames.get();
																				final ControlFrameData               helper = pool.get();
																				
																				for( int e = i, ii = 0, b; e < max; e++, ii++ )
																					if( ( b = src.get( e ) ) == ' ' || b == '\r' ) {
																						state = State.NEW_FRAME;
																						
																						helper.put_UPGRAGE_WEBSOCKET_responce( transmit_buffer, ii );
																						
																						pool.put( helper ); //return helper back
																						
																						transmit_lock_.getAndIncrement( this );          //!! lock transmitter. in java it is always async
																						ext.write( transmit_buffer, transmitter, this ); //start transmitting
																						
																						host.onEvent.accept( this, Event.EXT_INT_CONNECT );
																						break receiving;
																					} else
																						helper.buffer[ ii ] = ( byte ) b; //getting Sec-WebSocket-Key value into tmp
																			}
																}
														}
												}
									}
								host.onFailure.accept( this, new RuntimeException( "Unexpected handshake:" + toString( src ) ) );
								close_and_dispose();
								break receiving;
							}
							
							src.position( src.limit() ).limit( src.capacity() ); //allocate space to continue receiving
							return src;
						case State.NEW_FRAME:
							
							if( !get_byte( State.NEW_FRAME ) )
								break receiving;
							OPcode = BYTE & Mask.OPCODE;
						
						case State.PAYLOAD_LENGTH_BYTE:
							if( !get_byte( State.PAYLOAD_LENGTH_BYTE ) )
								break receiving;
							
							if( ( BYTE & Mask.MASK ) == 0 ) {
								host.onFailure.accept( this, new RuntimeException( "Frames sent from client to server have this bit set to 1" ) );
								close();
								break receiving;
							}
							
							xor0 = 0;
							//https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
							if( 125 < ( frame_bytes_left = BYTE & Mask.LEN ) ) {                                    //if 0-125, that is the payload length.
								xor0             = frame_bytes_left == 126 ? //If 126, the following 2 bytes interpreted as a 16 -bit unsigned integer are the payload length.
										2
										: 4; //If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length.
								frame_bytes_left = 0;
							}
						case State.PAYLOAD_LENGTH_BYTES:
							for( ; 0 < xor0; xor0-- )
								if( get_byte( State.PAYLOAD_LENGTH_BYTES ) )
									frame_bytes_left = ( frame_bytes_left << 8 ) | BYTE;
								else
									break receiving;
						
						case State.XOR0:
							if( get_byte( State.XOR0 ) )
								xor0 = BYTE;
							else
								break receiving;
						case State.XOR1:
							if( get_byte( State.XOR1 ) )
								xor1 = BYTE;
							else
								break receiving;
						case State.XOR2:
							if( get_byte( State.XOR2 ) )
								xor2 = BYTE;
							else
								break receiving;
						case State.XOR3:
							if( get_byte( State.XOR3 ) )
								xor3 = BYTE;
							else
								break receiving;
							
							switch( OPcode ) {
								case OPCode.PING:
									
									allocate_frame_data( OPCode.PONG );
									
									if( frame_bytes_left == 0 ) {
										host.onEvent.accept( this, Event.PING );
										frame_ready();
										state = State.NEW_FRAME;
										continue;
									}
									break;
								
								case OPCode.CLOSE:
									if( sent_closing_frame ) {
										host.onEvent.accept( this, Event.CLOSE );
										close(); //gracefully the close confirmation frame was sent
										break receiving;
									}
									
									allocate_frame_data( OPCode.CLOSE );
									
									if( frame_bytes_left == 0 ) {
										host.onEvent.accept( this, Event.CLOSE );
										frame_ready();
										state = State.NEW_FRAME;
										continue;
									}
									break;
								case OPCode.PONG: //discard
									host.onEvent.accept( this, Event.PONG );
									state = frame_bytes_left == 0 ? State.NEW_FRAME : State.DISCARD;
									continue;
								default:
									if( frame_bytes_left == 0 ) //empty frame
									{
										host.onEvent.accept( this, Event.EMPTY_FRAME );
										state = State.NEW_FRAME;
										continue;
									}
							}
							
							index = src.position();
						case State.DATA0:
							if( decode_and_continue( index ) )
								continue;
							break receiving;
						case State.DATA1:
							if( need_more_bytes( State.DATA1, index ) )
								break receiving;
							if( decode_byte_and_continue( xor1, index++ ) )
								continue;
						
						case State.DATA2:
							if( need_more_bytes( State.DATA2, index ) )
								break receiving;
							if( decode_byte_and_continue( xor2, index++ ) )
								continue;
						case State.DATA3:
							if( need_more_bytes( State.DATA3, index ) )
								break receiving;
							if( decode_byte_and_continue( xor3, index++ ) )
								continue;
							
							if( decode_and_continue( index ) )
								continue;
							break receiving;
						
						case State.DISCARD:
							int bytes = Math.min( src.remaining(), frame_bytes_left );
							src.position( src.position() + bytes ); //discard
							if( ( frame_bytes_left -= bytes ) == 0 ) {
								state = State.NEW_FRAME;
								continue;
							}
							state = State.DISCARD; //trigger continue receiving more bytes
							break receiving;
					}
				
				//break receiving;
				return src.clear();
			}
			
			boolean decode_and_continue( int index ) throws IOException {
				for( ; ; ) {
					if( need_more_bytes( State.DATA0, index ) )
						return false;
					if( decode_byte_and_continue( xor0, index++ ) )
						return true;
					if( need_more_bytes( State.DATA1, index ) )
						return false;
					if( decode_byte_and_continue( xor1, index++ ) )
						return true;
					if( need_more_bytes( State.DATA2, index ) )
						return false;
					if( decode_byte_and_continue( xor2, index++ ) )
						return true;
					if( need_more_bytes( State.DATA3, index ) )
						return false;
					if( decode_byte_and_continue( xor3, index++ ) )
						return true;
				}
			}
			
			boolean need_more_bytes( int state_if_no_more_bytes, int index ) throws IOException {
				if( index < receive_buffer.limit() )
					return false;
				
				switch( OPcode ) {
					case OPCode.PING:
					case OPCode.CLOSE:
						frame_data.put_data( receive_buffer, index );
					default:
						receiver.write( receive_buffer );
				}
				
				state = frame_bytes_left == 0 ? State.NEW_FRAME : state_if_no_more_bytes;
				return true;
			}
			
			boolean decode_byte_and_continue( int XOR, int index ) throws IOException {
				
				receive_buffer.put( index, ( byte ) ( receive_buffer.get( index++ ) & 0xFF ^ XOR ) );
				if( 0 < --frame_bytes_left )
					return false;
				
				final int limit = receive_buffer.limit();
				
				switch( OPcode ) {
					case OPCode.PING:
					case OPCode.CLOSE:
						frame_data.put_data( receive_buffer, index );
						host.onEvent.accept( this, OPcode );
						frame_ready();
						break;
					default:
						receive_buffer.limit( index );
						receiver.write( receive_buffer );
				}
				
				state = State.NEW_FRAME; //continue receiving
				
				if( index < limit )
					receive_buffer.limit( limit ).position( index );
				return true;
			}
			
			boolean get_byte( int state_if_no_more_bytes ) {
				if( !receive_buffer.hasRemaining() ) {
					state = state_if_no_more_bytes;
					return false;
				}
				BYTE = receive_buffer.get() & 0xFF;
				return true;
			}
			
			String toString( ByteBuffer bb ) {
				byte[] dst = new byte[ bb.remaining() ];
				bb.get( dst );
				return new String( dst );
			}
			
			private @interface OPCode {
				int
						CONTINUATION = 0x00, //denotes a continuation frame
						TEXT_FRAME   = 0x01,   //denotes a text frame
						BINARY_FRAME = 0x02, //denotes a binary frame
						CLOSE        = 0x08,        //denotes a connection close
						PING         = 0x09,         //denotes a ping
						PONG         = 0x0A;         //denotes a pong
			}
			
			private @interface State {
				int
						HANDSHAKE            = 0,
						NEW_FRAME            = 1,
						PAYLOAD_LENGTH_BYTE  = 2,
						PAYLOAD_LENGTH_BYTES = 3,
						XOR0                 = 4,
						XOR1                 = 5,
						XOR2                 = 6,
						XOR3                 = 7,
						DATA0                = 8,
						DATA1                = 9,
						DATA2                = 10,
						DATA3                = 11,
						DISCARD              = 12;
			}
			
			private @interface Mask {
				int
						FIN    = 0b1000_0000,
						OPCODE = 0b0000_1111,
						MASK   = 0b1000_0000,
						LEN    = 0b0111_1111;
			}
//#endregion
			
			public static class Client< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > extends TCP< SRC, DST > {
//#region > WebSocket Client code
//#endregion > Network.TCP.WebSocket.Client
				
				//client is public for tuning. for example to set proxy ws.Options.Proxy = IWebProxy
				public final HttpClient client = HttpClient.newHttpClient();
				
				public Client( String name, Function< TCP< SRC, DST >, Channel< SRC, DST > > new_channel, int buffer_size ) {
					super( name, new_channel, buffer_size, Duration.ofDays( Integer.MAX_VALUE ) );
					channels.transmit_buffer = buffers.get().get();
				}
				
				private final AtomicBoolean transmit_lock = new AtomicBoolean( false );
				java.net.http.WebSocket.Listener listener = new java.net.http.WebSocket.Listener() {
					@Override
					public void onOpen( java.net.http.WebSocket ws ) {
						//The statusCode is an integer from the range 1000 <= code <= 4999. Status codes
						//1002, 1003, 1006, 1007, 1009, 1010, 1012, 1013 and 1015 are illegal. Behaviour
						//in respect to other status codes is implementation-specific. A legal reason is a
						//string that has a UTF-8 representation not longer than 123 bytes.
						channels.on_disposed  = ch -> ws.sendClose( 1000, "Bye" );
						channels.receive_time = System.currentTimeMillis();
						
						java.net.http.WebSocket.Listener.super.onOpen( ws );
						
						channels.transmitter.subscribe_on_new_bytes_to_transmit_arrive(
								src -> {
									if( !transmit_lock.getAndSet( true ) )
										transmit( ws );
								} );
						
						onConnected.accept( channels.transmitter );
					}
					
					private void transmit( java.net.http.WebSocket ws ) {
						try {
							if( 0 < channels.transmitter.read( channels.transmit_buffer.clear() ) ) {
								channels.transmit_buffer.flip();
								ws.sendBinary( channels.transmit_buffer, true ).thenAccept( this::transmit );
							} else {
								transmit_lock.set( false );
								if( channels.on_sent != null )
									channels.on_sent.accept( channels );
							}
						} catch( Throwable ex ) {
							onFailure.accept( WebSocket.Client.this, ex );
						}
					}
					
					@Override
					public CompletionStage< ? > onBinary( java.net.http.WebSocket ws, ByteBuffer data, boolean last ) {
						try {
							channels.receiver.write( data );
						} catch( Throwable e ) {
							onFailure.accept( WebSocket.Client.this, e );
						}
						
						return java.net.http.WebSocket.Listener.super.onBinary( ws, data, last );
					}
					
					@Override
					public void onError( java.net.http.WebSocket webSocket, Throwable e ) {
						
						onFailure.accept( WebSocket.Client.this, e );
						java.net.http.WebSocket.Listener.super.onError( webSocket, e );
					}
				};
				
				private Consumer< SRC > onConnected;
				
				private CompletableFuture< java.net.http.WebSocket > ws;
				
				private String toString;
				
				public void connect( URI server, Consumer< SRC > onConnected, Consumer< Throwable > onConnectingFailure ) { connect( server, onConnected, onConnectingFailure, Duration.ofSeconds( 5 ) ); }
				
				public void connect( URI server, Consumer< SRC > onConnected, Consumer< Throwable > onConnectingFailure, Duration connectingTimout ) {
					
					toString = new StringBuilder( 50 )
							.append( "Client " )
							.append( name )
							.append( " -> " )
							.append( server )
							.toString();
					
					this.onConnected = onConnected;
					ws               = client
							.newWebSocketBuilder()
							.connectTimeout( connectingTimout )
							.buildAsync( server, listener )
							.handle( ( ws, ex ) -> {
								if( ex != null )
									onConnectingFailure.accept( ex );
								return ws;
							} );
				}
				
				@Override
				public String toString() { return toString; }
			}
		}
		
		public static class Server< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > extends TCP< SRC, DST > {
//#region > Server code
//#endregion > Network.TCP.Server
			
			public static final ForkJoinPool             executor = new ForkJoinPool();
			final               AsynchronousChannelGroup group    = AsynchronousChannelGroup.withThreadPool( executor );
			
			public Server( String name,
			               Function< TCP< SRC, DST >, Channel< SRC, DST > > new_channel,
			               int buffer_size,
			               Duration timeout,
			               InetSocketAddress... ips ) throws IOException {
				super( name, new_channel, buffer_size, timeout );
				
				
				bind( ips );
			}
			
			public ArrayList< AsynchronousServerSocketChannel > tcp_listeners = new ArrayList<>();
			
			@Override
			public String toString() { return toString; }
			
			private String toString;
			
			public void bind( InetSocketAddress... ips ) throws IOException {
				StringBuilder sb = new StringBuilder( 50 )
						.append( "Server " )
						.append( name );
				
				for( InetSocketAddress ip : ips ) {
					sb.append( '\n' )
							.append( "\t\t -> " )
							.append( ip );
					final AsynchronousServerSocketChannel tcp_listener = AsynchronousServerSocketChannel.open( group )
							.setOption( StandardSocketOptions.SO_REUSEADDR, true )
							.bind( ip );
					
					tcp_listeners.add( tcp_listener );
					
					tcp_listener.accept( null,
							new CompletionHandler< AsynchronousSocketChannel, Void >() {
								@Override
								public void completed( AsynchronousSocketChannel client, Void v ) {
									allocate().receiver_connected( client );
									tcp_listener.accept( null, this ); //re-run
								}
								
								@Override
								public void failed( Throwable e, Void v ) { onFailure.accept( this, e ); }
							} );
				}
				
				toString = sb.toString();
			}
			
			
			private final Thread maintenance_thread = new Thread( "Maintain server " + name ) {
				@Override
				public synchronized void run() {
					for( ; ; )
						try {
							wait( maintenance( System.currentTimeMillis() ) );
						} catch( Exception ex ) {
							onFailure.accept( this, ex );
						}
				}
			};
			
			{
				maintenance_thread.setDaemon( true );
				maintenance_thread.start();
			}
			
			// Async forces the maintenance thread to wake up and perform maintenance immediately, 
			// regardless of the current schedule or timeout.
			public void maintenance() { maintenance_thread.notifyAll(); }
			
			// This method iterates through all active channels to determine the time 
			// for the next maintenance operation. It can be overridden if a different 
			// maintenance calculation logic is required
			protected long maintenance( long time ) {
				long timeout = maintenance_duty_cycle;
				for( Channel< SRC, DST > channel = channels; channel != null; channel = channel.next )
					if( channel.is_active() )
						timeout = Math.min( timeout, channel.maintenance( time ) );
				
				return timeout;
			}
			
			// Minimum timeout duration for maintenance tasks in milliseconds.
			public long maintenance_duty_cycle = 5000;
			
			public void shutdown() {
				for( Closeable closeable : tcp_listeners )
					try {
						closeable.close();
					} catch( IOException e ) {
						onFailure.accept( this, e );
					}
				
				for( Channel< SRC, DST > channel = channels; channel != null; channel = channel.next ) {
					if( channel.is_active() )
						channel.close_and_dispose();
				}
			}
		}
		
		public static class Client< SRC extends AdHoc.BytesSrc, DST extends AdHoc.BytesDst > extends TCP< SRC, DST > {
//#region > Client code
//#endregion > Network.TCP.Client
			
			public final String name;
			
			public Client( String name, Function< TCP< SRC, DST >, Channel< SRC, DST > > new_channel, int buffer_size ) {
				super( name, new_channel, buffer_size, Duration.ofDays( Integer.MAX_VALUE ) );
				this.name = name;
			}
			
			public void connect( InetSocketAddress server, Consumer< SRC > onConnected, Consumer< Throwable > onConnectingFailure ) {
				connect( server, onConnected, onConnectingFailure, Duration.ofMinutes( 5 ) );
			}
			
			Consumer< SRC > onConnected;
			
			public void connect( InetSocketAddress server, Consumer< SRC > onConnected, Consumer< Throwable > onConnectingFailure, Duration connectingTimout ) {
				toString = new StringBuilder( 50 )
						.append( "Client " )
						.append( name )
						.append( " -> " )
						.append( server )
						.toString();
				
				this.onConnected = onConnected;
				channels.peer_ip = server;
				try {
					( channels.ext = AsynchronousSocketChannel.open() ).connect( channels.peer_ip, null, on_connecting );
				} catch( IOException e ) {
					onFailure.accept( this, e );
					onConnectingFailure.accept( e );
					return;
				}
				
				Executors.newSingleThreadScheduledExecutor().schedule( () -> {
					if( !channels.ext.isOpen() )
						onConnectingFailure.accept( new Throwable( "Connection to the " + server + " in " + connectingTimout + ", timeout" ) );
				}, connectingTimout.getSeconds(), TimeUnit.SECONDS );
			}
			
			private final CompletionHandler< Void, Void > on_connecting = new CompletionHandler<>() {
				@Override
				public void completed( Void v, Void v2 ) {
					channels.transmitter_connected();
					onConnected.accept( channels.transmitter );
				}
				
				@Override
				public void failed( Throwable t, Void v2 ) {
					onFailure.accept( channels, t );
					channels.ext = null;
				}
			};
			private       String                          toString;
			
			@Override
			public String toString() { return toString; }
		}
	}
	
	class Wire {
		protected final ByteBuffer                 buffer;
		protected       AdHoc.BytesSrc             src;
		protected       Consumer< AdHoc.BytesSrc > subscriber;
		
		public Wire( AdHoc.BytesSrc src, AdHoc.BytesDst dst, int buffer_size ) {
			buffer = ByteBuffer.wrap( new byte[ buffer_size ] );
			connect( src, dst );
		}
		
		public void connect( AdHoc.BytesSrc src, AdHoc.BytesDst dst ) {
			if( this.src != null )
				this.src.subscribe_on_new_bytes_to_transmit_arrive( subscriber ); //off hook
			
			subscriber = ( this.src = src ).subscribe_on_new_bytes_to_transmit_arrive( ( SRC ) -> {
				try {
					while( 0 < SRC.read( buffer.clear() ) ) {
						buffer.flip();
						dst.write( buffer );
					}
				} catch( IOException e ) {
					System.out.println( "public void send_bytes " + e );
				}
			} );
		}
	}
	
	class UDP {
		//use TCP implementation over Wireguard https://www.wireguard.com/
	}
}