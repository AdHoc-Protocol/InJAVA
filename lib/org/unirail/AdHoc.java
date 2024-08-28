//  MIT License
//
//  Copyright © 2020 Chikirev Sirguy, Unirail Group. All rights reserved.
//  For inquiries, please contact:  al8v5C6HU4UtqE9@gmail.com
//  GitHub Repository: https://github.com/AdHoc-Protocol
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to use,
//  copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//  the Software, and to permit others to do so, under the following conditions:
//
//  1. The above copyright notice and this permission notice must be included in all
//     copies or substantial portions of the Software.
//
//  2. Users of the Software must provide a clear acknowledgment in their user
//     documentation or other materials that their solution includes or is based on
//     this Software. This acknowledgment should be prominent and easily visible,
//     and can be formatted as follows:
//     "This product includes software developed by Chikirev Sirguy and the Unirail Group
//     (https://github.com/AdHoc-Protocol)."
//
//  3. If you modify the Software and distribute it, you must include a prominent notice
//     stating that you have changed the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM,
//  OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
package org.unirail;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
import java.lang.ref.SoftReference;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.unirail.collections.LongRingBuffer;
import org.unirail.collections.RingBuffer;

public abstract class AdHoc {
//region CRC
	
	private static final int  CRC_LEN_BYTES = 2; //CRC len in bytes
	private static final char tab[]         = { 0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935 };
	
	//!!!!
	//Https://github.com/redis/redis/blob/95b1979c321eb6353f75df892ab8be68cf8f9a77/src/crc16.c
	//Output for "123456789" : 31C3 (12739)
	private static char crc16( int src, char crc ) {
		src &= 0xFF;
		crc = (char) (tab[(crc >> 12 ^ src >> 4) & 0x0F] ^ crc << 4);
		return (char) (tab[(crc >> 12 ^ src & 0x0F) & 0x0F] ^ crc << 4);
	}
//endregion
	
	protected static final int
			OK         = Integer.MAX_VALUE - 10,
			STR        = OK - 100,
			RETRY      = STR + 1,
			VAL4       = RETRY + 1,
			VAL8       = VAL4 + 1,
			INT1       = VAL8 + 1,
			INT2       = INT1 + 1,
			INT4       = INT2 + 1,
			LEN0       = INT4 + 1,
			LEN1       = LEN0 + 1,
			LEN2       = LEN1 + 1,
			BITS       = LEN2 + 1,
			BITS_BYTES = BITS + 1,
			VARINT     = BITS_BYTES + 1;
	
	protected int bit;
	
	public String str;
	
	protected int        bits;
	protected ByteBuffer buffer;
	protected int        mode;
	
	public String print_data() {
		final StringBuilder sb = new StringBuilder();
		sb.append( "Position: " ).append( buffer.position() ).append( ", Limit: " ).append( buffer.limit() ).append( ", Capacity: " ).append( buffer.capacity() ).append( '\n' );
		
		for( int i = 0; i < buffer.limit(); i++ )
		{
			byte b = buffer.get( i );
			sb.append( String.format( i == buffer.position() ? "%02X*" : "%02X ", b ) );
			
			//Print in rows of 16 bytes
			if( (i + 1) % 16 == 0 || i == buffer.limit() - 1 )
				sb.append( '\n' );
			else if( (i + 1) % 8 == 0 )
				sb.append( " " );
		}
		
		return sb.toString();
	}
	
	protected int  u4;
	public    long u8;
	public    long u8_;
	protected int  bytes_left;
	protected int  bytes_max;
	
	public interface BytesSrc extends ReadableByteChannel {
		Consumer<BytesSrc> subscribe_on_new_bytes_to_transmit_arrive( Consumer<BytesSrc> subscriber ); //Subscribe to be
		//notified when new
		//bytes are
		//available for
		//transmission
	}
	
	/**
	 write bytes
	 ATTENTION! The data in the provided buffer "src" may change due to buffer reuse.
	 */
	public interface BytesDst extends WritableByteChannel {
	}
	
	/**
	 Represents a stage within a channel, defining a processing state that
	 can transmit and receive packets. Each stage is uniquely identified and
	 can have specific behaviors for packet transmission and reception.
	 */
	public static class Stage {
		//Unique identifier for the stage.
		public final int uid;
		
		//Name of the stage.
		public final String name;
		
		//Timeout duration for the stage. If not set, the stage can remain indefinitely.
		public final Duration timeout;
		
		//Constructor to initialize the stage with its properties.
		public Stage( int uid, String name, Duration timeout ) {
			this.uid     = uid;
			this.name    = name;
			this.timeout = timeout;
		}
		
		//Function to handle actions when transmitting packets. Defaults to ERROR stage if not specified.
		public Stage on_transmitting( int id ) { return ERROR; }
		
		//Function to handle actions when receiving packets. Defaults to ERROR stage if not specified.
		public Stage on_receiving( int id ) { return ERROR; }
		
		//Override toString method to return the stage name.
		@Override
		public String toString() { return name; }
		
		//Predefined EXIT stage to drop the connection after receiving the packet.
		public static final Stage EXIT = new Stage( 0xFFFF, "Exit", Duration.ofHours( 0xFFFF ) );
		
		//Predefined ERROR stage to handle errors.
		public static final Stage ERROR = new Stage( 0xFFFF, "Error", Duration.ofHours( 0xFFFF ) );
	}
	
	public static abstract class Receiver extends Context.Receiver implements AdHoc.BytesDst {
		
		public volatile      EventsHandler                                        handler;
		private static final AtomicReferenceFieldUpdater<Receiver, EventsHandler> exchange = AtomicReferenceFieldUpdater.newUpdater( Receiver.class, EventsHandler.class, "handler" );
		
		public EventsHandler exchange( EventsHandler dst ) { return exchange.getAndSet( this, dst ); }
		
		private final int id_bytes;
		
		public Receiver( EventsHandler handler, int id_bytes ) {
			
			this.handler = handler;
			bytes_left   = bytes_max = this.id_bytes = id_bytes;
		}
		
		public static OnError.Handler error_handler = OnError.Handler.DEFAULT;
		
		public @interface OnError {
			int FFFF_ERROR           = 0,
					CRC_ERROR        = 1,
					BYTES_DISTORTION = 3,
					OVERFLOW         = 4,
					INVALID_ID       = 5;
			
			interface Handler {
				Handler DEFAULT = new Handler() { };
				
				default void error( AdHoc.BytesSrc src, int error, Throwable ex ) {
					switch( error )
					{
						case OVERFLOW:
							System.out.println( "OVERFLOW src:\n" + src + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
					}
				}
				
				default void error( AdHoc.BytesDst dst, int error, Throwable ex ) {
					switch( error )
					{
						case FFFF_ERROR:
							System.out.println( "FFFF_ERROR dst:\n" + dst + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
						case CRC_ERROR:
							System.out.println( "CRC_ERROR dst:\n" + dst + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
						case BYTES_DISTORTION:
							System.out.println( "BYTES_DISTORTION dst:\n" + dst + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
						case OVERFLOW:
							System.out.println( "OVERFLOW dst:\n" + dst + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
						case INVALID_ID:
							System.out.println( "INVALID_ID dst:\n" + dst + " at:\n" + (ex == null ? "" : StackTracePrinter.ONE.stackTrace( ex )) );
					}
				}
			}
		}
		
		public interface EventsHandler {
			default void on_receiving( Receiver src, BytesDst dst ) { }
			
			default void on_received( Receiver src, BytesDst dst )  { }
		}
		
		public interface BytesDst {
			boolean __put_bytes( Receiver src );
			
			int __id();
		}
		
		public static class Framing implements AdHoc.BytesDst, EventsHandler {
			public               Receiver                                            upper_layer;
			public volatile      EventsHandler                                       handler;
			private static final AtomicReferenceFieldUpdater<Framing, EventsHandler> exchange = AtomicReferenceFieldUpdater.newUpdater( Framing.class, EventsHandler.class, "handler" );
			
			public EventsHandler exchange( EventsHandler dst ) { return exchange.getAndSet( this, dst ); }
			
			public Framing( Receiver upper_layer )             { switch_to( upper_layer ); }
			
			public void switch_to( Receiver upper_layer ) {
				reset();
				
				if( this.upper_layer != null )
				{
					this.upper_layer.reset();
					upper_layer.exchange( handler ); //off hook
				}
				
				handler = (this.upper_layer = upper_layer).exchange( this );
			}
			
			private void error_reset( @OnError int error ) {
				error_handler.error( this, error, null );
				reset();
			}
			
			@Override
			public void close() {
				reset();
				upper_layer.close();
			}
			
			private void reset() {
				
				bits                         = 0;
				shift                        = 0;
				crc0                         = 0;
				crc1                         = 0;
				crc2                         = 0;
				crc3                         = 0;
				dst_byte                     = 0;
				raw                          = 0;
				waiting_for_dispatching_pack = null;
				
				if( !FF ) //not on next frame start position... switch to search next frame start
					//position mode
					state = State.SEEK_FF;
			}
			
			/**
			 write bytes
			 ATTENTION! The data in the provided buffer "src" may change due to buffer reuse.
			 */
			@Override
			public int write( ByteBuffer src ) throws IOException {
				if( src == null )
				{
					reset();
					return -1;
				}
				final int remaining = src.remaining();
				if( remaining < 1 )
					return 0;
				final int limit = src.limit();
				dst_byte = 0;
init:
				switch( state )
				{
					case State.SEEK_FF: //bytes distortion was detected, skip bytes until FF sync mark
						while( src.hasRemaining() )
							if( src.get() == (byte) 0xFF )
							{
								state = State.NORMAL;
								if( FF )
									error_handler.error( this, OnError.FFFF_ERROR, null );
								FF = true;
								if( src.hasRemaining() )
									break init;
								
								return remaining;
							}
							else
								FF = false;
						return remaining;
					
					case State.Ox7F:
						
						if( FF = (raw = src.get() & 0xFF) == 0xFF ) //FF here is an error
						{
							error_reset( OnError.BYTES_DISTORTION );
							break init;
						}
						
						bits |= ((raw & 1) << 7 | 0x7F) << shift;
						put( src, 0 );
						
						write( src, 1, State.NORMAL );
						src.position( 1 ).limit( limit );
					case State.Ox7F_:
						
						while( raw == 0x7F )
						{
							if( !src.hasRemaining() )
							{
								write( src, dst_byte, State.Ox7F_ );
								return remaining;
							}
							
							if( FF = (raw = src.get() & 0xFF) == 0xFF ) //FF here is an error
							{
								error_reset( OnError.BYTES_DISTORTION );
								break init;
							}
							
							bits |= (raw << 6 | 0x3F) << shift;
							if( (shift += 7) < 8 )
								continue;
							shift -= 8;
							
							put( src, dst_byte++ );
						}
						
						bits |= raw >> 1 << shift;
						if( (shift += 7) < 8 )
							break;
						
						shift -= 8;
						
						if( src.position() == dst_byte )
						{
							write( src, dst_byte, State.NORMAL );
							src.position( dst_byte ).limit( limit );
							dst_byte = 0;
						}
						put( src, dst_byte++ );
						
						state = State.NORMAL;
				}
				
				while( src.hasRemaining() )
				{
					if( (raw = src.get() & 0xFF) == 0x7F )
					{
						FF = false;
						if( !src.hasRemaining() )
						{
							write( src, dst_byte, State.Ox7F );
							return remaining;
						}
						
						if( FF = (raw = src.get() & 0xFF) == 0xFF ) //FF here is an error
						{
							error_reset( OnError.BYTES_DISTORTION );
							continue;
						}
						
						bits |= ((raw & 1) << 7 | 0x7F) << shift;
						
						put( src, dst_byte++ );
						
						while( raw == 0x7F )
						{
							if( !src.hasRemaining() )
							{
								write( src, dst_byte, State.Ox7F_ );
								return remaining;
							}
							
							if( FF = (raw = src.get() & 0xFF) == 0xFF ) //FF here is an error
							{
								error_reset( OnError.BYTES_DISTORTION );
								continue;
							}
							
							bits |= ((raw & 1) << 6 | 0x3F) << shift;
							if( (shift += 7) < 8 )
								continue;
							
							shift -= 8;
							
							put( src, dst_byte++ );
						}
						
						bits |= raw >> 1 << shift;
						if( (shift += 7) < 8 )
							continue;
						
						shift -= 8;
					}
					else if( raw == 0xFF ) //starting new frame mark byte
					{
						if( FF )
						{
							error_handler.error( this, OnError.FFFF_ERROR, null );
							continue;
						}
						
						FF = true;
						if( state == State.SEEK_FF ) //can happence after any call of put (src, dec_position++) that can
						//call >>> checkCrcThenDispatch >>> reset () so cleanup
						{
							reset();
							state = State.NORMAL;
						}
						else
						{
							final int fix = src.position(); //store position
							
							write( src, dst_byte, State.NORMAL );
							src.limit( limit ).position( fix ); //restore position
						}
						
						continue;
					}
					else
						bits |= raw << shift;
					
					FF = false;
					put( src, dst_byte++ );
				}
				write( src, dst_byte, State.NORMAL );
				
				return remaining;
			}
			
			private void put( ByteBuffer dst, int index ) {
				
				crc3 = crc2; //shift crc history
				crc2 = crc1;
				crc1 = crc0;
				
				crc0 = crc16( bits, crc1 );
				dst.put( index, (byte) bits );
				
				bits >>= 8;
			}
			
			@Override
			public void on_receiving( Receiver src, BytesDst dst ) { handler.on_receiving( src, dst ); }
			
			@Override
			public void on_received( Receiver src, BytesDst pack ) {
				pack_crc                     = 0;
				pack_crc_byte                = CRC_LEN_BYTES - 1;
				waiting_for_dispatching_pack = pack;
				dispatch_on_0                = false;
				
				while( src.buffer.hasRemaining() && waiting_for_dispatching_pack != null )
					getting_crc( src.buffer.get() & 0xFF );
			}
			
			private void write( ByteBuffer src, int limit, int state_if_ok ) throws IOException {
				state = state_if_ok;
				if( limit == 0 )
					return; //no decoded bytes
				
				src.position( 0 ).limit( limit ); //positioning on the decoded bytes section
				
				while( waiting_for_dispatching_pack != null )
				{
					getting_crc( src.get() & 0xFF );
					if( !src.hasRemaining() )
						return;
				}
				
				upper_layer.write( src );
				if( upper_layer.mode == OK || !FF )
					return; //not enough bytes to complete the current packet but already next pack frame
				//detected. error
				error_reset( OnError.BYTES_DISTORTION );
			}
			
			private BytesDst waiting_for_dispatching_pack;
			private boolean  dispatch_on_0;
			
			private void getting_crc( int crc_byte ) {
				
				if( dispatch_on_0 )
				{
					if( crc_byte == 0 )
						handler.on_received( upper_layer, waiting_for_dispatching_pack ); //dispatching
					else
						error_handler.error( this, OnError.CRC_ERROR, null ); //bad CRC
					reset();
					return;
				}
				
				pack_crc |= crc_byte << pack_crc_byte * 8;
				pack_crc_byte--;
				if( -1 < pack_crc_byte )
					return; //need more
				
				if( crc2 == pack_crc )
					handler.on_received( upper_layer, waiting_for_dispatching_pack ); //pass dispatching
				else if( crc16( pack_crc >> 8, crc3 ) == crc2 )
				{
					dispatch_on_0 = true;
					return;
				}
				else
					error_handler.error( this, OnError.CRC_ERROR, null ); //bad CRC
				reset();
			}
			
			private        int     bits     = 0;
			private        int     shift    = 0;
			private        char    pack_crc = 0; //from packet crc
			private        char    crc0     = 0;     //calculated crc history
			private        char    crc1     = 0;
			private        char    crc2     = 0;
			private        char    crc3     = 0;
			private        int     pack_crc_byte;
			private        int     raw      = 0;      //fix fetched byte
			private        int     dst_byte = 0; //place where put decoded
			private        boolean FF       = false;
			private @State int     state    = State.SEEK_FF;
			
			private @interface State {
				int NORMAL      = 0,
						Ox7F    = 1,
						Ox7F_   = 2,
						SEEK_FF = 3;
			}
			
			@Override
			public boolean isOpen() { return upper_layer.isOpen(); }
		}
//region Slot
		
		public static class Slot extends Context.Receiver.Slot {
			
			public BytesDst dst;
			
			public int fields_nulls;
			
			@SuppressWarnings( "unchecked" )
			public <DST extends BytesDst> DST get_bytes() { return (DST) next.dst; }
			
			private       Slot next;
			private final Slot prev;
			
			public Slot( Receiver dst, Slot prev ) {
				super( dst );
				this.prev = prev;
				if( prev != null )
					prev.next = this;
			}
		}
		
		public boolean isOpen() { return slot != null; }
		
		public  Slot                slot;
		private SoftReference<Slot> slot_ref = new SoftReference<>( new Slot( this, null ) );
		//Soft references are kept alive longer in the server virtual machine than in
		//the client.
		//
		//The rate of clearing can be controlled with the command-line
		//option -XX:SoftRefLRUPolicyMSPerMB=\<N\>, which specifies the number of
		//milliseconds (ms) a soft reference will be kept alive (once it is no longer
		//strongly reachable) for each megabyte of free space in the heap. The default
		//value is 1000 ms per megabyte, which means that a soft reference will survive
		//(after the last strong reference to the object has been collected) for 1
		//second
		//for each megabyte of free space in the heap. This is an approximate figure
		//because soft references are cleared only during garbage collection, which may
		//occur sporadically
//endregion
		
		public boolean get_fields_nulls( int this_case ) {
			if( buffer.hasRemaining() )
			{
				slot.fields_nulls = buffer.get() & 0xFF;
				return true;
			}
			
			slot.state = this_case;
			mode       = RETRY;
			return false;
		}
		
		public boolean is_null( int field, int if_null_case ) {
			if( (slot.fields_nulls & field) != 0 )
				return false;
			slot.state = if_null_case;
			return true;
		}
		
		public boolean byte_nulls( int if_null_case ) {
			int null_bit = get_byte();
			if( null_bit == 0 )
				return false;
			u8         = u8_ |= 1L << null_bit;
			slot.state = if_null_case;
			return true;
		}
		
		public boolean byte_nulls( long null_value, int if_null_case ) {
			int null_bit = get_byte();
			if( null_bit == 0 )
				return false;
			
			u8         = u8_ |= null_value;
			slot.state = if_null_case;
			return true;
		}
		
		public boolean byte_nulls( int bit, long null_value, int if_null_case ) {
			int null_bit = get_byte();
			if( null_bit == 0 )
				return false;
			
			u8         = u8_ |= null_bit == bit ? null_value : 1L << null_bit;
			slot.state = if_null_case;
			return true;
		}
		
		public boolean bit_null( int if_null_case ) {
			if( get_bits() == 0 )
				return false;
			slot.state = if_null_case;
			return true;
		}
		
		public boolean idle() { return slot == null; }
		
		boolean not_get4() {
			if( buffer.remaining() < bytes_left )
			{
				int r = buffer.remaining();
				u4 |= get4( r ) << (bytes_max - bytes_left) * 8;
				bytes_left -= r;
				return true;
			}
			
			u4 |= get4( bytes_left ) << (bytes_max - bytes_left) * 8;
			return false;
		}
		
		public abstract BytesDst allocate( int id ); //throws Exception if wrong id
		
		public abstract BytesDst receiving( int id ); //throws Exception if wrong id
		
		@Override
		public void close() { reset(); }
		
		protected void reset() {
			if( slot == null )
				return;
			
			for( Slot s = slot; s != null; s = s.next )
			     s.dst = null;
			slot = null;
			
			buffer = null;
			chs    = null;
			
			mode       = OK;
			bytes_left = bytes_max = id_bytes;
			u4         = 0;
			//dont u8 = 0; preserve probably a value pack data for framing layer.
			//dont str = null; preserve probably a value pack data for framing layer.
		}
		
		/**
		 write bytes
		 if src == null - clear and reset
		 ATTENTION! The data in the provided buffer "src" may change due to buffer reuse.
		 */
		public int write( ByteBuffer src ) {
			
			final int remaining = src.remaining();
write:
			{
				for( buffer = src; src.hasRemaining(); )
				{
					if( slot == null || slot.dst == null )
						try
						{
							if( not_get4() )
								break write;
							
							final BytesDst dst = receiving( u4 ); //throws Exception if wrong id
							if( (slot = slot_ref.get()) == null )
								slot_ref = new SoftReference<>( slot = new Slot( this, null ) );
							
							slot.dst   = dst;
							bytes_left = bytes_max = id_bytes;
							u4         = 0;
							u8         = 0;
							u8_        = 0;
							slot.state = 0;
							handler.on_receiving( this, dst );
							if( slot == null )
								return -1; //receiving event handler has reset this
						} catch( Exception ex )
						{
							reset();
							error_handler.error( this, OnError.INVALID_ID, ex );
							break;
						}
					else
						switch( mode )
						{
							case INT1:
								if( not_get4() )
									break write;
								u8 = (byte) u4;
								break;
							case INT2:
								if( not_get4() )
									break write;
								u8 = (short) u4;
								break;
							case INT4:
								if( not_get4() )
									break write;
								u8 = u4;
								break;
							case VAL4:
								if( not_get4() )
									break write;
								break;
							case VAL8:
								if( buffer.remaining() < bytes_left )
								{
									int r = buffer.remaining();
									u8 |= get8( r ) << (bytes_max - bytes_left) * 8;
									bytes_left -= r;
									break write;
								}
								
								u8 |= get8( bytes_left ) << (bytes_max - bytes_left) * 8;
								
								break;
							case LEN0:
								if( not_get4() )
									break write;
								slot.check_len0( u4 );
								break;
							case LEN1:
								if( not_get4() )
									break write;
								slot.check_len1( u4 );
								break;
							case LEN2:
								if( not_get4() )
									break write;
								slot.check_len2( u4 );
								break;
							case VARINT:
								if( varint() )
									break;
								break write;
							
							case STR:
								if( !varint() )
									break write;
								
								if( u8_ == -1 )
									if( check_length_and_getting_string() )
										break;
									else
										break write; //was reading string length
								
								chs[u4++] = (char) u8;
								if( getting_string() )
									break;
								break write;
						}
					
					mode = OK;
					
					for( ; ; )
						if( !this.slot.dst.__put_bytes( this ) )
							break write; //data over
						else
						{
							
							if( slot.prev == null )
								break;
							slot = slot.prev;
						}
					
					handler.on_received( this, slot.dst ); //dispatching
					
					u4         = 0;
					bytes_left = bytes_max = id_bytes;
					if( slot == null )
						return -1;   //received event handler has reset this
					slot.dst = null; //ready to read next packet data
				}
				
				if( slot != null && slot.dst == null )
					reset();
			} //write
			
			buffer = null;
			
			return remaining;
		}
		
		public <DST extends BytesDst> DST get_bytes( DST dst ) {
			slot.state = 0;
			dst.__put_bytes( this );
			return dst;
		}
		
		public <DST extends BytesDst> DST try_get_bytes( DST dst, int next_case ) {
			
			final Slot s = slot;
			
			(slot = s.next == null ? s.next = new Slot( this, s ) : s.next).dst = dst;
			this.slot.state                                                     = 0;
			u8_                                                                 = 0;
			if( dst.__put_bytes( this ) )
			{
				
				slot = s;
				return dst;
			}
			
			s.state = next_case;
			
			return null;
		}
		
		public void retry_at( int the_case ) {
			slot.state = the_case;
			mode       = RETRY;
		}
		
		public boolean has_bytes( int next_case ) {
			if( buffer.hasRemaining() )
				return true;
			mode       = RETRY;
			slot.state = next_case;
			return false;
		}
		
		public boolean has_1bytes( int get_case ) { return buffer.hasRemaining() || retry_get4( 1, get_case ); }
		
		public byte get_byte_()                   { return (byte) u4; }
		
		public byte get_byte()                    { return buffer.get(); }
		
		public char get_ubyte()                   { return (char) (buffer.get() & 0xFF); }
		
		public char get_ubyte_()                  { return (char) (u4 & 0xFF); }
		
		public boolean has_2bytes( int get_case ) { return 1 < buffer.remaining() || retry_get4( 2, get_case ); }
		
		public short get_short_()                 { return (short) u4; }
		
		public short get_short()                  { return buffer.getShort(); }
		
		public char get_char()                    { return buffer.getChar(); }
		
		public char get_char_()                   { return (char) u4; }
		
		public boolean has_4bytes( int get_case ) { return 3 < buffer.remaining() || retry_get4( 4, get_case ); }
		
		public int get_int()                      { return buffer.getInt(); }
		
		public int get_int_()                     { return u4; }
		
		public long get_uint()                    { return buffer.getInt() & 0xFFFFFFFFL; }
		
		public long get_uint_()                   { return u4 & 0xFFFFFFFFL; }
		
		public boolean has_8bytes( int get_case ) { return 7 < buffer.remaining() || retry_get8( 8, get_case ); }
		
		public long get_long()                    { return buffer.getLong(); }
		
		public long get_long_()                   { return u8; }
		
		public double get_double()                { return buffer.getDouble(); }
		
		public double get_double_()               { return Double.longBitsToDouble( u8 ); }
		
		public float get_float()                  { return buffer.getFloat(); }
		
		public float get_float_()                 { return Float.intBitsToFloat( u4 ); }
		
		public boolean get_byte_u8( int get_case ) {
			if( buffer.hasRemaining() )
			{
				u8 = buffer.get();
				return true;
			}
			retry_get4( 1, get_case );
			mode = INT1;
			return false;
		}
		
		public boolean get_ubyte_u8( int get_case ) {
			if( buffer.remaining() == 0 )
				return retry_get8( 1, get_case );
			u8 = buffer.get() & 0xFF;
			return true;
		}
		
		public boolean get_short_u8( int get_case ) {
			if( 1 < buffer.remaining() )
			{
				u8 = buffer.getShort();
				return true;
			}
			retry_get4( 2, get_case );
			mode = INT2;
			return false;
		}
		
		public boolean get_char_u8( int get_case ) {
			if( buffer.remaining() < 2 )
				return retry_get8( 2, get_case );
			u8 = buffer.getShort() & 0xFFFF;
			return true;
		}
		
		public boolean get_int_u8( int get_case ) {
			if( 3 < buffer.remaining() )
			{
				u8 = buffer.getInt();
				return true;
			}
			retry_get4( 4, get_case );
			mode = INT4;
			return false;
		}
		
		public boolean get_uint_u8( int get_case ) {
			if( buffer.remaining() < 4 )
				return retry_get8( 4, get_case );
			u8 = buffer.getInt() & 0xFFFFFFFFL;
			return true;
		}
		
		public boolean get_long_u8( int get_case ) {
			if( buffer.remaining() < 8 )
				return retry_get8( 8, get_case );
			u8 = buffer.getLong();
			return true;
		}
//#region 8
		
		public boolean try_get8( int bytes, int next_case ) {
			if( buffer.remaining() < bytes )
				return retry_get8( bytes, next_case );
			u8 = get8( bytes );
			return true;
		}
		
		public boolean retry_get8( int bytes, int get8_case ) {
			bytes_left = (bytes_max = bytes) - buffer.remaining();
			u8         = get8( buffer.remaining() );
			slot.state = get8_case;
			mode       = VAL8;
			return false;
		}
		
		public long get8() { return u8; }
		
		public long get8( int bytes ) {
			
			switch( bytes )
			{
				case 8:
					return buffer.getLong();
				case 7:
					return buffer.getInt() & 0xFFFF_FFFFL |
					       (buffer.getShort() & 0xFFFFL) << 32 |
					       (buffer.get() & 0xFFL) << 48;
				case 6:
					return buffer.getInt() & 0xFFFF_FFFFL |
					       (buffer.getShort() & 0xFFFFL) << 32;
				case 5:
					return buffer.getInt() & 0xFFFF_FFFFL |
					       (buffer.get() & 0xFFL) << 32;
				case 4:
					return buffer.getInt() & 0xFFFF_FFFFL;
				case 3:
					return buffer.getShort() & 0xFFFFL |
					       (buffer.get() & 0xFFL) << 16;
				case 2:
					return buffer.getShort() & 0xFFFFL;
				case 1:
					return buffer.get() & 0xFFL;
				case 0:
					return 0;
			}
			throw new RuntimeException( "Unexpected amount of bytes:" + bytes );
		}
//#endregion
//#region 4
		
		public boolean try_get4( int bytes, int next_case ) {
			if( buffer.remaining() < bytes )
				return retry_get4( bytes, next_case );
			u4 = get4( bytes );
			return true;
		}
		
		public boolean retry_get4( int bytes, int get_case ) {
			bytes_left = (bytes_max = bytes) - buffer.remaining();
			u4         = get4( buffer.remaining() );
			slot.state = get_case;
			mode       = VAL4;
			return false;
		}
		
		public int get4() { return u4; }
		
		public int get4( int bytes ) {
			switch( bytes )
			{
				case 4:
					return buffer.getInt();
				case 3:
					return buffer.getShort() & 0xFFFF |
					       (buffer.get() & 0xFF) << 16;
				case 2:
					return buffer.getShort() & 0xFFFF;
				case 1:
					return buffer.get() & 0xFF;
				case 0:
					return 0;
			}
			throw new RuntimeException( "Unexpected amount of bytes:" + bytes );
		}
//#endregion
//region bits
		
		public void init_bits() { //initialization receive bit
			bits = 0;
			bit  = 8;
		}
		
		public byte get_bits() { return (byte) u4; }
		
		public int get_bits( int len_bits ) {
			int ret;
			if( bit + len_bits < 9 )
			{
				ret = bits >> bit & 0xFF >> 8 - len_bits;
				bit += len_bits;
			}
			else
			{
				ret = (bits >> bit | (bits = buffer.get() & 0xFF) << 8 - bit) & 0xFF >> 8 - len_bits;
				bit = bit + len_bits - 8;
			}
			
			return ret;
		}
		
		public boolean try_get_bits( int len_bits, int this_case ) {
			if( bit + len_bits < 9 )
			{
				u4 = bits >> bit & 0xFF >> 8 - len_bits;
				bit += len_bits;
			}
			else if( buffer.hasRemaining() )
			{
				u4  = (bits >> bit | (bits = buffer.get() & 0xFF) << 8 - bit) & 0xFF >> 8 - len_bits;
				bit = bit + len_bits - 8;
			}
			else
			{
				retry_at( this_case );
				return false;
			}
			return true;
		}
//endregion
//region varint
		
		public boolean try_get8( int next_case ) { return try_get8( bytes_left, next_case ); }
		
		public boolean try_get_varint_bits1( int bits, int this_case ) {
			if( !try_get_bits( bits, this_case ) )
				return false;
			bytes_left = bytes_max = get_bits() + 1;
			return true;
		}
		
		public boolean try_get_varint_bits( int bits, int this_case ) {
			if( !try_get_bits( bits, this_case ) )
				return false;
			bytes_left = bytes_max = get_bits();
			return true;
		}
		
		public boolean try_get_varint( int next_case ) {
			u8         = 0;
			bytes_left = 0;
			
			if( varint() )
				return true;
			
			slot.state = next_case;
			mode       = VARINT;
			return false;
		}
		
		private boolean varint() {
			
			for( byte b; buffer.hasRemaining(); u8 |= (b & 0x7FL) << bytes_left, bytes_left += 7 )
				if( -1 < (b = buffer.get()) )
				{
					u8 |= (long) b << bytes_left;
					return true;
				}
			
			return false;
		}
		
		public static long zig_zag( long src ) { return -(src & 1) ^ src >>> 1; }
//endregion
//region dims
		
		private static final int[] empty = new int[0];
		private              int[] dims  = empty; //temporary buffer for the receiving string and more
		
		public void init_dims( int size ) {
			u8 = 1;
			if( size <= dims.length )
				return;
			dims = new int[size];
		}
		
		public int dim( int index ) { return dims[index]; }
		
		public void dim( int max, int index ) {
			int dim = u4;
			if( max < dim )
				error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "In dim  (int max, int index){} max < dim : " + max + " < " + dim ) );
			              
			              u8 *= dim;
			dims[index] = dim;
		}
		
		public int length( long max ) {
			int len = u4;
			if( len <= max )
				return len;
			
			error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "In length  (long max){} max < len : " + max + " < " + len ) );
			u8 = 0;
			return 0;
		}
//endregion
//region string
		
		//getting the result of an internal receiving
		public String get_string() {
			String ret = str;
			str = null;
			return ret;
		}
		
		public boolean try_get_string( int max_chars, int get_string_case ) {
			u4  = max_chars;
			u8_ = -1; //indicate state before string length received
			
			u8         = 0;         //varint receiving string char holde
			bytes_left = 0; //varint pointer
			if( varint() && //getting string length into u8
			    check_length_and_getting_string() )
				return true;
			
			slot.state = get_string_case;
			mode       = STR; //lack of received bytes, switch to receiving internally
			return false;
		}
		
		private SoftReference<char[]> chs_ref = new SoftReference<>( null ); //temporary buffer for the received string
		private char[]                chs     = null;
		
		private boolean check_length_and_getting_string() {
			
			if( u4 < u8 )
				error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "In check_length_and_getting_string  (){} u4 < u8 : " + u4 + " < " + u8 ) );
			
			if( chs == null && (chs = chs_ref.get()) == null || chs.length < u8 )
				chs_ref = new SoftReference<>( chs = new char[(int) u8] );
			
			u8_ = u8; //store string length into u8_
			u4  = 0;   //index 1receiving char
			
			return getting_string();
		}
		
		private boolean getting_string() {
			
			while( u4 < u8_ )
			{
				u8         = 0;
				bytes_left = 0;
				if( varint() )
					chs[u4++] = (char) u8;
				else
					return false;
			}
			str = new String( chs, 0, u4 );
			return true;
		}
//endregion
		
		public int remaining() { return buffer.remaining(); }
		
		public int position()  { return buffer.position(); }
		
		@Override
		public String toString() {
			if( slot == null )
				return super.toString() + " \uD83D\uDCA4";
			Slot s = slot;
			while( s.prev != null )
				s = s.prev;
			StringBuilder str    = new StringBuilder( super.toString() + "\n" );
			String        offset = "";
			for( ; s != slot; s = s.next, offset += "\t" )
			     str.append( offset ).append( s.dst.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" );
			
			str.append( offset ).append( s.dst.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" );
			
			return str.toString();
		}
	}
	
	public abstract static class Transmitter extends Context.Transmitter implements BytesSrc {
		public interface EventsHandler {
			default void on_sending( Transmitter dst, BytesSrc src ) { }
			
			default void sent( Transmitter dst, BytesSrc src )       { }
		}
		
		public interface BytesSrc {
			boolean __get_bytes( Transmitter dst );
			
			int __id();
		}
		
		public volatile      EventsHandler                                           handler;
		private static final AtomicReferenceFieldUpdater<Transmitter, EventsHandler> exchange = AtomicReferenceFieldUpdater.newUpdater( Transmitter.class, EventsHandler.class, "handler" );
		
		public EventsHandler exchange( EventsHandler dst ) { return exchange.getAndSet( this, dst ); }
		
		public Transmitter( EventsHandler handler )        { this( handler, 5 ); }
		
		public Transmitter( EventsHandler handler, int power_of_2_sending_queue_size ) {
			this.handler = handler;
			
			sending       = new RingBuffer<BytesSrc>( BytesSrc.class, power_of_2_sending_queue_size );
			sending_value = new LongRingBuffer( power_of_2_sending_queue_size );
		}
		
		Consumer<AdHoc.BytesSrc> subscriber; /* http://adhoc.lan:1968/InJAVA/5115/ */
		
		@Override
		public Consumer<AdHoc.BytesSrc> subscribe_on_new_bytes_to_transmit_arrive( Consumer<AdHoc.BytesSrc> subscriber ) {
			Consumer<AdHoc.BytesSrc> tmp = this.subscriber;
			if( (this.subscriber = subscriber) != null && !isOpen() )
				subscriber.accept( this );
			return tmp;
		}
//region sending
		
		public final RingBuffer<BytesSrc> sending;
		public final LongRingBuffer       sending_value;
		
		protected volatile int lock = 0;
		
		protected boolean send( Transmitter.BytesSrc src ) {
			while( !lock_update.compareAndSet( this, 0, 1 ) )
				Thread.yield();
			
			if( !sending.put( src ) )
			{
				lock = 0;
				return false;
			}
			
			lock = 0;
			if( subscriber != null )
				subscriber.accept( this );
			return true;
		}
		
		protected boolean send( AdHoc.Transmitter.BytesSrc handler, long src ) {
			
			while( !lock_update.compareAndSet( this, 0, 1 ) )
				Thread.yield();
			if( !sending_value.put( src ) )
			{
				lock = 0;
				return false;
			}
			
			sending.put( handler );
			lock = 0;
			if( subscriber != null )
				subscriber.accept( this );
			return true;
		}
		
		private static final AtomicIntegerFieldUpdater<Transmitter> lock_update = AtomicIntegerFieldUpdater.newUpdater( Transmitter.class, "lock" );
//endregion
//region value_pack transfer
		
		public void pull_value() { u8 = sending_value.get( 0 ); }
		
		public boolean put_bytes( long src, BytesSrc handler, int next_case ) {
			
			u8 = src;
			return put_bytes( handler, next_case );
		}
		
		public void put_bytes( BytesSrc src ) {
			
			slot.state = 1; //skip write id
			src.__get_bytes( this );
		}
		
		public boolean put_bytes( BytesSrc src, int next_case ) {
			
			final Slot s = slot;
			
			(slot = s.next == null ? s.next = new Slot( this, s ) : s.next).src = src;
			this.slot.state                                                     = 1; //skip write id
			
			if( src.__get_bytes( this ) )
			{
				slot = s;
				return true;
			}
			
			s.state = next_case;
			return false;
		}
//endregion
		
		public static class Framing implements AdHoc.BytesSrc, EventsHandler {
			
			public               Transmitter                                         upper_layer;
			public volatile      EventsHandler                                       handler;
			private static final AtomicReferenceFieldUpdater<Framing, EventsHandler> exchange = AtomicReferenceFieldUpdater.newUpdater( Framing.class, EventsHandler.class, "handler" );
			
			public EventsHandler exchange( EventsHandler dst ) { return exchange.getAndSet( this, dst ); }
			
			public Framing( Transmitter upper_layer )          { switch_to( upper_layer ); }
			
			public void switch_to( Transmitter upper_layer ) {
				bits  = 0;
				shift = 0;
				crc   = 0;
				if( this.upper_layer != null )
				{
					this.upper_layer.reset();
					this.upper_layer.exchange( handler );
				}
				
				handler = (this.upper_layer = upper_layer).exchange( this );
			}
			
			private int enc_position; //where start to put encoded bytes
			private int raw_position; //start position for temporarily storing raw bytes from the upper layer
			
			private boolean allocate_raw_bytes_space( ByteBuffer buffer ) {
				//divide free space.
				raw_position = (enc_position = buffer.position()) + //dst.position ()
				               1 +                                  //for 0xFF byte - frame start mark.
				               buffer.remaining() / 8 +             //ensure enough space for encoded bytes in a worse case
				               CRC_LEN_BYTES + 2;                   //guaranty space for CRC + its expansion
				
				if( raw_position < buffer.limit() )
				{
					buffer.position( raw_position );
					return true;
				}
				
				buffer.position( enc_position ).limit( enc_position ); //no more space. prevent continue
				return false;
			}
			
			@Override
			public void close() {
				reset();
				upper_layer.close();
			}
			
			private void reset() {
				upper_layer.reset();
				bits  = 0;
				shift = 0;
				crc   = 0;
			}
			
			@Override
			public int read( ByteBuffer dst ) throws IOException {
				
				final int fix_position = dst.position();
				while( allocate_raw_bytes_space( dst ) )
				{
					int len = upper_layer.read( dst ); //getting bytes from the upper layer
					
					if( len < 1 )
					{
						dst.limit( enc_position ).position( enc_position );
						return fix_position < enc_position ? enc_position - fix_position : len;
					}
					
					encode( dst );
				}
				
				return fix_position < enc_position ? enc_position - fix_position : 0;
			}
			
			@Override
			public void on_sending( Transmitter dst, BytesSrc src ) {
				handler.on_sending( dst, src );
				
				dst.buffer.put( enc_position++, (byte) 0xFF ); //write starting frame byte
				dst.buffer.position( ++raw_position );        //less space
			}
			
			public void sent( Transmitter dst, BytesSrc pack ) {
				encode( dst.buffer );
				
				//the packet sending completed write crc
				int fix = crc; //crc will continue counting on encode () calling , so fix it
				encode( fix >> 8 & 0xFF, dst.buffer );
				encode( fix & 0xFF, dst.buffer );
				if( 0 < shift )
				{
					dst.put( (byte) bits );
					if( bits == 0x7F )
						dst.put( (byte) 0 );
				}
				
				allocate_raw_bytes_space( dst.buffer );
				
				bits  = 0;
				shift = 0;
				crc   = 0;
				handler.sent( dst, pack ); //pass
			}
			
			private void encode( ByteBuffer buffer ) {
				final int raw_position_max = buffer.position();
				buffer.position( enc_position ); //switch to encoded position
				while( raw_position < raw_position_max )
					encode( buffer.get( raw_position++ ) & 0xFF, buffer );
				enc_position = buffer.position();
			}
			
			private void encode( int src, ByteBuffer dst ) {
				
				crc = crc16( src, crc );
				final int v = (bits |= src << shift) & 0xFF;
				
				if( (v & 0x7F) == 0x7F )
				{
					dst.put( (byte) 0x7F );
					bits >>= 7;
					
					if( shift < 7 )
						shift++;
					else //a full byte in `bits`
					{
						if( (bits & 0x7F) == 0x7F )
						{
							dst.put( (byte) 0x7F );
							bits >>= 7;
							
							shift = 1;
							return;
						}
						
						dst.put( (byte) bits );
						shift = 0;
						bits  = 0;
					}
					return;
				}
				
				dst.put( (byte) v );
				bits >>= 8;
			}
			
			@Override
			public Consumer<AdHoc.BytesSrc> subscribe_on_new_bytes_to_transmit_arrive( Consumer<AdHoc.BytesSrc> subscriber ) { return upper_layer.subscribe_on_new_bytes_to_transmit_arrive( subscriber ); }
			
			private int  bits  = 0;
			private int  shift = 0;
			private char crc   = 0;
			
			@Override
			public boolean isOpen() { return upper_layer.isOpen(); }
		}
//region Slot
		
		public static final class Slot extends Context.Transmitter.Slot {
			
			BytesSrc src;
			
			int fields_nulls;
			
			private       Slot next;
			private final Slot prev;
			
			public Slot( Transmitter src, Slot prev ) {
				super( src );
				this.prev = prev;
				if( prev != null )
					prev.next = this;
			}
		}
		
		protected SoftReference<Slot> slot_ref = new SoftReference<>( new Slot( this, null ) );
		public    Slot                slot;
		
		public boolean isOpen() { return slot != null; } //has data
//endregion
		
		@Override
		public void close() { reset(); }
		
		protected void reset() {
			if( slot == null )
				return;
			
			for( Slot s = slot; s != null; s = s.next )
			     s.src = null;
			slot = null;
			
			sending.clear();
			sending_value.clear();
			
			buffer     = null;
			mode       = OK;
			u4         = 0;
			bytes_left = 0;
		}
		
		public int position()  { return buffer.position(); }
		
		public int remaining() { return buffer.remaining(); }
		
		public boolean init_fields_nulls( int field0_bit, int this_case ) {
			if( !allocate( 1, this_case ) )
				return false;
			slot.fields_nulls = field0_bit;
			return true;
		}
		
		public void set_fields_nulls( int field ) { slot.fields_nulls |= field; }
		
		public void flush_fields_nulls()          { put( (byte) slot.fields_nulls ); }
		
		public boolean is_null( int field, int next_field_case ) {
			if( (slot.fields_nulls & field) == 0 )
			{
				slot.state = next_field_case;
				return true;
			}
			return false;
		}
		
		//if dst == null - clean / reset state
		//
		//if 0 < return - bytes read
		//if return == 0 - not enough space available
		//if return == -1 - no more packets left
		public int read( ByteBuffer dst ) {
			
			buffer = dst;
			final int fix = buffer.position();
read:
			{
				for( ; buffer.hasRemaining(); )
				{
					if( slot == null || slot.src == null )
					{
						final BytesSrc src = sending.get( null );
						
						if( src == null )
						{
							int ret = buffer.position() - fix;
							this.reset();
							return 0 < ret ? ret : -1;
						}
						
						if( slot == null )
							if( (slot = slot_ref.get()) == null )
								slot_ref = new SoftReference<>( slot = new Slot( this, null ) );
						
						slot.src   = src;
						slot.state = 0; //write id request
						u4         = 0;
						bytes_left = 0;
						this.handler.on_sending( this, src );
						if( slot == null )
							return -1; //sending event handler has reset this
					}
					else
					{
						switch( mode ) //the packet transmission was interrupted, recall where we stopped
						{
							case STR:
								if( !varint() )
									break read;
								if( u4 == -1 )
									u4 = 0; //now ready getting string
								
								while( u4 < str.length() )
									if( !varint( str.charAt( u4++ ) ) )
										break read;
								
								str = null;
								break;
							case VAL4:
								if( buffer.remaining() < bytes_left )
									break read;
								put_val( u4, bytes_left );
								break;
							case VAL8:
								if( buffer.remaining() < bytes_left )
									break read;
								put_val( u8, bytes_left );
								break;
							case BITS_BYTES:
								if( buffer.remaining() < bits_transaction_bytes_ )
									break read;                //space for one full transaction
								bits_byte = buffer.position(); //preserve space for bits info
								buffer.position( bits_byte + 1 );
								put_val( u8, bytes_left );
								break;
							case VARINT:
								if( varint() )
									break;
								break read;
							case BITS:
								if( buffer.remaining() < bits_transaction_bytes_ )
									break read;                //space for one full transaction
								bits_byte = buffer.position(); //preserve space for bits info
								buffer.position( bits_byte + 1 );
								break;
						}
					}
					
					mode = OK;
					for( ; ; )
						if( !slot.src.__get_bytes( this ) )
							break read;
						else
						{
							
							if( slot.prev == null )
								break;
							slot = slot.prev;
						}
					
					handler.sent( this, slot.src );
					if( slot == null )
						return -1;   //sent event handler has reset this
					slot.src = null; //sing of next packet data request
				} //read loop
				
				if( slot != null && slot.src == null )
					slot = null;
			}
			
			int ret = buffer.position() - fix;
			buffer = null;
			
			return 0 < ret ? ret : -1;
		}
		
		public boolean allocate( int bytes, int this_case ) {
			slot.state = this_case;
			if( bytes <= buffer.remaining() )
				return true;
			mode = RETRY;
			return false;
		}
		
		public void put( Boolean src ) {
			put_bits( src == null ? 0 : src ? 1
			                                : 2,
			          2 );
		}
		
		public void put( boolean src ) {
			put_bits( src ? 1 : 0, 1 );
		}
//region bits
		
		private int bits_byte = -1;
		private int bits_transaction_bytes_;
		
		public boolean init_bits_( int transaction_bytes, int this_case ) {
			if( (bits_transaction_bytes_ = transaction_bytes) <= buffer.remaining() )
				return true; //26 byte wost case 83: 3 bits x 3times x 8 bytes
			
			slot.state = this_case;
			buffer.position( bits_byte ); //trim byte at bits_byte index
			
			mode = BITS;
			return false;
		}
		
		public boolean init_bits( int transaction_bytes, int this_case ) {
			if( buffer.remaining() < (bits_transaction_bytes_ = transaction_bytes) )
			{
				slot.state = this_case;
				mode       = RETRY;
				return false;
			}
			
			bits = 0;
			bit  = 0;
			
			bits_byte = buffer.position(); //place fixation
			buffer.position( bits_byte + 1 );
			return true;
		}
		
		public void put_bits( int src, int len_bits ) {
			bits |= src << bit;
			if( (bit += len_bits) < 9 )
				return; //yes 9! not 8! to avoid allocating the next byte after the current one is
			//full. it is might be redundant
			
			buffer.put( bits_byte, (byte) bits ); //sending
			
			bits >>= 8;
			bit -= 8;
			
			bits_byte = buffer.position();
			if( buffer.hasRemaining() )
				buffer.position( bits_byte + 1 );
		}
		
		public boolean put_bits( int src, int len_bits, int continue_at_case ) {
			bits |= src << bit;
			if( (bit += len_bits) < 9 )
				return true; //yes 9! not 8! to avoid allocating the next byte after the current one is
			//full. it is might be redundant
			
			buffer.put( bits_byte, (byte) bits ); //sending
			
			bits >>= 8;
			bit -= 8;
			
			if( buffer.remaining() < bits_transaction_bytes_ )
			{
				slot.state = continue_at_case;
				return false;
			}
			
			bits_byte = buffer.position();
			buffer.position( bits_byte + 1 );
			return true;
		}
		
		public void end_bits() {
			if( 0 < bit )
				buffer.put( bits_byte, (byte) bits );
			else
				buffer.position( bits_byte ); //trim byte at bits_byte index. allocated, but not used
		}
		
		public boolean put_nulls( int nulls, int nulls_bits, int continue_at_case ) {
			if( put_bits( nulls, nulls_bits, continue_at_case ) )
				return true;
			
			mode = BITS;
			return false;
		}
		
		public void continue_bits_at( int continue_at_case ) {
			slot.state = continue_at_case;
			buffer.position( bits_byte ); //trim byte at bits_byte index
			mode = BITS;
		}
//endregion
//region varint
		
		public boolean put_bits_bytes( int info, int info_bits, long value, int value_bytes, int continue_at_case ) {
			if( put_bits( info, info_bits, continue_at_case ) )
			{
				put_val( value, value_bytes );
				return true;
			}
			
			u8         = value;
			bytes_left = value_bytes;
			mode       = BITS_BYTES;
			return false;
		}
		
		private static int bytes1( long src ) {
			return src < 1 << 8 ? 1 : 2;
		}
		
		public boolean put_varint21( long src, int continue_at_case ) {
			int bytes = bytes1( src );
			return put_bits_bytes( bytes - 1, 1, src & 0xFFFFL, bytes, continue_at_case );
		}
		
		public boolean put_varint21( long src, int continue_at_case, int nulls, int nulls_bits ) {
			int bytes = bytes1( src );
			return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 1, src & 0xFFFFL, bytes, continue_at_case );
		}
		
		private static int bytes2( long src ) {
			return src < 1 << 8 ? 1 : src < 1 << 16 ? 2
			                                        : 3;
		}
		
		public boolean put_varint32( long src, int continue_at_case ) {
			int bytes = bytes2( src );
			return put_bits_bytes( bytes, 2, src & 0xFFFF_FFL, bytes, continue_at_case );
		}
		
		public boolean put_varint32( long src, int continue_at_case, int nulls, int nulls_bits ) {
			
			int bytes = bytes2( src );
			return put_bits_bytes( bytes << nulls_bits | nulls, nulls_bits + 2, src & 0xFFFF_FFL, bytes, continue_at_case );
		}
		
		private static int bytes3( long src ) {
			return src < 1L << 16 ? src < 1L << 8 ? 1 : 2 : src < 1L << 24 ? 3
			                                                               : 4;
		}
		
		public boolean put_varint42( long src, int continue_at_case ) {
			int bytes = bytes3( src );
			return put_bits_bytes( bytes - 1, 2, src & 0xFFFF_FFFFL, bytes, continue_at_case );
		}
		
		public boolean put_varint42( long src, int continue_at_case, int nulls, int nulls_bits ) {
			int bytes = bytes3( src );
			return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 2, src & 0xFFFF_FFFFL, bytes, continue_at_case );
		}
		
		private static int bytes4( long src ) {
			return src < 1 << 24 ? src < 1 << 16 ? src < 1 << 8 ? 1 : 2 : 3 : src < 1L << 32 ? 4
			                                                                                 : src < 1L << 40 ? 5
			                                                                                                  : src < 1L << 48 ? 6
			                                                                                                                   : 7;
		}
		
		public boolean put_varint73( long src, int continue_at_case ) {
			int bytes = bytes4( src );
			
			return put_bits_bytes( bytes, 3, src, bytes, continue_at_case );
		}
		
		public boolean put_varint73( long src, int continue_at_case, int nulls, int bits ) {
			int bytes = bytes4( src );
			
			return put_bits_bytes( bytes << bits | nulls, bits + 3, src, bytes, continue_at_case );
		}
		
		private static int bytes5( long src ) {
			return src < 0 ? 8 : src < 1L << 32 ? src < 1 << 16 ? src < 1 << 8 ? 1 : 2 : src < 1 << 24 ? 3
			                                                                                           : 4
			                                    : src < 1L << 48 ? src < 1L << 40 ? 5 : 6
			                                                     : src < 1L << 56 ? 7
			                                                                      : 8;
		}
		
		public boolean put_varint83( long src, int continue_at_case ) {
			int bytes = bytes5( src );
			return put_bits_bytes( bytes - 1, 3, src, bytes, continue_at_case );
		}
		
		public boolean put_varint83( long src, int continue_at_case, int nulls, int nulls_bits ) {
			int bytes = bytes5( src );
			return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 3, src, bytes, continue_at_case );
		}
		
		public boolean put_varint84( long src, int continue_at_case ) {
			int bytes = bytes5( src );
			return put_bits_bytes( bytes, 4, src, bytes, continue_at_case );
		}
		
		public boolean put_varint84( long src, int continue_at_case, int nulls, int nulls_bits ) {
			int bytes = bytes5( src );
			return put_bits_bytes( bytes << nulls_bits | nulls, nulls_bits + 4, src, bytes, continue_at_case );
		}
		
		public boolean put_varint( long src, int next_case ) {
			
			if( varint( src ) )
				return true;
			
			slot.state = next_case;
			mode       = VARINT;
			return false;
		}
		
		private boolean varint() { return varint( u8_ ); }
		
		private boolean varint( long src ) {
			
			for( ; buffer.hasRemaining(); buffer.put( (byte) (0x80 | src) ), src >>>= 7 )
				if( (src & 0x7F) == src )
				{
					buffer.put( (byte) src );
					return true;
				}
			u8_ = src;
			return false;
		}
		
		public static long zig_zag( long src, int right ) { return src << 1 ^ src >> right; }
//endregion
		
		public boolean put_val( long src, int bytes, int next_case ) {
			if( buffer.remaining() < bytes )
			{
				put( src, bytes, next_case );
				return false;
			}
			
			put_val( src, bytes );
			return true;
		}
		
		public void put_val( long src, int bytes ) {
			
			switch( bytes )
			{
				case 8:
					buffer.putLong( src );
					return;
				case 7:
					buffer.putInt( (int) src );
					buffer.putShort( (short) (src >> 32) );
					buffer.put( (byte) (src >> 48) );
					return;
				case 6:
					buffer.putInt( (int) src );
					buffer.putShort( (short) (src >> 32) );
					return;
				case 5:
					buffer.putInt( (int) src );
					buffer.put( (byte) (src >> 32) );
					return;
				case 4:
					buffer.putInt( (int) src );
					return;
				case 3:
					buffer.putShort( (short) src );
					buffer.put( (byte) (src >> 16) );
					return;
				case 2:
					buffer.putShort( (short) src );
					return;
				case 1:
					buffer.put( (byte) src );
			}
		}
		
		public boolean put_val( int src, int bytes, int next_case ) {
			if( buffer.remaining() < bytes )
			{
				put( src, bytes, next_case );
				return false;
			}
			
			put_val( src, bytes );
			return true;
		}
		
		public void put_val( int src, int bytes ) {
			switch( bytes )
			{
				case 4:
					buffer.putInt( (int) src );
					return;
				case 3:
					buffer.putShort( (short) src );
					buffer.put( (byte) (src >> 16) );
					return;
				case 2:
					buffer.putShort( (short) src );
					return;
				case 1:
					buffer.put( (byte) src );
			}
		}
		
		public boolean put( String src, int next_case ) {
put:
			{
				u4 = -1; //indicate state before string length send
				if( !varint( src.length() ) )
					break put;
				u4 = 0; //indicate state after string length sent
				
				while( u4 < src.length() )
					if( !varint( src.charAt( u4++ ) ) )
						break put;
				return true;
			}
			
			slot.state = next_case; //switch to sending internally
			str        = src;
			mode       = STR;
			return false;
		}
		
		private void put( int src, int bytes, int next_case ) {
			slot.state = next_case;
			bytes_left = bytes;
			u4         = src;
			mode       = VAL4;
		}
		
		private void put( long src, int bytes, int next_case ) {
			slot.state = next_case;
			bytes_left = bytes;
			u8         = src;
			mode       = VAL8;
		}
		
		public void retry_at( int the_case ) {
			slot.state = the_case;
			mode       = RETRY;
		}
		
		public boolean put( byte src, int next_case ) {
			if( buffer.hasRemaining() )
			{
				put( src );
				return true;
			}
			
			put( src, 1, next_case );
			return false;
		}
		
		public void put( byte src ) { buffer.put( src ); }
		
		public boolean put( short src, int next_case ) {
			if( buffer.remaining() < 2 )
			{
				put( src, 2, next_case );
				return false;
			}
			
			put( src );
			return true;
		}
		
		public void put( short src ) { buffer.putShort( src ); }
		
		public boolean put( char src, int next_case ) {
			if( buffer.remaining() < 2 )
			{
				put( src, 2, next_case );
				return false;
			}
			
			put( src );
			return true;
		}
		
		public void put( char src ) { buffer.putChar( src ); }
		
		public boolean put( int src, int next_case ) {
			if( buffer.remaining() < 4 )
			{
				put( src, 4, next_case );
				return false;
			}
			
			put( src );
			return true;
		}
		
		public void put( int src ) { buffer.putInt( src ); }
		
		public boolean put( long src, int next_case ) {
			if( buffer.remaining() < 8 )
			{
				put( src, 8, next_case );
				return false;
			}
			
			put( src );
			return true;
		}
		
		public void put( long src )                     { buffer.putLong( src ); }
		
		public void put( float src )                    { buffer.putFloat( src ); }
		
		public boolean put( float src, int next_case )  { return put( Float.floatToIntBits( src ), next_case ); }
		
		public void put( double src )                   { buffer.putDouble( src ); }
		
		public boolean put( double src, int next_case ) { return put( Double.doubleToLongBits( src ), next_case ); }
		
		@Override
		public String toString() {
			if( slot == null )
				return super.toString() + " \uD83D\uDCA4 ";
			Slot s = slot;
			while( s.prev != null )
				s = s.prev;
			StringBuilder str    = new StringBuilder( super.toString() + "\n" );
			String        offset = "";
			for( ; s != slot; s = s.next, offset += "\t" )
			     str.append( offset ).append( s.src.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" );
			
			str.append( offset ).append( s.src.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" );
			
			return str.toString();
		}
	}
	
	public static class Pool<T> {
		
		private SoftReference<ArrayList<T>> list = new SoftReference<>( new ArrayList<>( 3 ) );
		final   Supplier<T>                 factory;
		
		public Pool( Supplier<T> factory ) { this.factory = factory; }
		
		public T get() {
			ArrayList<T> list = this.list.get();
			return list == null || list.isEmpty() ? factory.get() : list.remove( list.size() - 1 );
		}
		
		public void put( T item ) {
			ArrayList<T> list = this.list.get();
			if( list == null )
				this.list = new SoftReference<>( list = new ArrayList<>( 3 ) );
			
			list.add( item );
		}
	}
	
	public static final boolean debug_mode = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments().toString().indexOf( "jdwp" ) > 0;
	
	public static final class StackTracePrinter extends PrintStream {
		private StackTracePrinter() {
			super( new OutputStream() {
				@Override
				public void write( int b ) throws IOException { }
			} );
		}
		
		private AtomicReference<Thread> lock = new AtomicReference<>( null );
		private StringBuilder           sb   = new StringBuilder();
		
		@Override
		public PrintStream append( CharSequence csq ) {
			sb.append( csq );
			sb.append( '\n' );
			return this;
		}
		
		@Override
		public PrintStream append( CharSequence csq, int start, int end ) {
			sb.append( csq, start, end );
			sb.append( '\n' );
			return this;
		}
		
		@Override
		public void println( Object obj ) { sb.append( obj ).append( '\n' ); }
		
		String stackTrace( Throwable e ) {
			while( !lock.compareAndSet( null, Thread.currentThread() ) )
				Thread.onSpinWait();
			e.printStackTrace( this );
			String ret = sb.toString();
			sb.setLength( 0 );
			lock.set( null );
			return ret;
		}
		
		public static final StackTracePrinter ONE = new StackTracePrinter();
	}
	
	public static class BytesAsCharSequence implements CharSequence {
		//using regex over bytes array
		//
		//byte[] data = new byte[] { 'a', '\r', '\r', 'c' };
		//Pattern p = Pattern.compile ("\r\n?|\n\r?");
		//Matcher m = p.matcher (new ByteCharSequence (data));
		//
		//assertEquals (true, m.find (0));
		//assertEquals (1, m.start ());
		//assertEquals (2, m.end ());
		//
		//assertEquals (true, m.find (2));
		//assertEquals (2, m.start ());
		//assertEquals (3, m.end ());
		//
		//assertEquals (false, m.find (3));
		public byte[] bytes;
		public int    length;
		public int    offset;
		
		public BytesAsCharSequence( byte[] bytes )                         { this( bytes, 0, bytes.length ); }
		
		public BytesAsCharSequence( byte[] bytes, int offset, int length ) { set( bytes, offset, length ); }
		
		public void set( byte[] bytes, int offset, int length ) {
			this.bytes  = bytes;
			this.offset = offset;
			this.length = length;
		}
		
		@Override
		public int length() { return length; }
		
		@Override
		public char charAt( int index ) { return (char) (bytes[offset + index] & 0xff); }
		
		@Override
		public CharSequence subSequence( int start, int end ) { return new BytesAsCharSequence( bytes, offset + start, end - start ); }
	}
	
	public interface ULong {
		//-1
		// ^
		//Long.MIN_VALUE
		// ^
		//Long.MAX_VALUE
		// ^
		// 0
		
		//This code serves as a reminder of the specific functionalities provided in Java for handling unsigned long values.
		//All other operations remain the same as those for signed long values.
		static long divide( long dividend, long divisor ) { return Long.divideUnsigned( dividend, divisor ); }
		
		static long remainder( long dividend, long divisor )            { return Long.remainderUnsigned( dividend, divisor ); }
		
		static long parse( String string )                              { return Long.parseUnsignedLong( string, 10 ); }
		
		static int compare( long if_bigger_plus, long if_bigger_minus ) { return Long.compareUnsigned( if_bigger_plus, if_bigger_minus ); }
		
		static String toString( long ulong, int radix ) { //This is the most efficient way to get a string of an unsigned long in Java.
			
			if( 0 <= ulong )
				return Long.toString( ulong, radix );
			final long quotient = (ulong >>> 1) / radix << 1;
			final long rem      = ulong - quotient * radix;
			return rem < radix ? Long.toString( quotient, radix ) + Long.toString( rem, radix ) : Long.toString( quotient + 1, radix ) + Long.toString( rem - radix, radix );
		}
	}
	
	@Target( ElementType.TYPE_USE ) @interface NullableBool {
		interface value {
			static boolean hasValue( @NullableBool long src ) { return src != NULL; }
			
			static boolean get( @NullableBool long src )      { return src == 1; }
			
			static @NullableBool byte set( boolean src ) {
				return src ? (byte) 1 : (byte) 0;
			}
			
			static @NullableBool long to_null() { return NULL; }
		}
		
		@NullableBool
		long NULL = 2;
	}
	
	//Decoding table for base64
	private static final byte[] char2byte = new byte[256];
	
	static
	{
		for( int i = 'A'; i <= 'Z'; i++ )
		     char2byte[i] = (byte) (i - 'A');
		for( int i = 'a'; i <= 'z'; i++ )
		     char2byte[i] = (byte) (i - 'a' + 26);
		for( int i = '0'; i <= '9'; i++ )
		     char2byte[i] = (byte) (i - '0' + 52);
		char2byte['+'] = 62;
		char2byte['/'] = 63;
	}
	
	/**
	 Decodes base64 encoded bytes in place.
	 
	 @param bytes    The byte array containing the base64 encoded bytes.
	 @param srcIndex The starting index in the source array to begin decoding.
	 @param dstIndex The starting index in the destination array to place decoded bytes.
	 @param len      The length of the base64 encoded bytes to decode.
	 @return The length of the decoded bytes.
	 */
	public static int base64decode( byte[] bytes, int srcIndex, int dstIndex, int len ) {
		int max = srcIndex + len;
		
		//Adjust the length for padding characters
		while( bytes[max - 1] == '=' )
		{
			max--;
		}
		
		int newLen = max - srcIndex;
		for( int i = newLen >> 2; i > 0; i-- )
		{ //Process full 4-character blocks
			int b = char2byte[bytes[srcIndex++]] << 18 |
			        char2byte[bytes[srcIndex++]] << 12 |
			        char2byte[bytes[srcIndex++]] << 6 |
			        char2byte[bytes[srcIndex++]];
			
			bytes[dstIndex++] = (byte) (b >> 16);
			bytes[dstIndex++] = (byte) (b >> 8);
			bytes[dstIndex++] = (byte) b;
		}
		
		switch( newLen & 3 )
		{
			case 3:
				//If there are 3 characters remaining, decode them into 2 bytes
				int b = char2byte[bytes[srcIndex++]] << 12 |
				        char2byte[bytes[srcIndex++]] << 6 |
				        char2byte[bytes[srcIndex]];
				bytes[dstIndex++] = (byte) (b >> 10); //Extract first byte
				bytes[dstIndex++] = (byte) (b >> 2);  //Extract second byte
				break;
			case 2:
				//If there are 2 characters remaining, decode them into 1 byte
				bytes[dstIndex++] = (byte) ((char2byte[bytes[srcIndex++]] << 6 | char2byte[bytes[srcIndex]]) >> 4);
				break;
		}
		
		return dstIndex;
	}
	
	/**
	 Creates a DNS TXT record request for a given domain.
	 
	 @param domain The domain to query.
	 @return The byte array representing the DNS query request.
	 */
	private static byte[] create_DNS_TXT_Record_Request( String domain ) {
		int id = new Random().nextInt( 65536 ); //Generate a random query ID
		
		byte[] request = new byte[12 + domain.length() + 2 + 4]; //Initialize the request packet
		
		//Set DNS header fields
		request[0] = (byte) (id >> 8);
		request[1] = (byte) (id & 0xFF);
		request[2] = 0x01; //QR=0, OPCODE=0, AA=0, TC=0, RD=1
		request[5] = 0x01; //QDCOUNT=1
		
		//Add the domain name to the question section
		int index = 12;
		int p     = index++;
		
		for( int i = 0, ch; i < domain.length(); i++ )
			if( (ch = domain.charAt( i )) == '.' )
			{
				request[p] = (byte) (index - p - 1);
				p          = index++;
			}
			else
				request[index++] = (byte) ch;
		
		request[p] = (byte) (index - p - 1); //Set the length for the last label
		
		index += 2;              //Terminate domain name, set question type (TXT) and class (IN)
		request[index++] = 0x10; //QTYPE = TXT
		request[++index] = 0x01; //QCLASS = IN
		
		return request;
	}
	private static ByteBuffer[] parse_DNS_TXT_Record_Response( byte[] response ) {
		int questionCount = (response[4] << 8) | response[5]; //Extract question and answer counts from the header
		int answerCount   = (response[6] << 8) | response[7];
		
		int index = 12;
		
		for( int i = 0; i < questionCount; i++, index += 5 ) //Skip the question section
			while( response[index] != 0 )
				index += response[index] + 1;
		
		int          dst_index  = 0;
		int          dst_index_ = 0;
		ByteBuffer[] records    = new ByteBuffer[answerCount];
		for( int i = 0; i < answerCount; i++ ) //Parse each answer
		{
			index += 2; //Skip NAME field
			//TYPE            two octets containing one of the RR TYPE codes.
			int TYPE = (response[index] << 8) | response[index + 1];
			//CLASS           two octets containing one of the RR CLASS codes.
			//
			//TTL             a 32 bit signed integer that specifies the time interval
			//                that the resource record may be cached before the source
			//                of the information should again be consulted.  Zero
			//                values are interpreted to mean that the RR can only be
			//                used for the transaction in progress, and should not be
			//                cached.  For example, SOA records are always distributed
			//                with a zero TTL to prohibit caching.  Zero values can
			//                also be used for extremely volatile data.
			index += 8;                                                //Skip all above
			int RDLENGTH = response[index] << 8 | response[index + 1]; //an unsigned 16 bit integer that specifies the length in  octets of the RDATA field.
			index += 2;
			//TXT-DATA        One or more <character-string>s. where <character-string> is a single length octet followed by that number of characters
			//!!! attention records in reply may follow in arbitrary order
			
			if( TYPE == 16 ) //TXT record
				for( int max = index + RDLENGTH; index < max; )
				{
					byte len = response[index++];
					System.arraycopy( response, index, response, dst_index, len );
					dst_index += len;
					index += len;
				}
			
			records[i] = ByteBuffer.wrap( response, dst_index_, dst_index - dst_index_ );
			dst_index_ = dst_index;
		}
		
		return records;
	}
	
	private static InetAddress get_default_OS_dns_server() {
		try
		{
			ProcessBuilder pb  = new ProcessBuilder( System.getProperty( "os.name" ).toLowerCase().contains( "win" ) ? new String[]{ "cmd.exe", "/c", "nslookup", "1.1.1.1" } : new String[]{ "/bin/sh", "-c", "nslookup", "1.1.1.1" } );
			byte[]         out = pb.start().getInputStream().readAllBytes();
			int            s   = 0;
			while( out[s++] != ':' )
				;
			while( out[s++] != ':' )
				;
			int e = s += 2;
			while( out[e] != '\n' && out[e] != '\r' )
				e++;
			return InetAddress.getByName( new String( out, s, e - s ) );
		} catch( IOException e )
		{
		}
		return null;
	}
	
	//Using DNS as readonly key-value storage https://datatracker.ietf.org/doc/html/rfc1035
	public static ByteBuffer[] value( String key ) {
		try( DatagramSocket socket = new DatagramSocket() )
		{
			byte[]         request    = create_DNS_TXT_Record_Request( key );
			DatagramPacket sendPacket = new DatagramPacket( request, request.length, get_default_OS_dns_server(), 53 );
			socket.send( sendPacket );
			
			byte[]         receiveData   = new byte[1024];
			DatagramPacket receivePacket = new DatagramPacket( receiveData, receiveData.length );
			socket.receive( receivePacket );
			
			return parse_DNS_TXT_Record_Response( receivePacket.getData() );
		} catch( Exception e )
		{
		}
		
		return null;
	}
	
	/**
	 Calculates the number of bytes required to encode a String using varint encoding.
	 This method is a convenience wrapper that calls varint_bytes(String, int, int)
	 with the full length of the input string.
	 
	 @param src The String to be encoded.
	 @return The total number of bytes required for varint encoding of the entire string.
	 */
	public static int varint_bytes( String src ) { return varint_bytes( src, 0, src.length() ); }
	
	/**
	 Calculates the number of bytes required to encode a portion of a String using varint encoding.
	 <p>
	 Varint encoding is a method of serializing integers using one or more bytes.
	 Smaller numbers take fewer bytes. For Unicode characters:
	 - ASCII characters (0-127) are encoded in 1 byte
	 - Characters between 128 and 16,383 are encoded in 2 bytes
	 - Characters between 16,384 and 65,535 are encoded in 3 bytes
	 
	 @param src      The String to be encoded.
	 @param src_from The starting index (inclusive) in the string to begin calculation.
	 @param src_to   The ending index (exclusive) in the string to end calculation.
	 @return The total number of bytes required for varint encoding of the specified portion of the string.
	 */
	public static int varint_bytes( String src, int src_from, int src_to ) {
		int  bytes = 0;
		char ch;
		// Determine the number of bytes needed for each character:
		// - 1 byte for ASCII characters (0-127)
		// - 2 bytes for characters between 128 and 16,383
		// - 3 bytes for characters between 16,384 and 65,535
		while( src_from < src_to )
			bytes += (ch = src.charAt( src_from++ )) < 0x80 ? 1 : ch < 0x4000 ? 2 : 3;
		
		return bytes;
	}
	
	/**
	 Counts the number of characters that can be represented by a ByteBuffer containing varint-encoded data.
	 <p>
	 In varint encoding, the most significant bit (MSB) of each byte is used as a continuation flag:
	 - If MSB is 0, it's the last byte of the current character.
	 - If MSB is 1, there are more bytes for the current character.
	 <p>
	 This method counts complete characters by looking for bytes with MSB = 0.
	 
	 @param src The ByteBuffer containing varint-encoded data.
	 @return The number of complete characters that can be represented by the input bytes.
	 */
	public static int varint_chars( ByteBuffer src ) {
		int chars = 0;
		// Increment the character count for each byte that doesn't have
		// its most significant bit set (i.e., value < 128).
		// This indicates the end of a varint-encoded character.
		while( src.hasRemaining() )
			if( -1 < src.get() ) chars++;
		
		return chars;
	}
	
	/**
	 Encodes a portion of a string into a ByteBuffer using varint encoding.
	 
	 @param src       The source string to encode.
	 @param from_char The starting index in the source string.
	 @param dst       The destination ByteBuffer.
	 @return The index in the source string of the first character not processed yet.
	 */
	public static int varint( String src, int from_char, ByteBuffer dst ) {
		for( int src_max = src.length(), ch; from_char < src_max; from_char++ )
			if( (ch = src.charAt( from_char )) < 0x80 ) // Most frequent case: ASCII characters (0-127)
			{
				if( !dst.hasRemaining() ) break;
				dst.put( (byte) ch );
			}
			else if( ch < 0x4_000 )
			{
				if( dst.remaining() < 2 ) break;
				dst.put( (byte) (0x80 | ch) );
				dst.put( (byte) (ch >> 7) );
			}
			else// Less frequent case
			{
				if( dst.remaining() < 3 ) break;
				dst.put( (byte) (0x80 | ch) );
				dst.put( (byte) (0x80 | ch >> 7) );
				dst.put( (byte) (ch >> 14) );
			}
		
		return from_char;
	}
	
	/**
	 Decodes a portion of a ByteBuffer into a string using varint decoding.
	 
	 @param src The source ByteBuffer to decode.
	 @param ret A 32-bit integer containing two pieces of information:
	 - Low 16 bits: The partial character value from a previous call (if any).
	 - High 16 bits: The number of bits already processed for the partial character.
	 @param dst The StringBuffer to append the decoded characters to.
	 @return A 32-bit integer containing two pieces of information:
	 - Low 16 bits: The partial character value (if decoding is incomplete).
	 - High 8 bits: The number of bits processed for the partial character.
	 This return value can be used as the 'ret' parameter in a subsequent call to continue decoding.
	 */
	public static int varint( ByteBuffer src, int ret, StringBuilder dst ) {
		int  ch = ret & 0xFFFF;
		byte s  = (byte) (ret >> 16);
		int  b;
		
		while( src.hasRemaining() )
			if( -1 < (b = src.get()) )
			{
				dst.append( (char) ((b & 0xFF) << s | ch) );// Combine the partial character with the current byte and append to StringBuilder
				s  = 0;
				ch = 0;
			}
			else
			{
				ch |= (b & 0x7F) << s;
				s += 7;
			}
		
		return s << 16 | ch; // Return the current state (partial character and shift) for potential continuation
	}
	
	public static int varint_chars( byte[] src ) { return varint_chars( src, 0, src.length ); }
	
	/**
	 Counts the number of characters that can be represented by a byte array containing varint-encoded data.
	 <p>
	 In varint encoding, the most significant bit (MSB) of each byte is used as a continuation flag:
	 - If MSB is 0, it's the last byte of the current character.
	 - If MSB is 1, there are more bytes for the current character.
	 <p>
	 This method counts complete characters by looking for bytes with MSB = 0.
	 
	 @param src The byte array containing varint-encoded data.
	 @return The number of complete characters that can be represented by the input bytes.
	 */
	public static int varint_chars( byte[] src, int src_from, int src_to ) {
		int chars = 0;
		while( src_from < src_to )
			if( -1 < src[src_from++] ) chars++;
		
		return chars;
	}
	
	/**
	 Encodes a portion of a string into a byte array using varint encoding.
	 
	 @param src      The source string to encode.
	 @param src_from The starting index in the source string.
	 @param dst      The destination byte array.
	 @param dst_from The starting index in the destination byte array.
	 @return A 64-bit unsigned integer containing two pieces of information:
	 - High 32 bits: The index in the source string of the first character not processed
	 (i.e., the next character to be encoded if the operation were to continue).
	 - Low 32 bits: The number of bytes written to the destination array.
	 <p>
	 To extract these values:
	 - Next character to process: (int)(result >> 32)
	 - Bytes written: (int)(result & 0xFFFFFFFF)
	 */
	public static long varint( String src, int src_from, byte[] dst, int dst_from ) {
		
		for( int src_max = src.length(), dst_max = dst.length, ch; src_from < src_max; src_from++ )
			if( (ch = src.charAt( src_from )) < 0x80 )
			{
				// Check if there's enough space in the destination array for 1 byte
				if( dst_from == dst_max ) break;
				dst[dst_from++] = (byte) ch;
			}
			else if( ch < 0x4_000 )
			{
				// Check if there's enough space in the destination array for 2 bytes
				if( dst_max - dst_from < 2 ) break;
				dst[dst_from++] = (byte) (0x80 | ch);
				dst[dst_from++] = (byte) (ch >> 7);
			}
			else
			{
				// Check if there's enough space in the destination array for 3 bytes
				if( dst_max - dst_from < 3 ) break;
				dst[dst_from++] = (byte) (0x80 | ch);
				dst[dst_from++] = (byte) (0x80 | ch >> 7);
				dst[dst_from++] = (byte) (ch >> 14);
			}
		
		// Return the result: high 32 bits contain the next character index to process,
		// low 32 bits contain the number of bytes written to the destination array
		return (long) src_from << 32 | dst_from;
	}
	
	public static int varint( byte[] src, StringBuilder dst )                           { return varint( src, 0, src.length, 0, dst ); }
	public static int varint( byte[] src, int ret, StringBuilder dst )                  { return varint( src, 0, src.length, ret, dst ); }
	public static int varint( byte[] src, int src_from, int src_to, StringBuilder dst ) { return varint( src, src_from, 0, src_to, dst ); }
	
	/**
	 Decodes a portion of a byte array into a string using varint decoding.
	 
	 @param src      The source byte array to decode.
	 @param src_from The starting index in the source byte array.
	 @param src_to   The ending index (exclusive) in the source byte array.
	 @param ret      A 32-bit integer containing two pieces of information:
	 - Low 16 bits: The partial character value from a previous call (if any).
	 - High 16 bits: The number of bits already processed for the partial character.
	 @param dst      The StringBuilder to append the decoded characters to.
	 @return A 32-bit integer containing two pieces of information:
	 - Low 16 bits: The partial character value (if decoding is incomplete).
	 - High 8 bits: The number of bits processed for the partial character.
	 This return value can be used as the 'ret' parameter in a subsequent call to continue decoding.
	 */
	public static int varint( byte[] src, int src_from, int src_to, int ret, StringBuilder dst ) {
		int  ch = ret & 0xFFFF;
		byte s  = (byte) (ret >> 16);
		int  b;
		
		while( src_from < src_to )
			if( -1 < (b = src[src_from++]) )
			{
				dst.append( (char) ((b & 0xFF) << s | ch) );
				s  = 0;
				ch = 0;
			}
			else
			{
				ch |= (b & 0x7F) << s;
				s += 7;
			}
		
		return s << 16 | ch;
	}
	
	
}