//Copyright 2025 Chikirev Sirguy, Unirail Group
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
//For inquiries, please contact: al8v5C6HU4UtqE9@gmail.com
//GitHub Repository: https://github.com/AdHoc-Protocol

package org.unirail;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ObjIntConsumer;

/**
 * A namespace for network communication interfaces and their TCP/WebSocket implementations,
 * focusing on asynchronous, non-blocking I/O using Java NIO.
 * <p>
 * This collection provides high-performance, low-level abstractions for building network
 * clients and servers, with built-in support for connection management, buffer pooling,
 * and event-driven communication.
 */
public interface Network {
	
	/**
	 * An abstract base class for TCP-based network communication.
	 * <p>
	 * This class provides the core infrastructure for both client and server implementations,
	 * as well as for the WebSocket protocol which runs over TCP. It manages a dynamic pool of
	 * communication channels, a thread-local buffer pool to minimize memory overhead, and
	 * defines the fundamental event handling mechanism.
	 */
	abstract class TCP {
		
		/**
		 * The head of a singly linked list of communication channels. Each channel points
		 * to the next via its {@link ExternalChannel#next} field.
		 */
		public final           ExternalChannel                         channels;
		/**
		 * A thread-local pool of reusable {@link ByteBuffer} instances, designed to minimize
		 * memory allocation and garbage collection overhead during I/O operations.
		 */
		protected final        ThreadLocal< AdHoc.Pool< ByteBuffer > > buffers;
		/**
		 * A constant representing a free or inactive channel, identified by a {@code receive_time} of -1.
		 */
		protected static final long                                    CHANNEL_FREE = -1;
		
		/**
		 * A factory function for creating new channels of type {@link ExternalChannel}.
		 * This allows subclasses to provide custom channel implementations (e.g., for WebSockets).
		 */
		public final Function< TCP, ExternalChannel > new_channel;
		
		/**
		 * A user-defined name for this TCP host instance, primarily used for logging and debugging.
		 */
		public final String name;
		
		/**
		 * Constructs a new TCP host instance.
		 *
		 * @param name        A descriptive name for this instance (e.g., "WebServer", "GameClient").
		 * @param new_channel A factory function to create new {@link ExternalChannel} instances.
		 * @param onFailure   A callback for handling otherwise unhandled exceptions from asynchronous operations.
		 * @param buffer_size The size of each {@link ByteBuffer} allocated for I/O operations.
		 */
		public TCP( String name, Function< TCP, ExternalChannel > new_channel, BiConsumer< Object, Throwable > onFailure, int buffer_size ) {
			this.name      = name;
			this.channels  = ( this.new_channel = new_channel ).apply( this ); //Initialize channel list with a single head channel.
			this.buffers   = ThreadLocal.withInitial( () -> new AdHoc.Pool<>( () -> ByteBuffer.allocateDirect( buffer_size ).order( ByteOrder.LITTLE_ENDIAN ) ) );
			this.onFailure = onFailure;
		}
		
		public TCP( String name, Function< TCP, ExternalChannel > new_channel, int bufferSize ) { this( name, new_channel, onFailurePrintConsole, bufferSize ); }
		
		public TCP( String name, Function< TCP, ExternalChannel > new_channel )                 { this( name, new_channel, onFailurePrintConsole, 1024 ); }
		
		/**
		 * Allocates a free channel from the pool or creates a new one if the pool is exhausted.
		 * <p>
		 * This method iterates through the linked list of channels, attempting to atomically
		 * activate an inactive one. If it reaches the end of the list without finding a free channel,
		 * it creates a new one and appends it to the list, allowing the pool to grow dynamically.
		 *
		 * @return An available communication channel, marked as active for immediate use.
		 */
		protected ExternalChannel allocate() {
			ExternalChannel ch = channels; //Start from the head of the channel list.
			
			//Iterate through channels until one is successfully activated.
			for( ; !ch.isActivateDeactivated(); ch = ch.next )
				if( ch.next == null ) {                                                       //If the end of the list is reached...
					ExternalChannel ret = this.new_channel.apply( this ); //Create a new channel.
					
					ret.receive_time = ret.transmit_time = System.currentTimeMillis(); //Mark as active.
					
					//Atomically append the new channel to the end of the list.
					while( !ExternalChannel.next_.compareAndSet( ch, null, ret ) )
						ch = ch.next;
					return ret;
				}
			
			ch.transmit_time = System.currentTimeMillis(); //Update transmit time on successful allocation.
			return ch;
		}
		
		/**
		 * Triggers the maintenance thread to run immediately, bypassing its scheduled delay.
		 * <p>
		 * This method is intended to be overridden by subclasses like {@link Server} that implement
		 * a periodic maintenance routine. The override typically signals a condition variable to
		 * wake the maintenance thread.
		 */
		public void trigger_maintenance() {
			//No-op by default; overridden by subclasses with a maintenance thread.
		}
		
		/**
		 * A callback for handling exceptions that occur during asynchronous network operations
		 * that are not otherwise handled (e.g., protocol errors or unexpected I/O failures).
		 * <p>
		 * This serves as a global error handler for the TCP host, providing a centralized place
		 * for logging and cleanup.
		 */
		protected final     BiConsumer< Object, Throwable > onFailure;
		/**
		 * A default implementation of {@link #onFailure} that prints the exception's stack trace to standard output.
		 */
		public static final BiConsumer< Object, Throwable > onFailurePrintConsole =
				( src, e ) ->
				{
					System.out.println( "onFailure from " + src );
					if( AdHoc.debug_mode )
						System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( new Throwable( "onFailure" ) ) );
					System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( e ) );
				};
		
		/**
		 * Represents a single, full-duplex communication channel over TCP.
		 * <p>
		 * This class encapsulates an {@link AsynchronousSocketChannel} and manages the entire
		 * lifecycle of a connection, including data transmission, reception, and graceful
		 * or abrupt closure. It uses a {@link CompletionHandler} to process asynchronous I/O
		 * results and integrates with internal data sources ({@code BytesSrc}) and sinks ({@code BytesDst}).
		 */
		public static class ExternalChannel implements CompletionHandler< Integer, Object >, Closeable, AdHoc.Channel.External {
			
			/**
			 * Provides a string representation of the channel, including its host name and connection endpoints.
			 *
			 * @return A descriptive string of the channel's status and addresses.
			 */
			public String toString() {
				try {
					return isActive() ?
					       String.format( "%s %s:%s", host.name, ext.getLocalAddress(), ext.getRemoteAddress() ) :
					       String.format( "%s : closed", host.name );
				} catch( IOException ignored ) {
				}
				return super.toString();
			}
			
			/**
			 * Defines a vocabulary of event types that signal state changes within a {@link ExternalChannel}.
			 *
			 * <h3>Design Philosophy</h3>
			 * <p>
			 * Events are constructed as 32-bit integers using a bitmask system. This design principle
			 * allows multiple independent properties of an event—such as its source, manner, and
			 * underlying action—to be encoded into a single, efficient value. This enables flexible
			 * and high-performance event handling through simple bitwise operations.
			 *
			 * <p>
			 * The system is composed of two main parts:
			 * <ul>
			 *   <li><b>Base Actions (Lower 16 bits):</b> These are the fundamental "nouns" of an
			 *       event, like {@link Action#CONNECT} or {@link Action#CLOSE}. They describe the core action that occurred.
			 *       You can isolate the base action using the {@link Mask#ACTION}.</li>
			 *   <li><b>Flags (Higher 16 bits):</b> Defined in the {@link Mask} interface, these are
			 *       "adjectives" that add context to the base action. They specify properties like
			 *       the event's initiator ({@link Mask#REMOTE}), its manner ({@link Mask#GRACEFUL}),
			 *       or the protocol layer ({@link Mask#WEBSOCKET}).</li>
			 * </ul>
			 *
			 * <h3>Usage Examples</h3>
			 *
			 * <h4>1. Checking for a specific composite event:</h4>
			 * <pre>{@code
			 * if (event == Event.WEBSOCKET_REMOTE_CONNECT) {
			 *     // Logic for when a new WebSocket client completes its handshake.
			 * }
			 * }</pre>
			 *
			 * <h4>2. Checking for a general category of event (e.g., any close event):</h4>
			 * <pre>{@code
			 * if (Event.Action.isClose(event)) { // Using a helper method
			 *     // This will trigger for THIS_CLOSE_GRACEFUL, REMOTE_CLOSE_ABRUPTLY, etc.
			 * }
			 * }</pre>
			 *
			 * <h4>3. Checking for specific properties (e.g., any event initiated remotely and abruptly):</h4>
			 * <pre>{@code
			 * if (Event.Mask.isRemote(event) && Event.Mask.isAbrupt(event)) {
			 *     // This could be a connection reset (RST) from the peer.
			 *     log.warn("Connection was terminated abruptly by the remote peer.");
			 * }
			 * }</pre>
			 *
			 * <h4>4. Using a switch statement on the base action:</h4>
			 * <pre>{@code
			 * switch (event & Event.Mask.ACTION) {
			 *     case Event.Action.CONNECT:
			 *         // Handle any kind of successful connection (TCP, WebSocket, local, remote)
			 *         break;
			 *     case Event.Action.CLOSE:
			 *         if (Event.Mask.isGraceful(event)) {
			 *             handleClose(true);
			 *         } else {
			 *             handleClose(false);
			 *         }
			 *         break;
			 *     case Event.Action.TIMEOUT:
			 *         // Handle any timeout
			 *         break;
			 * }
			 * }</pre>
			 */
			public @interface Event {
				//--- Composite TCP/General Events ---
				
				/**
				 * Event indicating an incoming connection from a remote peer has been accepted. (Composition: {@code REMOTE | CONNECT})
				 */
				int REMOTE_CONNECT        = Mask.REMOTE | Action.CONNECT;
				/**
				 * Event indicating an outgoing connection to a remote peer was successfully established. (Composition: {@code THIS | CONNECT})
				 */
				int THIS_CONNECT          = Mask.THIS | Action.CONNECT;
				/**
				 * Event indicating the remote peer has initiated a graceful disconnection. (Composition: {@code REMOTE | GRACEFUL | CLOSE})
				 */
				int REMOTE_CLOSE_GRACEFUL = Mask.REMOTE | Mask.GRACEFUL | Action.CLOSE;
				/**
				 * Event indicating this host has completed its side of a graceful disconnection. (Composition: {@code THIS | GRACEFUL | CLOSE})
				 */
				int THIS_CLOSE_GRACEFUL   = Mask.THIS | Mask.GRACEFUL | Action.CLOSE;
				/**
				 * Event indicating the connection was abruptly closed by the remote peer or a network failure. (Composition: {@code REMOTE | ABRUPT | CLOSE})
				 */
				int REMOTE_CLOSE_ABRUPTLY = Mask.REMOTE | Mask.ABRUPT | Action.CLOSE;
				/**
				 * Event indicating this host is abruptly closing the connection. (Composition: {@code THIS | ABRUPT | CLOSE})
				 */
				int THIS_CLOSE_ABRUPTLY   = Mask.THIS | Mask.ABRUPT | Action.CLOSE;
				/**
				 * Event indicating a timeout occurred during a transmit operation. (Composition: {@code TRANSMIT | TIMEOUT})
				 */
				int TRANSMIT_TIMEOUT      = Mask.TRANSMIT | Action.TIMEOUT;
				/**
				 * Event indicating a timeout occurred during a receive operation. (Composition: {@code RECEIVE | TIMEOUT})
				 */
				int RECEIVE_TIMEOUT       = Mask.RECEIVE | Action.TIMEOUT;
				
				//--- Composite WebSocket-Specific Events ---
				
				/**
				 * Event indicating a WebSocket handshake from a remote peer has been successfully completed. (Composition: {@code WEBSOCKET | REMOTE | CONNECT})
				 */
				int WEBSOCKET_REMOTE_CONNECT        = Mask.WEBSOCKET | Mask.REMOTE | Action.CONNECT;
				/**
				 * Event indicating an outgoing WebSocket connection to a remote peer was successfully established. (Composition: {@code WEBSOCKET | THIS | CONNECT})
				 */
				int WEBSOCKET_THIS_CONNECT          = Mask.WEBSOCKET | Mask.THIS | Action.CONNECT;
				/**
				 * Event indicating a WebSocket PING frame was received from the remote peer.
				 */
				int WEBSOCKET_PING                  = Mask.WEBSOCKET | Mask.REMOTE | Action.PING;
				/**
				 * Event indicating a WebSocket PONG frame was received from the remote peer.
				 */
				int WEBSOCKET_PONG                  = Mask.WEBSOCKET | Mask.REMOTE | Action.PONG;
				/**
				 * Event indicating an empty WebSocket data frame was received.
				 */
				int WEBSOCKET_EMPTY_FRAME           = Mask.WEBSOCKET | Mask.REMOTE | Action.EMPTY_FRAME;
				/**
				 * Event indicating the remote peer initiated a graceful WebSocket close handshake.
				 */
				int WEBSOCKET_REMOTE_CLOSE_GRACEFUL = Mask.WEBSOCKET | Mask.REMOTE | Mask.GRACEFUL | Action.CLOSE;
				/**
				 * Event indicating this host has completed its side of the WebSocket close handshake.
				 */
				int WEBSOCKET_THIS_CLOSE_GRACEFUL   = Mask.WEBSOCKET | Mask.THIS | Mask.GRACEFUL | Action.CLOSE;
				/**
				 * Event indicating the WebSocket connection was abruptly closed by the remote peer or a network failure. (Composition: {@code WEBSOCKET | REMOTE | ABRUPT | CLOSE})
				 */
				int WEBSOCKET_REMOTE_CLOSE_ABRUPTLY = Mask.WEBSOCKET | Mask.REMOTE | Mask.ABRUPT | Action.CLOSE;
				/**
				 * Event indicating this host is abruptly closing the WebSocket connection. (Composition: {@code WEBSOCKET | THIS | ABRUPT | CLOSE})
				 */
				int WEBSOCKET_THIS_CLOSE_ABRUPTLY   = Mask.WEBSOCKET | Mask.THIS | Mask.ABRUPT | Action.CLOSE;
				/**
				 * Event indicating a timeout occurred during a WebSocket transmit operation. (Composition: {@code WEBSOCKET | TRANSMIT | TIMEOUT})
				 */
				int WEBSOCKET_TRANSMIT_TIMEOUT      = Mask.WEBSOCKET | Mask.TRANSMIT | Action.TIMEOUT;
				/**
				 * Event indicating a timeout occurred during a WebSocket receive operation. (Composition: {@code WEBSOCKET | RECEIVE | TIMEOUT})
				 */
				int WEBSOCKET_RECEIVE_TIMEOUT       = Mask.WEBSOCKET | Mask.RECEIVE | Action.TIMEOUT;
				
				/**
				 * Defines the base "actions" of an event, occupying the lower 16 bits of the event code.
				 */
				interface Action {
					/**
					 * Base action for a connection being established. Use {@link Mask#ACTION} to extract this from an event.
					 */
					int CONNECT     = 1;
					/**
					 * Base action for a connection being terminated.
					 */
					int CLOSE       = 2;
					/**
					 * Base action for a timeout occurring during an I/O operation.
					 */
					int TIMEOUT     = 3;
					/**
					 * Base action for a WebSocket PING control frame.
					 */
					int PING        = 4;
					/**
					 * Base action for a WebSocket PONG control frame.
					 */
					int PONG        = 5;
					/**
					 * Base action for an empty WebSocket data frame.
					 */
					int EMPTY_FRAME = 6;
					
					/**
					 * Checks if the given event represents any type of CONNECT action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is CONNECT, {@code false} otherwise.
					 */
					static boolean isConnect( int event ) { return ( event & Mask.ACTION ) == CONNECT; }
					
					/**
					 * Checks if the given event represents any type of CLOSE action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is CLOSE, {@code false} otherwise.
					 */
					static boolean isClose( int event ) { return ( event & Mask.ACTION ) == CLOSE; }
					
					static boolean isCloseGraceful( int event ) { return isClose( event ) && Mask.isGraceful( event ); }
					
					/**
					 * Checks if the given event represents any type of TIMEOUT action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is TIMEOUT, {@code false} otherwise.
					 */
					static boolean isTimeout( int event ) { return ( event & Mask.ACTION ) == TIMEOUT; }
					
					/**
					 * Checks if the given event represents a PING action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is PING, {@code false} otherwise.
					 */
					static boolean isPing( int event ) { return ( event & Mask.ACTION ) == PING; }
					
					/**
					 * Checks if the given event represents a PONG action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is PONG, {@code false} otherwise.
					 */
					static boolean isPong( int event ) { return ( event & Mask.ACTION ) == PONG; }
					
					/**
					 * Checks if the given event represents an EMPTY_FRAME action.
					 *
					 * @param event The event code to check.
					 * @return {@code true} if the base action is EMPTY_FRAME, {@code false} otherwise.
					 */
					static boolean isEmptyFrame( int event ) { return ( event & Mask.ACTION ) == EMPTY_FRAME; }
				}
				
				/**
				 * Defines bitmasks used as building blocks to compose event types. Each mask represents
				 * an independent property of an event.
				 */
				interface Mask {
					//--- Source Flags (Bit 31) ---
					/**
					 * Flag indicating the event was initiated by this endpoint (the local host). This is the default (zero).
					 */
					int THIS   = 0;
					/**
					 * Flag indicating the event was initiated by the remote peer.
					 */
					int REMOTE = 1 << 31;
					
					//--- Manner Flags (Bits 30-29) ---
					/**
					 * Flag indicating the operation was performed gracefully (e.g., a clean TCP FIN/ACK or WebSocket close handshake).
					 */
					int GRACEFUL = 1 << 30;
					/**
					 * Flag indicating the operation was abrupt (e.g., a TCP RST, a hard close, or an unhandled exception).
					 */
					int ABRUPT   = 1 << 29;
					
					//--- I/O Direction Flags (Bits 28-27) ---
					/**
					 * Flag indicating the event is related to a transmit (send) operation. Primarily used for timeouts.
					 */
					int TRANSMIT = 1 << 28;
					/**
					 * Flag indicating the event is related to a receive (read) operation. Primarily used for timeouts.
					 */
					int RECEIVE  = 1 << 27;
					
					//--- Protocol/Context Flags (Bit 26) ---
					/**
					 * Flag indicating the event is specific to the WebSocket protocol layer.
					 */
					int WEBSOCKET = 1 << 26;
					
					//--- Group & Action Masks ---
					/**
					 * A mask to isolate the source of an event ({@link #THIS} or {@link #REMOTE}).
					 */
					int SOURCE_MASK       = REMOTE;
					/**
					 * A mask to isolate the manner of an event (e.g., {@link #GRACEFUL} or {@link #ABRUPT}).
					 */
					int MANNER_MASK       = GRACEFUL | ABRUPT;
					/**
					 * A mask to isolate the I/O direction of an event (e.g., {@link #TRANSMIT} or {@link #RECEIVE}).
					 */
					int IO_DIRECTION_MASK = TRANSMIT | RECEIVE;
					/**
					 * A mask to isolate all property flags (the upper 16 bits).
					 */
					int FLAGS             = 0xFFFF0000;
					/**
					 * A mask to isolate the base action of an event (the lower 16 bits).
					 */
					int ACTION            = 0x0000FFFF;
					
					//--- Static Helper Methods ---
					
					/**
					 * Checks if the event was initiated by the remote peer.
					 */
					static boolean isRemote( int event ) { return ( event & REMOTE ) == REMOTE; }
					
					/**
					 * Checks if the event was initiated by this host.
					 */
					static boolean isThis( int event ) { return ( event & REMOTE ) == 0; }
					
					/**
					 * Checks if the event was a graceful operation.
					 */
					static boolean isGraceful( int event ) { return ( event & GRACEFUL ) == GRACEFUL; }
					
					/**
					 * Checks if the event was an abrupt operation.
					 */
					static boolean isAbrupt( int event ) { return ( event & ABRUPT ) == ABRUPT; }
					
					/**
					 * Checks if the event is WebSocket-specific.
					 */
					static boolean isWebSocket( int event ) { return ( event & WEBSOCKET ) == WEBSOCKET; }
				}
				
				/**
				 * Provides utility implementations for event handlers.
				 */
				interface Utils {
					/**
					 * A default event handler that prints a human-readable description of each event to the console.
					 */
					ObjIntConsumer< AdHoc.Channel.External > PrintConsole =
							( channel, event ) ->
							{
								if( AdHoc.debug_mode )
									System.out.println( AdHoc.StackTracePrinter.ONE.stackTrace( new Throwable( "debugging stack of onEvent" ) ) );
								
								String eventDescription;
								String[] channelInfo = channel == null || channel.toString() == null ?
								                       new String[]{ "", "" } :
								                       channel.toString().split( ":", 2 );
								
								if( Action.isConnect( event ) ) {
									boolean isWebSocket = Mask.isWebSocket( event );
									boolean isRemote    = Mask.isRemote( event );
									eventDescription = isRemote ?
									                   ( isWebSocket ?
									                     "WebSocket connection established from " :
									                     "Accepted connection from " ) :
									                   ( isWebSocket ?
									                     "WebSocket connected to " :
									                     "Connected to " );
								}
								else if( Action.isClose( event ) ) {
									boolean isWebSocket = Mask.isWebSocket( event );
									boolean isGraceful  = Mask.isGraceful( event );
									boolean isRemote    = Mask.isRemote( event );
									String prefix = isWebSocket ?
									                "WebSocket " :
									                "";
									if( isRemote ) {
										eventDescription = isGraceful ?
										                   "Remote peer gracefully closed " + prefix + "connection with " :
										                   prefix + "Connection abruptly closed by remote peer with ";
									}
									else {
										eventDescription = isGraceful ?
										                   "Gracefully closed " + prefix + "connection to " :
										                   "Abruptly closed " + prefix + "connection to ";
									}
								}
								else if( Action.isTimeout( event ) ) {
									boolean isTransmit = ( event & Mask.TRANSMIT ) != 0;
									eventDescription = ( Mask.isWebSocket( event ) ?
									                     "WebSocket " :
									                     "" ) + "Timeout while " + ( isTransmit ?
									                                                 "transmitting to " :
									                                                 "receiving from " );
								}
								else if( Action.isPing( event ) )
									eventDescription = "PING received from ";
								else if( Action.isPong( event ) )
									eventDescription = "PONG received from ";
								else if( Action.isEmptyFrame( event ) )
									eventDescription = "Empty WebSocket data frame received from ";
								else
									eventDescription = "Unknown event (" + event + ") from ";
								
								System.out.println( channelInfo[ 0 ] + ":" + eventDescription + channelInfo[ 1 ] );
							};
					
					/**
					 * A stub event handler that does nothing. Useful as a default or placeholder.
					 */
					ObjIntConsumer< AdHoc.Channel.External > Stub = ( channel, event ) -> { };
				}
			}
			
			/**
			 * The underlying asynchronous socket channel for network communication.
			 */
			public AsynchronousSocketChannel ext;
			
			/**
			 * Checks if the channel is currently active and in use.
			 * A channel is considered active if its {@code receive_time} is greater than 0.
			 *
			 * @return {@code true} if the channel is active, {@code false} otherwise.
			 */
			public boolean isActive() {
				return 0 < receive_time;
			}
			
			/**
			 * A reference to the host {@link TCP} instance that manages this channel.
			 */
			public final TCP host;
			
			/**
			 * Constructs a new Channel associated with a given TCP host.
			 *
			 * @param host The TCP host instance that this channel belongs to.
			 */
			public ExternalChannel( TCP host ) { this.host = host; }
			
			/**
			 * A flag indicating whether the channel is undergoing a graceful close sequence.
			 * This is set to {@code true} when {@link #close()} is called, signaling that a
			 * TCP FIN has been sent and the channel is waiting for the peer's acknowledgment.
			 */
			protected boolean isClosingGracefully = false;
			
			/**
			 * Initiates a graceful shutdown of the channel's output stream by sending a TCP FIN packet.
			 * <p>
			 * This method signals to the remote peer that no more data will be sent from this endpoint.
			 * It is the standard way to cleanly terminate a TCP connection. If an error occurs during
			 * the shutdown, it falls back to an abrupt closure via {@link #abort()}.
			 *
			 * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-shutdown">MSDN: shutdown function</a>
			 */
			@Override
			public void close() {
				if( !isActive() )
					return;
				isClosingGracefully = true;
				try {
					ext.shutdownOutput(); //Sends TCP FIN
				} catch( IOException e ) {
					host.onFailure.accept( this, e );
					abort();
				}
			}
			
			/**
			 * Forces an immediate, abrupt closure of the channel.
			 * <p>
			 * This method closes the underlying socket without a graceful handshake, which may
			 * result in a TCP RST being sent to the peer. It releases all associated system
			 * resources and should be used for error recovery or when immediate termination is required.
			 */
			@Override
			public void abort() {
				isClosingGracefully = false;
				if( ext == null || !ext.isOpen() )
					return;
				try {
					ext.close();
				} //Forcefully close the socket.
				catch( IOException e ) { /* Ignore*/
				}
				closeAndDispose();
			}
			
			/**
			 * Performs a partial cleanup, closing the socket but retaining the channel object and its internal handlers.
			 * <p>
			 * This method is an intermediate step in the full disposal process. It resets connection-specific
			 * state and closes the socket, but does not yet return buffers to the pool or close internal
			 * data sources/sinks. This can be useful in scenarios where the internal components might outlive
			 * the external connection.
			 */
			protected void closeNotDispose() {
				if( ext == null )
					return;
				
				if( transmit_buffer != null )
					transmit_buffer.clear();
				if( receive_buffer != null )
					receive_buffer.clear();
				
				if( ext.isOpen() )
					try {
						close();
					} catch( Exception e ) {
						host.onFailure.accept( this, e );
					}
				
				activateTransmitter(); //Mark transmitter as busy to prevent new data processing.
			}
			
			/**
			 * Closes the connection and disposes of all associated resources, making the channel available for reuse.
			 * <p>
			 * This method performs a full cleanup by closing the socket, closing the internal data source
			 * and destination, and returning I/O buffers to the pool. It then marks the channel as inactive,
			 * allowing it to be reallocated for a new connection.
			 */
			public void closeAndDispose() {
				if( !IsDeactivateActivated() )
					return; //Prevent double disposal.
				
				closeNotDispose(); //Close socket and reset state.
				
				if( internal != null && internal.BytesSrc() != null )
					try {
						internal.BytesSrc().close();
					} catch( IOException e ) {
						host.onFailure.accept( this, e );
					}
				if( internal != null && internal.BytesDst() != null )
					try {
						internal.BytesDst().close();
					} catch( IOException e ) {
						host.onFailure.accept( this, e );
					}
				
				if( transmit_buffer != null ) {
					host.buffers.get().put( transmit_buffer.clear() );
					transmit_buffer = null;
				}
				if( receive_buffer != null ) {
					host.buffers.get().put( receive_buffer.clear() );
					receive_buffer = null;
				}
			}
			
			/**
			 * Handles the failure of an asynchronous I/O operation.
			 * <p>
			 * This callback is invoked by the NIO framework when an operation fails. It translates
			 * common exceptions into specific {@link Event} types (e.g., timeouts, abrupt closures)
			 * and notifies the application. For unexpected errors, it delegates to the host's
			 * {@code onFailure} handler before cleaning up and disposing of the channel.
			 *
			 * @param e          The exception that caused the failure.
			 * @param attachment The context object associated with the failed operation (e.g., the source or destination).
			 */
			@Override
			public void failed( Throwable e, Object attachment ) {
				if( e instanceof InterruptedByTimeoutException ) {
					if( isClosingGracefully && attachment == internal.BytesDst() )
						internal.OnExternalEvent( this, Event.REMOTE_CLOSE_ABRUPTLY ); //Timeout waiting for peer's close ack.
					else if( attachment == internal.BytesSrc() )
						internal.OnExternalEvent( this, Event.TRANSMIT_TIMEOUT );
					else
						internal.OnExternalEvent( this, Event.RECEIVE_TIMEOUT );
				}
				else if( e instanceof java.nio.channels.AsynchronousCloseException ) {
					//Channel was closed locally via abort() or close(). This is an expected outcome.
					internal.OnExternalEvent( this, Event.THIS_CLOSE_ABRUPTLY );
				}
				else if( e instanceof java.io.IOException && isActive() ) {
					//A network error occurred, or the peer sent a TCP RST.
					internal.OnExternalEvent( this, Event.REMOTE_CLOSE_ABRUPTLY );
				}
				else {
					host.onFailure.accept( this, e );
				}
				closeAndDispose();
			}
			
			/**
			 * Handles the successful completion of an asynchronous I/O operation (read or write).
			 * <p>
			 * This callback is invoked by the NIO framework. Its behavior depends on the operation:
			 * <ul>
			 *   <li><b>End-of-Stream ({@code result == -1}):</b> The remote peer has gracefully closed its sending side.
			 *       This triggers a graceful close event and disposes of the channel.</li>
			 *   <li><b>Transmission Completed:</b> A write operation finished. If more data is in the buffer,
			 *       another write is initiated. Otherwise, it requests more data from the source.</li>
			 *   <li><b>Reception Completed:</b> A read operation finished. The received data is passed to the
			 *       application via {@link #receive()}, and a new read is initiated.</li>
			 * </ul>
			 *
			 * @param result     The number of bytes transferred, or -1 for end-of-stream.
			 * @param attachment The context object indicating the operation type (transmitter or receiver).
			 */
			@Override
			public void completed( Integer result, Object attachment ) {
				if( isLockedForMaintenance() )
					Thread.yield(); //Yield if maintenance is running to avoid contention.
				
				try {
					if( result == -1 ) {
						//End-of-stream: peer has gracefully closed its output.
						int event = isClosingGracefully ?
						            Event.THIS_CLOSE_GRACEFUL :
						            //Peer acknowledged our close request.
						            Event.REMOTE_CLOSE_GRACEFUL; //Peer initiated the close.
						internal.OnExternalEvent( this, event );
						closeAndDispose();
					}
					else if( attachment == internal.BytesSrc() ) { //Transmission completed.
						if( transmit_buffer == null )
							return; //channel closed or transmitting blocked..
						
						transmit_time = System.currentTimeMillis();
						activateTransmitter(); //Mark as busy to prevent re-triggering.
						
						if( transmit_buffer.hasRemaining() ) //More data in buffer? Send it.
							ext.write( transmit_buffer, TransmitTimeout(), TimeUnit.MILLISECONDS, internal.BytesSrc(), this );
						else
							transmit(); //Buffer empty? Get more data.
					}
					else { //Reception completed.
						receive_time = System.currentTimeMillis();
						receive_buffer.flip(); //Prepare buffer for reading.
						receive();             //Process received data.
					}
				} finally {
					pendingSendReceiveCompleted(); //Signal I/O completion to maintenance logic.
				}
			}
			
			protected AdHoc.Channel.Internal internal;
			
			@Override
			public AdHoc.Channel.Internal Internal() { return internal; }
			
			/**
			 * Initializes the channel with internal data handlers, activating data flow.
			 * <p>
			 * This method is critical for making a channel functional. It must be called by the user,
			 * typically within the {@code onConnected} callback, to link this external network channel
			 * with the application's internal data logic (source, destination, and event handler).
			 */
			@Override
			public void Internal( AdHoc.Channel.Internal internal ) {
				this.internal = internal;
			}
//#region Transmitting
			/**
			 * The buffer for staging outgoing data before transmission.
			 */
			public ByteBuffer transmit_buffer;
			
			/**
			 * The timestamp (in milliseconds since epoch) of the last successful data transmission.
			 */
			public long transmit_time = CHANNEL_FREE;
			
			/**
			 * Performs final setup after an outgoing connection is successfully established.
			 * <p>
			 * This is called after the channel has been initialized with its internal handlers via
			 * {@link AdHoc.Channel.External#Internal(AdHoc.Channel.Internal)}. It then fires the
			 * {@link Event#THIS_CONNECT} event and configures the channel for transmitting and receiving data.
			 */
			protected void transmitterConnected() {
				isClosingGracefully = false;
				transmit_time       = System.currentTimeMillis();
				
				internal.OnExternalEvent( this, Event.THIS_CONNECT );
				
				if( internal.BytesSrc() != null ) {
					deactivateTransmitter();
					if( transmit_buffer == null )
						transmit_buffer = host.buffers.get().get();
					internal.BytesSrc().subscribe_on_new_bytes_to_transmit_arrive( this::onNewBytesToTransmitArrive );
				}
				
				if( internal.BytesDst() != null ) {
					if( receive_buffer == null )
						receive_buffer = host.buffers.get().get();
					ext.read( receive_buffer, ReceiveTimeout(), TimeUnit.MILLISECONDS, internal.BytesDst(), this );
				}
			}
			
			/**
			 * Callback invoked when the internal data source has new bytes ready for transmission.
			 * It attempts to activate the transmitter and, if successful, starts the send process.
			 *
			 * @param src The byte source that triggered the notification.
			 */
			protected void onNewBytesToTransmitArrive( AdHoc.BytesSrc src ) {
				if( isActivateDeactivatedTransmitter() )
					transmit();
			}
			
			/**
			 * The timeout duration (in milliseconds) for asynchronous write operations.
			 */
			private long TransmitTimeout = Integer.MAX_VALUE;
			
			/**
			 * Gets the current transmit timeout in milliseconds. A negative return value indicates
			 * that a graceful close is scheduled to occur after the current transmission completes.
			 *
			 * @return The transmit timeout.
			 */
			@Override
			public long TransmitTimeout() {
				return isClosingGracefully ?
				       -TransmitTimeout :
				       TransmitTimeout;
			}
			
			/**
			 * Sets the timeout for transmit operations.
			 *
			 * @param timeout The timeout in milliseconds. If negative, a graceful close will be
			 *                initiated after all currently buffered data is sent.
			 */
			@Override
			public void TransmitTimeout( long timeout ) {
				TransmitTimeout = timeout < 0 && ( isClosingGracefully = true ) ?
				                  -timeout :
				                  timeout;
			}
			
			/**
			 * Manages the data transmission process, pulling data from the source and writing it to the socket.
			 * <p>
			 * This method runs a loop that fills the transmit buffer from the internal source and
			 * initiates an asynchronous write. The loop continues until the source is empty. When
			 * the transmitter becomes idle, it calls {@link #onTransmitterDrained()}.
			 */
			void transmit() {
				do
					try {
						if( transmit( transmit_buffer.clear() ) ) {                                                                                                  //Load data into buffer.
							ext.write( transmit_buffer, TransmitTimeout, TimeUnit.MILLISECONDS, internal.BytesSrc(), this ); //Initiate async write.
							return;                                                                                        //Exit; completion handler continues the process.
						}
					} catch( Exception e ) {
						host.onFailure.accept( this, e );
					}
				while( isDeactivateActiveTransmitter() ); //Loop if new data arrived during this operation.
				
				onTransmitterDrained(); //Source is now empty.
			}
			
			/**
			 * A hook method called when the internal data source has been fully drained.
			 * <p>
			 * The default implementation initiates a graceful close if one was scheduled. Subclasses
			 * can override this to implement protocol-specific actions, such as sending a WebSocket
			 * CLOSE frame after all application data has been transmitted.
			 */
			protected void onTransmitterDrained() {
				if( isClosingGracefully )
					close();
			}
			
			/**
			 * Loads data from the internal source into the provided buffer.
			 * <p>
			 * This is the basic data transfer step. Subclasses (e.g., {@link WebSocket}) override this
			 * method to add protocol-specific framing around the application data.
			 *
			 * @param dst The ByteBuffer to fill with outgoing data.
			 * @return {@code true} if data was read from the source, {@code false} otherwise.
			 * @throws Exception If an error occurs while reading from the source.
			 */
			protected boolean transmit( ByteBuffer dst ) throws Exception {
				boolean dataAvailable = 0 < internal.BytesSrc().read( dst );
				dst.flip();
				return dataAvailable;
			}
			
			/**
			 * Atomically checks if the transmitter was active and resets it to idle.
			 */
			protected boolean isDeactivateActiveTransmitter() { return transmitLock_.getAndSet( this, 0 ) != 0; }
			
			/**
			 * Resets the transmitter lock to the idle state (0).
			 */
			protected void deactivateTransmitter() { transmitLock_.set( this, 0 ); }
			
			/**
			 * Atomically activates the transmitter if it is idle, preventing concurrent transmission attempts.
			 */
			protected boolean isActivateDeactivatedTransmitter() { return transmitLock_.getAndIncrement( this ) == 0; }
			
			/**
			 * Increments the transmitter lock, marking it as busy or queuing an activation request.
			 */
			protected void activateTransmitter() { transmitLock_.getAndIncrement( this ); }
			
			/**
			 * A lock and counter managing the transmitter's state to prevent race conditions.
			 * <ul>
			 *   <li>{@code 0}: Idle, ready for new data.</li>
			 *   <li>{@code > 0}: Busy, with the value representing the number of pending activations.</li>
			 * </ul>
			 */
			protected volatile     int                                          transmit_lock = 1;
			/**
			 * Atomic updater for {@link #transmit_lock}.
			 */
			protected static final AtomicIntegerFieldUpdater< ExternalChannel > transmitLock_ = AtomicIntegerFieldUpdater.newUpdater( ExternalChannel.class, "transmit_lock" );
//#endregion
//#region Receiving
			/**
			 * The buffer for staging incoming data from the network.
			 */
			public                 ByteBuffer                                   receive_buffer;
			
			/**
			 * The timestamp (in milliseconds since epoch) of the last successful data reception.
			 * A value of {@link #CHANNEL_FREE} indicates the channel is inactive.
			 */
			public volatile long receive_time = CHANNEL_FREE;
			
			protected static final AtomicLongFieldUpdater< ExternalChannel > receiveTime_ = AtomicLongFieldUpdater.newUpdater( ExternalChannel.class, "receive_time" );
			
			/**
			 * Performs final setup after an incoming connection is accepted by the server.
			 * <p>
			 * It then fires the {@link Event#REMOTE_CONNECT} event and initiates the first read operation.
			 *
			 * @param externalChannel The socket channel for the new connection.
			 */
			protected void receiverConnected( AsynchronousSocketChannel externalChannel ) {
				this.ext     = externalChannel;
				receive_time = System.currentTimeMillis();
				
				internal.OnExternalEvent( this, Event.REMOTE_CONNECT );
				
				if( !ext.isOpen() )
					return;
				
				final AdHoc.Pool< ByteBuffer > buffers = host.buffers.get();
				if( receive_buffer == null )
					receive_buffer = buffers.get();
				
				if( internal.BytesSrc() != null ) { //Setup for full-duplex communication.
					deactivateTransmitter();
					if( transmit_buffer == null )
						transmit_buffer = buffers.get();
					internal.BytesSrc().subscribe_on_new_bytes_to_transmit_arrive( this::onNewBytesToTransmitArrive );
				}
				
				ext.read( receive_buffer, ReceiveTimeout(), TimeUnit.MILLISECONDS, internal.BytesDst(), this );
			}
			
			/**
			 * The timeout duration (in milliseconds) for asynchronous read operations.
			 */
			public long ReceiveTimeout = Integer.MAX_VALUE;
			
			/**
			 * Gets the current receive timeout in milliseconds. A negative value indicates
			 * a graceful close has been initiated.
			 *
			 * @return The receive timeout.
			 */
			public long ReceiveTimeout() {
				return isClosingGracefully ?
				       -ReceiveTimeout :
				       ReceiveTimeout;
			}
			
			/**
			 * Sets the timeout for receive operations.
			 *
			 * @param timeout The timeout in milliseconds. If negative, a graceful close is
			 *                initiated immediately.
			 */
			public void ReceiveTimeout( long timeout ) {
				if( timeout < 0 ) {
					if( !isClosingGracefully )
						close();
					ReceiveTimeout = -timeout;
				}
				else
					ReceiveTimeout = timeout;
			}
			
			/**
			 * Processes incoming data from the receive buffer.
			 * <p>
			 * This method is called after a read operation completes. It passes the received
			 * data to the application and then initiates a new asynchronous read to continue
			 * listening for more data.
			 */
			protected void receive() {
				try {
					receive( receive_buffer );
					ext.read( receive_buffer, ReceiveTimeout(), TimeUnit.MILLISECONDS, internal.BytesDst(), this );
				} catch( Exception e ) {
					host.onFailure.accept( this, e );
				}
			}
			
			/**
			 * Writes received data to the internal destination and prepares the buffer for the next read.
			 * <p>
			 * Subclasses (e.g., {@link WebSocket}) override this to implement protocol-specific
			 * parsing and decoding before passing data to the destination.
			 *
			 * @param src The ByteBuffer containing the received data.
			 * @throws Exception If an error occurs while writing to the destination.
			 */
			protected void receive( ByteBuffer src ) throws Exception {
				internal.BytesDst().write( src );
				src.clear();
			}
//#endregion
			
			/**
			 * A reference to the next channel in the host's singly linked list.
			 */
			volatile ExternalChannel next = null;
			
			/**
			 * Atomically activates an inactive channel. Returns {@code true} on success.
			 */
			protected boolean isActivateDeactivated() { return receiveTime_.compareAndSet( this, CHANNEL_FREE, System.currentTimeMillis() ); }
			
			/**
			 * Atomically deactivates an active channel, marking it as free. Returns {@code true} if the state was changed.
			 */
			protected boolean IsDeactivateActivated() { return receiveTime_.getAndSet( this, CHANNEL_FREE ) != CHANNEL_FREE; }
			
			/**
			 * Atomic updater for {@link #next}.
			 */
			protected static final AtomicReferenceFieldUpdater< ExternalChannel, ExternalChannel > next_ = AtomicReferenceFieldUpdater.newUpdater( ExternalChannel.class, ExternalChannel.class, "next" );
			
			/**
			 * A lock and counter for coordinating maintenance with I/O operations.
			 * <ul>
			 *   <li>{@code > 0}: The number of in-progress I/O operations.</li>
			 *   <li>{@code < 0}: Maintenance is scheduled or in progress.</li>
			 *   <li>{@code Integer.MIN_VALUE}: The channel is locked for its maintenance cycle.</li>
			 * </ul>
			 */
			private volatile int maintenance_lock = 0;
			
			/**
			 * Checks if the channel is currently scheduled for or undergoing maintenance.
			 */
			protected boolean isWaitingForMaintenance() { return maintenance_lock < 0; }
			
			/**
			 * Performs periodic maintenance tasks. Subclasses can override to add logic (e.g., timeouts).
			 */
			protected int maintenance() { return Integer.MAX_VALUE; }
			
			/**
			 * Checks if the channel is locked and ready for maintenance (i.e., no pending I/O).
			 */
			protected boolean isReadyForMaintenance() { return maintenance_lock == Integer.MIN_VALUE; }
			
			/**
			 * Resets the maintenance lock after a maintenance cycle is complete.
			 */
			protected void maintenanceCompleted() { completedLock_.set( this, 0 ); }
			
			/**
			 * Decrements the I/O operation counter, signaling that a read or write has completed.
			 */
			protected void pendingSendReceiveCompleted() { completedLock_.decrementAndGet( this ); }
			
			/**
			 * Atomically increments the I/O counter if maintenance is not locked.
			 */
			protected boolean isLockedForMaintenance() {
				int lockValue;
				do
					lockValue = maintenance_lock;
				while( !completedLock_.compareAndSet( this, lockValue, lockValue < 0 ?
				                                                       lockValue :
				                                                       lockValue + 1 ) );
				return lockValue < 0;
			}
			
			/**
			 * Schedules maintenance, preventing new I/O ops until current ones complete and maintenance runs.
			 */
			protected void scheduleMaintenance() {
				int lockValue;
				do
					lockValue = maintenance_lock;
				while( !completedLock_.compareAndSet( this, lockValue, lockValue < 0 ?
				                                                       lockValue :
				                                                       Integer.MIN_VALUE + lockValue ) );
			}
			
			/**
			 * Atomic updater for {@link #maintenance_lock}.
			 */
			protected static final AtomicIntegerFieldUpdater< ExternalChannel > completedLock_ = AtomicIntegerFieldUpdater.newUpdater( ExternalChannel.class, "maintenance_lock" );
		}
		
		/**
		 * An extension of {@link ExternalChannel} that implements the WebSocket protocol.
		 * <p>
		 * This class handles the WebSocket opening handshake, frame encoding/decoding, and
		 * the processing of control frames (PING, PONG, CLOSE) on top of the underlying
		 * TCP transport provided by the superclass.
		 */
		public static class WebSocket extends ExternalChannel {
			
			/**
			 * Constructs a new WebSocket channel.
			 *
			 * @param host The TCP host instance that this WebSocket channel belongs to.
			 */
			public WebSocket( TCP host ) { super( host ); }
			
			protected volatile boolean _wsCloseGracefully   = false;   //Flag to initiate a WS close after sending data.
			protected volatile boolean _wsClosingGracefully = false; //Flag indicating a WS close frame has been sent/is sending.
			
			/**
			 * Sets the transmit timeout. A negative value schedules a graceful WebSocket close
			 * handshake to be initiated after all pending application data has been sent.
			 *
			 * @param timeout The timeout in milliseconds.
			 */
			@Override
			public void TransmitTimeout( long timeout ) {
				super.TransmitTimeout( timeout < 0 && ( _wsCloseGracefully = true ) ?
				                       -timeout :
				                       timeout );
			}
			
			/**
			 * Sets the receive timeout. A negative value is interpreted as an immediate command
			 * to initiate a graceful WebSocket close handshake.
			 *
			 * @param timeout The timeout in milliseconds.
			 */
			@Override
			public void ReceiveTimeout( long timeout ) {
				if( timeout < 0 ) {
					closeGracefully( 1000, "Normal Closure" );
					super.ReceiveTimeout( -timeout );
				}
				else
					super.ReceiveTimeout( timeout );
			}
			
			@Override
			public void close() { closeGracefully( 1000, "AdHoc server closing" ); }
			
			/**
			 * Overridden to initiate a graceful WebSocket close if one was scheduled after
			 * all application data has been transmitted.
			 */
			@Override
			protected void onTransmitterDrained() {
				if( _wsCloseGracefully )
					closeGracefully( 1000, "Normal Closure" );
			}
			
			/**
			 * Initiates a graceful WebSocket close handshake by sending a CLOSE control frame.
			 * <p>
			 * The CLOSE frame is queued for urgent transmission, meaning it will be sent before
			 * any pending application data.
			 *
			 * @param code The WebSocket close code (e.g., 1000 for normal closure).
			 * @param why  An optional, human-readable reason for closing, truncated if its UTF-8
			 *             representation exceeds 123 bytes.
			 */
			public void closeGracefully( int code, String why ) {
				if( _wsClosingGracefully )
					return;
				_wsClosingGracefully = true;
				ControlFrameData frameData = catchUrgentFrame();
				if( frameData == null )
					frameData = frames.get().get();
				
				frameData.OPcode       = OPCode.CLOSE;
				frameData.buffer[ 0 ]  = ( byte ) ( code >>> 8 );
				frameData.buffer[ 1 ]  = ( byte ) code;
				frameData.buffer_bytes = 2;
				
				if( why != null && !why.isEmpty() ) {
					byte[] whyBytes = why.getBytes( StandardCharsets.UTF_8 );
					int    len      = Math.min( whyBytes.length, 123 ); //Max payload for control frame is 125, minus 2 for code.
					System.arraycopy( whyBytes, 0, frameData.buffer, 2, len );
					frameData.buffer_bytes += len;
				}
				
				recycleFrame( urgent.getAndSet( this, frameData ) ); //Atomically set as urgent frame.
				onNewBytesToTransmitArrive( null );                //Trigger transmitter.
			}
			
			/**
			 * Sends a WebSocket PING frame to the remote peer, optionally with a payload.
			 * The PING frame is queued for urgent transmission.
			 *
			 * @param msg An optional message to include in the PING frame.
			 */
			public void ping( String msg ) {
				ControlFrameData frameData = catchUrgentFrame();
				if( frameData == null )
					frameData = frames.get().get();
				
				if( msg == null )
					frameData.buffer_bytes = 0;
				else {
					for( int i = 0, max = msg.length(); i < max; i++ )
					     frameData.buffer[ i ] = ( byte ) msg.charAt( i );
					
					frameData.buffer_bytes = msg.length();
				}
				
				recycleFrame( urgent.getAndSet( this, frameData ) );
				onNewBytesToTransmitArrive( null );
			}
			
			/**
			 * Closes the connection and resets all WebSocket-specific state before cleaning up general resources.
			 */
			@Override
			public void closeNotDispose() {
				state              = State.HANDSHAKE;
				sent_closing_frame = isClosingGracefully = _wsClosingGracefully = _wsCloseGracefully = false;
				frame_bytes_left   = OPcode = BYTE = xor0 = xor1 = xor2 = xor3 = 0;
				
				if( frame_data != null )
					recycleFrame( frame_data );
				if( urgent_frame_data != null )
					recycleFrame( urgent_frame_data );
				recycleFrame( urgent.getAndSet( this, null ) );
				frame_lock = 0;
				
				super.closeNotDispose();
			}
			
			private  boolean          sent_closing_frame = false;
			volatile ControlFrameData urgent_frame_data;
			
			/**
			 * Encodes application data and control frames into the WebSocket wire format.
			 * <p>
			 * This method overrides the base TCP transmission logic. It prioritizes sending any
			 * "urgent" control frame (like CLOSE or PING). It then reads application data,
			 * prepends the appropriate WebSocket frame header, and writes the complete frame
			 * to the destination buffer for sending.
			 *
			 * @param dst The ByteBuffer to write the WebSocket frame into.
			 * @return {@code true} if a frame was written and is ready to send, {@code false} otherwise.
			 * @throws Exception If an error occurs during frame encoding.
			 */
			@Override
			protected boolean transmit( ByteBuffer dst ) throws Exception {
				ControlFrameData frameData = catchUrgentFrame(); //Prioritize urgent control frames.
				
				if( frameData == null ) {
					frameData = WebSocket.frame.get( this );
					if( !catchFrameSend() )
						frameData = null; //Acquire send lock for non-urgent frames.
				}
				
				//https://datatracker.ietf.org/doc/html/rfc6455#section-5.2 WebSocket Frame Format
				
				//Reserve space in the buffer for the WebSocket header and a potential control frame.
				int startPosition = dst.position( ( frameData != null ?
				                                    frameData.buffer_bytes + 2 :
				                                    0 ) + 10 ).position();
				
				//Attempt to read application data from the transmitter.
				if( 0 < internal.BytesSrc().read( dst ) ) {
					dst.flip();
					final int payloadLength = dst.limit() - startPosition;
					
					//Prepend WebSocket header for the data frame.
					if( payloadLength < 126 ) {
						dst.position( startPosition -= 2 );
						dst.put( startPosition, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) );
						dst.put( startPosition + 1, ( byte ) payloadLength );
					}
					else if( payloadLength < 0x1_0000 ) {
						dst.position( startPosition -= 4 );
						dst.put( startPosition, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) );
						dst.put( startPosition + 1, ( byte ) 126 );
						dst.put( startPosition + 2, ( byte ) ( payloadLength >> 8 ) );
						dst.put( startPosition + 3, ( byte ) payloadLength );
					}
					else {
						dst.position( startPosition -= 10 );
						dst.put( startPosition, ( byte ) ( Mask.FIN | OPCode.BINARY_FRAME ) );
						dst.put( startPosition + 1, ( byte ) 127 );
						dst.put( startPosition + 2, ( byte ) 0 );
						dst.put( startPosition + 3, ( byte ) 0 );
						dst.put( startPosition + 4, ( byte ) 0 );
						dst.put( startPosition + 5, ( byte ) 0 );
						dst.put( startPosition + 6, ( byte ) ( payloadLength >> 24 ) );
						dst.put( startPosition + 7, ( byte ) ( payloadLength >> 16 ) );
						dst.put( startPosition + 8, ( byte ) ( payloadLength >> 8 ) );
						dst.put( startPosition + 9, ( byte ) payloadLength );
					}
					
					//If a control frame is also queued, prepend it before the data frame.
					if( frameData != null ) {
						sent_closing_frame = frameData.OPcode == OPCode.CLOSE;
						recycleFrame( frameData.getFrame( dst.position( startPosition -= frameData.buffer_bytes + 2 ) ) );
					}
					
					dst.position( startPosition );
					return true;
				}
				
				//No application data, but there might be a control frame to send.
				if( frameData == null ) {
					dst.clear();
					return false;
				}
				
				sent_closing_frame = frameData.OPcode == OPCode.CLOSE;
				recycleFrame( frameData.getFrame( dst.position( 0 ) ) );
				dst.flip();
				return true;
			}
			
			/**
			 * The current state of the WebSocket frame receiver state machine.
			 */
			int state = State.HANDSHAKE;
			/**
			 * The opcode of the current WebSocket frame being processed.
			 */
			int OPcode;
			/**
			 * The number of remaining payload bytes to be read for the current frame.
			 */
			int frame_bytes_left;
			/**
			 * A temporary variable for byte-by-byte processing.
			 */
			int BYTE;
			/**
			 * The XOR masking key bytes for decoding client-to-server frames.
			 */
			int xor0, xor1, xor2, xor3;
			
			/**
			 * A volatile reference holding data for a pending control frame.
			 */
			volatile ControlFrameData frame_data;
			/**
			 * A lock to control access to frame data, ensuring thread-safe processing.
			 */
			volatile int              frame_lock = 0;
			
			/**
			 * Allocates or reuses a {@code ControlFrameData} object for a new control frame.
			 */
			protected void allocate_frame_data( @OPCode int OPCode ) {
				if( !frame_locker.compareAndSet( this, FRAME_READY, FRAME_STANDBY ) ) {
					frame_locker.set( this, FRAME_STANDBY );
					frame.set( this, frames.get().get() );
				}
				frame_data.buffer_bytes = 0;
				frame_data.OPcode       = OPCode;
			}
			
			/**
			 * Recycles a {@code ControlFrameData} object by returning it to the pool.
			 */
			protected void recycleFrame( ControlFrameData frameData ) {
				if( frameData == null )
					return;
				WebSocket.frame.compareAndSet( this, frameData, null );
				frames.get().put( frameData );
			}
			
			/**
			 * Marks the current control frame as ready for transmission and triggers the send process.
			 */
			protected void frame_ready() {
				frame_locker.set( this, FRAME_READY );
				onNewBytesToTransmitArrive( null );
			}
			
			/**
			 * Atomic updater for the {@link #frame_lock} field.
			 */
			protected static final AtomicIntegerFieldUpdater< WebSocket > frame_locker = AtomicIntegerFieldUpdater.newUpdater( WebSocket.class, "frame_lock" );
			
			/**
			 * Attempts to atomically acquire the frame sending lock.
			 */
			protected boolean catchFrameSend() { return frame_locker.compareAndSet( this, FRAME_READY, 0 ); }
			
			protected static final AtomicReferenceFieldUpdater< WebSocket, ControlFrameData > frame = AtomicReferenceFieldUpdater.newUpdater( WebSocket.class, ControlFrameData.class, "frame_data" );
			
			/**
			 * Atomically retrieves and clears the urgent frame data reference.
			 */
			protected ControlFrameData catchUrgentFrame() { return urgent.getAndSet( this, null ); }
			
			protected static final AtomicReferenceFieldUpdater< WebSocket, ControlFrameData > urgent = AtomicReferenceFieldUpdater.newUpdater( WebSocket.class, ControlFrameData.class, "urgent_frame_data" );
			
			/**
			 * Frame lock state: The frame is being prepared.
			 */
			protected static final int FRAME_STANDBY = 1;
			/**
			 * Frame lock state: The frame is ready to be sent.
			 */
			protected static final int FRAME_READY   = 2;
			
			/**
			 * A helper class for managing WebSocket control frame data and the handshake response.
			 */
			protected static class ControlFrameData {
				
				/**
				 * The WebSocket Opcode for this control frame.
				 */
				@OPCode
				int OPcode;
				/**
				 * The number of bytes currently in the buffer.
				 */
				int buffer_bytes = 0;
				/**
				 * The buffer for the control frame payload (max 125 bytes).
				 */
				final byte[]        buffer = new byte[ 125 ];
				/**
				 * A {@code MessageDigest} instance for SHA-1 hashing, used in the WebSocket handshake.
				 */
				final MessageDigest sha;
				
				{
					try {
						sha = MessageDigest.getInstance( "SHA-1" );
					} catch( NoSuchAlgorithmException e ) {
						throw new RuntimeException( e );
					}
				}
				
				/**
				 * Generates the WebSocket handshake response and writes it to the destination buffer.
				 *
				 * @param src The buffer containing the incoming handshake request.
				 * @param dst The buffer to write the WebSocket upgrade response into.
				 * @param pos The starting position of the {@code Sec-WebSocket-Key} value.
				 */
				public void put_UPGRAGE_WEBSOCKET_responce_into( ByteBuffer src, ByteBuffer dst, int pos ) throws Exception {
					int keyLength = 0;
					for( int max = src.limit(), b; pos < max && ( b = src.get( pos ) ) != '\r'; pos++, keyLength++ )
					     buffer[ keyLength ] = ( byte ) b;
					
					sha.update( buffer, 0, keyLength );
					sha.update( GUID, 0, GUID.length );
					int hashBytesLength = sha.digest( buffer, 0, buffer.length );
					sha.reset();
					
					dst.clear().put( UPGRAGE_WEBSOCKET );
					base64( buffer, 0, hashBytesLength, dst ); //Base64 encode the hash.
					dst.put( rnrn );                           //Append CRLFCRLF.
				}
				
				/**
				 * Base64 encodes a byte array segment and writes the result to a ByteBuffer.
				 */
				private void base64( byte[] src, int off, int end, ByteBuffer dst ) {
					for( int max = off + ( end - off ) / 3 * 3; off < max; ) {
						int bits = ( src[ off++ ] & 0xff ) << 16 | ( src[ off++ ] & 0xff ) << 8 | ( src[ off++ ] & 0xff );
						dst.put( byte2char[ ( bits >>> 18 ) & 0x3f ] ).put( byte2char[ ( bits >>> 12 ) & 0x3f ] ).put( byte2char[ ( bits >>> 6 ) & 0x3f ] ).put( byte2char[ bits & 0x3f ] );
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
				
				/**
				 * The standard Base64 character set.
				 */
				private static final byte[] byte2char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes();
				
				/**
				 * Writes a WebSocket control frame to the destination buffer.
				 */
				ControlFrameData getFrame( ByteBuffer dst ) {
					dst.put( ( byte ) ( Mask.FIN | OPcode ) );
					dst.put( ( byte ) buffer_bytes );
					if( 0 < buffer_bytes )
						dst.put( buffer, 0, buffer_bytes );
					return this;
				}
				
				/**
				 * Appends data from a ByteBuffer to this control frame's internal buffer.
				 */
				void put_data( ByteBuffer src, int end ) {
					int bytesToRead = end - src.position();
					src.get( buffer, buffer_bytes, bytesToRead );
					buffer_bytes += bytesToRead;
				}
				
				/**
				 * The standard GUID used in the WebSocket handshake protocol.
				 */
				static final byte[] GUID              = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".getBytes();
				/**
				 * The byte sequence for CRLFCRLF, used for HTTP header termination.
				 */
				static final byte[] rnrn              = "\r\n\r\n".getBytes();
				/**
				 * The static portion of the HTTP 101 response for a WebSocket upgrade.
				 */
				static final byte[] UPGRAGE_WEBSOCKET = ( "HTTP/1.1 101 Switching Protocols\r\n"
				                                          + "Server: AdHoc\r\n"
				                                          + "Connection: Upgrade\r\n"
				                                          + "Upgrade: websocket\r\n"
				                                          + "Sec-WebSocket-Accept: " )
						.getBytes();
			}
			
			/**
			 * A thread-local pool for reusing {@code ControlFrameData} objects.
			 */
			protected static final ThreadLocal< AdHoc.Pool< ControlFrameData > > frames = ThreadLocal.withInitial( () -> new AdHoc.Pool<>( ControlFrameData::new ) );
			
			/**
			 * A Boyer-Moore pattern for quickly finding the "Sec-Websocket-Key: " header.
			 */
			public static final int[] Sec_Websocket_Key_ = AdHoc.boyer_moore_pattern( "Sec-Websocket-Key: " );
			
			/**
			 * Parses the incoming HTTP header during the WebSocket handshake. If the {@code Sec-WebSocket-Key}
			 * is found, it generates the appropriate upgrade response.
			 *
			 * @param bytes The ByteBuffer containing the HTTP header.
			 */
			public void parsing_HTTP_header( ByteBuffer bytes ) throws Exception {
				if( transmit_buffer.position() > 0 )
					return;
				int keyStartPosition = AdHoc.boyer_moore_ASCII_Case_insensitive( bytes, Sec_Websocket_Key_ );
				if( keyStartPosition == -1 )
					return;
				
				final AdHoc.Pool< ControlFrameData > pool   = frames.get();
				final ControlFrameData               helper = pool.get();
				helper.put_UPGRAGE_WEBSOCKET_responce_into( bytes, transmit_buffer, keyStartPosition );
				pool.put( helper );
			}
			
			/**
			 * Processes received data by decoding it as WebSocket frames using a state machine.
			 * <p>
			 * This method first handles the initial HTTP handshake. Once upgraded, it enters a loop
			 * to parse WebSocket frame headers, unmask payloads, and dispatch control frames (PING, PONG, CLOSE)
			 * or data frames to the appropriate application handlers. It handles fragmented frames and
			 * protocol violations.
			 *
			 * @param src The ByteBuffer containing received bytes to be processed.
			 * @throws Exception If a protocol violation or other error occurs during frame decoding.
			 */
			@Override
			protected void receive( ByteBuffer src ) throws Exception {
receivingLoop:
				for( int index = 0; ; )
					switch( state ) {
						case State.HANDSHAKE:
							int limit = src.limit();
							//Check for complete HTTP header termination (CRLFCRLF).
							if( 4 <= limit &&
							    src.get( limit - 4 ) == ( byte ) '\r' &&
							    src.get( limit - 3 ) == ( byte ) '\n' &&
							    src.get( limit - 2 ) == ( byte ) '\r' &&
							    src.get( limit - 1 ) == ( byte ) '\n' ) {
								
								parsing_HTTP_header( src );
								if( transmit_buffer.position() == 0 ) {
									host.onFailure.accept( this, new RuntimeException( "Sec-WebSocket-Key not found in header. Handshake failed: " + toString( src ) ) );
									abort();
									break receivingLoop;
								}
								state = State.NEW_FRAME;
								activateTransmitter(); //Lock transmitter to send handshake response.
								ext.write( transmit_buffer.flip(), TransmitTimeout(), TimeUnit.MILLISECONDS, internal.BytesSrc(), this );
								internal.OnExternalEvent( this, Event.WEBSOCKET_REMOTE_CONNECT );
								break receivingLoop;
							}
							int lastNewlineIndex = limit - 1;
							//Find the last newline to process only complete header lines.
							for( ; -1 < lastNewlineIndex && src.get( lastNewlineIndex ) != '\n'; lastNewlineIndex-- )
								;
							if( lastNewlineIndex == -1 )
								return;
							src.limit( lastNewlineIndex + 1 );
							parsing_HTTP_header( src );
							
							src.limit( limit )
							   .position( lastNewlineIndex + 1 )
							   .compact(); //Shift unprocessed data to the beginning
							
							return;
						
						case State.NEW_FRAME: //Read first byte: FIN, RSV, Opcode
							if( !getByte( State.NEW_FRAME ) )
								break receivingLoop;
							OPcode = BYTE & Mask.OPCODE;
						
						case State.PAYLOAD_LENGTH_BYTE: //Read second byte: MASK, Payload len
							if( !getByte( State.PAYLOAD_LENGTH_BYTE ) )
								break receivingLoop;
							if( ( BYTE & Mask.MASK ) == 0 ) {
								//Per RFC 6455, client-to-server frames must be masked.
								host.onFailure.accept( this, new RuntimeException( "Protocol Error: Client frame is not masked." ) );
								abort();
								break receivingLoop;
							}
							xor0 = 0;
							if( 125 < ( frame_bytes_left = BYTE & Mask.LEN ) ) {
								xor0             = frame_bytes_left == 126 ?
								                   2 :
								                   //2 bytes for 16-bit extended payload length
								                   8; //8 bytes for 64-bit
								frame_bytes_left = 0;
							}
						
						case State.PAYLOAD_LENGTH_BYTES: //Read extended payload length
							for( ; 0 < xor0; xor0-- )
								if( getByte( State.PAYLOAD_LENGTH_BYTES ) )
									frame_bytes_left = ( frame_bytes_left << 8 ) | BYTE;
								else
									break receivingLoop;
						
						case State.XOR0: //Read 4-byte masking key
							if( getByte( State.XOR0 ) )
								xor0 = BYTE;
							else
								break receivingLoop;
						case State.XOR1:
							if( getByte( State.XOR1 ) )
								xor1 = BYTE;
							else
								break receivingLoop;
						case State.XOR2:
							if( getByte( State.XOR2 ) )
								xor2 = BYTE;
							else
								break receivingLoop;
						case State.XOR3:
							if( getByte( State.XOR3 ) )
								xor3 = BYTE;
							else
								break receivingLoop;
							
							switch( OPcode ) {
								case OPCode.PING:
									allocate_frame_data( OPCode.PONG ); //Prepare PONG response.
									if( frame_bytes_left == 0 ) {
										internal.OnExternalEvent( this, Event.WEBSOCKET_PING );
										frame_ready();
										state = State.NEW_FRAME;
										continue;
									}
									break;
								case OPCode.CLOSE:
									if( sent_closing_frame ) {
										internal.OnExternalEvent( this, Event.WEBSOCKET_THIS_CLOSE_GRACEFUL );
										close();
										_wsCloseGracefully = _wsClosingGracefully = false;
										break receivingLoop;
									}
									allocate_frame_data( OPCode.CLOSE ); //Prepare CLOSE response.
									break;
								case OPCode.PONG:
									internal.OnExternalEvent( this, Event.WEBSOCKET_PONG );
									state = frame_bytes_left == 0 ?
									        State.NEW_FRAME :
									        State.DISCARD; //Discard any PONG payload.
									continue;
								default: //BINARY, TEXT, CONTINUATION
									if( frame_bytes_left == 0 ) {
										internal.OnExternalEvent( this, Event.WEBSOCKET_EMPTY_FRAME );
										state = State.NEW_FRAME;
										continue;
									}
							}
							index = src.position();
						case State.DATA0: //Decode payload data
							if( decodeAndContinue( index ) )
								continue;
							break receivingLoop;
						case State.DATA1:
							if( needMoreBytes( State.DATA1, index ) )
								break receivingLoop;
							if( decodeByteAndContinue( xor1, index++ ) )
								continue;
						case State.DATA2:
							if( needMoreBytes( State.DATA2, index ) )
								break receivingLoop;
							if( decodeByteAndContinue( xor2, index++ ) )
								continue;
						case State.DATA3:
							if( needMoreBytes( State.DATA3, index ) )
								break receivingLoop;
							if( decodeByteAndContinue( xor3, index++ ) )
								continue;
							if( decodeAndContinue( index ) )
								continue;
							break receivingLoop;
						
						case State.DISCARD: //Discard payload bytes (e.g., for a PONG)
							int bytesToDiscard = Math.min( src.remaining(), frame_bytes_left );
							src.position( src.position() + bytesToDiscard );
							if( ( frame_bytes_left -= bytesToDiscard ) == 0 ) {
								state = State.NEW_FRAME;
								continue;
							}
							break receivingLoop;
					}
				src.clear();
			}
			
			/**
			 * Decodes a 4-byte chunk of the WebSocket payload.
			 *
			 * @param index The starting index in the receive buffer for decoding.
			 * @return {@code true} if decoding can continue, {@code false} if more bytes are needed.
			 * @throws IOException If an I/O error occurs.
			 */
			boolean decodeAndContinue( int index ) throws IOException {
				for( ; ; ) {
					if( needMoreBytes( State.DATA0, index ) )
						return false;
					if( decodeByteAndContinue( xor0, index++ ) )
						return true;
					if( needMoreBytes( State.DATA1, index ) )
						return false;
					if( decodeByteAndContinue( xor1, index++ ) )
						return true;
					if( needMoreBytes( State.DATA2, index ) )
						return false;
					if( decodeByteAndContinue( xor2, index++ ) )
						return true;
					if( needMoreBytes( State.DATA3, index ) )
						return false;
					if( decodeByteAndContinue( xor3, index++ ) )
						return true;
				}
			}
			
			/**
			 * Checks if more bytes are needed from the network to continue decoding the current frame.
			 *
			 * @param stateIfNoMoreBytes The state to transition to if more bytes are needed.
			 * @param index              The current index in the receive buffer.
			 * @return {@code true} if more bytes are needed, {@code false} otherwise.
			 * @throws IOException If an I/O error occurs.
			 */
			boolean needMoreBytes( int stateIfNoMoreBytes, int index ) throws IOException {
				if( index < receive_buffer.limit() )
					return false;
				switch( OPcode ) {
					case OPCode.PING:
					case OPCode.CLOSE:
						frame_data.put_data( receive_buffer, index );
					default:
						internal.BytesDst().write( receive_buffer );
				}
				state = frame_bytes_left == 0 ?
				        State.NEW_FRAME :
				        stateIfNoMoreBytes;
				return true;
			}
			
			/**
			 * Decodes a single byte of the payload. Returns true if the frame is complete.
			 */
			boolean decodeByteAndContinue( int XOR, int index ) throws IOException {
				receive_buffer.put( index, ( byte ) ( receive_buffer.get( index++ ) & 0xFF ^ XOR ) );
				if( 0 < --frame_bytes_left )
					return false;
				
				//Frame is fully received. Process it.
				final int limit = receive_buffer.limit();
				switch( OPcode ) {
					case OPCode.PING:
						frame_data.put_data( receive_buffer, index );
						internal.OnExternalEvent( this, Event.WEBSOCKET_PING );
						frame_ready(); //Send PONG response.
						break;
					case OPCode.CLOSE:
						frame_data.put_data( receive_buffer, index );
						internal.OnExternalEvent( this, Event.WEBSOCKET_REMOTE_CLOSE_GRACEFUL );
						frame_ready(); //Send CLOSE confirmation.
						break;
					default:
						internal.BytesDst().write( receive_buffer.limit( index ) );
				}
				state = State.NEW_FRAME;
				if( index < limit )
					receive_buffer.limit( limit ).position( index );
				return true;
			}
			
			/**
			 * Gets a single byte from the receive buffer. Returns false if the buffer is empty.
			 */
			boolean getByte( int stateIfNoMoreBytes ) {
				if( receive_buffer.hasRemaining() ) {
					BYTE = receive_buffer.get() & 0xFF;
					return true;
				}
				state = stateIfNoMoreBytes;
				return false;
			}
			
			/**
			 * Converts a ByteBuffer to a String for debugging.
			 */
			String toString( ByteBuffer bb ) {
				final int    pos = bb.position();
				final byte[] dst = new byte[ bb.remaining() ];
				bb.get( dst );
				bb.position( pos );
				return new String( dst );
			}
			
			/**
			 * Defines standard WebSocket opcodes as per RFC 6455.
			 */
			private @interface OPCode {
				int CONTINUATION = 0x00;
				int TEXT_FRAME   = 0x01;
				int BINARY_FRAME = 0x02;
				int CLOSE        = 0x08;
				int PING         = 0x09;
				int PONG         = 0x0A;
			}
			
			/**
			 * Defines the states for the WebSocket frame receiving state machine.
			 */
			private @interface State {
				int HANDSHAKE            = 0;
				int NEW_FRAME            = 1;
				int PAYLOAD_LENGTH_BYTE  = 2;
				int PAYLOAD_LENGTH_BYTES = 3;
				int XOR0                 = 4;
				int XOR1                 = 5;
				int XOR2                 = 6;
				int XOR3                 = 7;
				int DATA0                = 8;
				int DATA1                = 9;
				int DATA2                = 10;
				int DATA3                = 11;
				int DISCARD              = 12;
			}
			
			/**
			 * Defines masks for decoding bits in the WebSocket frame header.
			 */
			private @interface Mask {
				int FIN    = 0b1000_0000;
				int OPCODE = 0b0000_1111;
				int MASK   = 0b1000_0000;
				int LEN    = 0b0111_1111;
			}
			
			/**
			 * Implements a WebSocket client using the built-in {@link java.net.http.WebSocket}.
			 * <p>
			 * This class is a specialized adapter, designed to bridge an internal data source
			 * ({@code AdHoc.BytesSrc}) and destination ({@code AdHoc.BytesDst}) with a WebSocket
			 * connection. It is not a general-purpose client with public send/receive methods;
			 * instead, it acts as a dedicated transport layer, transparently handling data flow
			 * once initialized.
			 */
			public static class Client< INT extends AdHoc.Channel.Internal > {
				
				private final String     name;
				private final HttpClient httpClient;
				private final ByteBuffer transmitBuffer;
				private       String     connectionInfo = ":";
				
				private final    ScheduledExecutorService                     watchdogScheduler;
				private final    AtomicReference< ScheduledFuture< ? > >      watchdogFuture = new AtomicReference<>();
				private final    AtomicBoolean                                transmitLock   = new AtomicBoolean( false );
				private volatile CompletableFuture< java.net.http.WebSocket > webSocketFuture;
				
				/**
				 * Constructs a new WebSocket client adapter.
				 *
				 * @param name        A descriptive name for this client instance.
				 * @param newInternal A factory to create the internal channel handler.
				 * @param onFailure   A callback for handling asynchronous operation failures.
				 * @param bufferSize  The size of the internal buffer for sending data.
				 */
				public Client( String name, Function< AdHoc.Channel.External, INT > newInternal, BiConsumer< Object, Throwable > onFailure, int bufferSize ) {
					this.name = name;
					external.Internal( newInternal.apply( external ) );
					this.httpClient        = HttpClient.newHttpClient();
					this.transmitBuffer    = ByteBuffer.allocateDirect( bufferSize ).order( ByteOrder.LITTLE_ENDIAN );
					this.watchdogScheduler = Executors.newSingleThreadScheduledExecutor( r -> new Thread( r, "WebSocket-Watchdog-" + name ) {
						{
							setDaemon( true );
						}
					} );
					this.onFailure         = onFailure;
				}
				
				public Client( String name, Function< AdHoc.Channel.External, INT > newInternal, int bufferSize ) { this( name, newInternal, onFailurePrintConsole, bufferSize ); }
				
				public Client( String name, Function< AdHoc.Channel.External, INT > newInternal )                 { this( name, newInternal, onFailurePrintConsole, 1024 ); }
				
				/**
				 * Connects to a WebSocket server asynchronously.
				 *
				 * @param server            The URI of the WebSocket server.
				 * @param connectingTimeout The maximum duration to wait for the connection to be established.
				 * @return A {@link CompletableFuture} that completes with the {@link INT} on success,
				 * or completes exceptionally on failure.
				 */
				public CompletableFuture< INT > connect( URI server, Duration connectingTimeout ) {
					this.connectionInfo = String.format( " %s : %s", name, "closed" );
					
					CompletableFuture< INT > promise = new CompletableFuture<>();
					if( !connectionPromise.compareAndSet( null, promise ) )
						return connectionPromise.get();
					
					webSocketFuture = httpClient.newWebSocketBuilder()
					                            .connectTimeout( connectingTimeout )
					                            .buildAsync( server, external );
					
					webSocketFuture.whenComplete(
							( ws, ex ) -> {
								this.connectionInfo = String.format( " %s : %s", name, server );
								if( ex == null ) return;
								onFailure.accept( this, ex );
								CompletableFuture< INT > p = connectionPromise.getAndSet( null );
								if( p != null )
									p.completeExceptionally( ex );
							} );
					
					return promise;
				}
				
				private final AtomicReference< CompletableFuture< INT > > connectionPromise = new AtomicReference<>();
				
				public boolean isConnecting() { return connectionPromise.get() != null; }
				
				public boolean isConnected() {
					if( webSocketFuture == null || !webSocketFuture.isDone() || webSocketFuture.isCompletedExceptionally() ) return false;
					java.net.http.WebSocket ws = webSocketFuture.getNow( null );
					return ws != null && !ws.isInputClosed() && !ws.isOutputClosed();
				}
				
				/**
				 * Connects to a WebSocket server with a default timeout of 5 seconds.
				 *
				 * @param server The URI of the WebSocket server.
				 * @return A {@link CompletableFuture} that completes with the {@link INT} on success, or completes exceptionally on failure.
				 */
				public CompletableFuture< INT > connect( URI server ) { return connect( server, Duration.ofSeconds( 5 ) ); }
				
				private void closeConnection( int statusCode, String reason ) {
					if( webSocketFuture != null )
						webSocketFuture.thenAccept( ws -> { if( ws != null && !ws.isOutputClosed() ) ws.sendClose( statusCode, reason ); } );
				}
				
				private void shutdownScheduler() {
					ScheduledFuture< ? > future = watchdogFuture.getAndSet( null );
					if( future != null )
						future.cancel( false );
					if( !watchdogScheduler.isShutdown() )
						watchdogScheduler.shutdownNow();
				}
				
				@Override
				public String toString() { return connectionInfo; }
				
				/**
				 * Generic failure event handler for connection, transmission, or reception errors.
				 */
				protected final BiConsumer< Object, Throwable > onFailure;
				
				public void abort() { external.abort(); }
				
				private final External external = new External();
				
				/**
				 * Internal implementation that bridges AdHoc channel logic with java.net.http.WebSocket.Listener.
				 */
				private class External implements java.net.http.WebSocket.Listener, AdHoc.Channel.External {
					@Override
					public String toString() { return connectionInfo; }
					
					protected boolean isClosingGracefully = false;
					private   long    TransmitTimeout     = Integer.MAX_VALUE;
					
					@Override
					public long TransmitTimeout() {
						return isClosingGracefully ?
						       -TransmitTimeout :
						       TransmitTimeout;
					}
					
					@Override
					public void TransmitTimeout( long timeout ) {
						TransmitTimeout = ( isClosingGracefully = timeout < 0 ) ?
						                  -timeout :
						                  timeout;
					}
					
					public long ReceiveTimeout = Integer.MAX_VALUE;
					
					@Override
					public long ReceiveTimeout() {
						return isClosingGracefully ?
						       -ReceiveTimeout :
						       ReceiveTimeout;
					}
					
					@Override
					public void ReceiveTimeout( long timeout ) {
						if( timeout < 0 ) {
							ReceiveTimeout = -timeout;
							close();
						}
						else
							ReceiveTimeout = timeout;
					}
					
					private AdHoc.Channel.Internal internal;
					
					@Override
					public AdHoc.Channel.Internal Internal() { return internal; }
					
					/**
					 * Links this external channel representation to the application's internal data logic.
					 * This method is called by the {@link WebSocket.Client} constructor, not by the end-user.
					 *
					 * @param internal An implementation providing the data logic.
					 */
					@Override
					public void Internal( AdHoc.Channel.Internal internal ) { this.internal = internal; }
					
					@Override
					public void closeAndDispose() {
						if( internal != null )
							internal.OnExternalEvent( this, Event.WEBSOCKET_THIS_CLOSE_GRACEFUL );
						closeConnection( java.net.http.WebSocket.NORMAL_CLOSURE, "Client disposing" );
						shutdownScheduler();
					}
					
					@Override
					public void close() {
						if( internal != null )
							internal.OnExternalEvent( this, Event.WEBSOCKET_THIS_CLOSE_GRACEFUL );
						closeConnection( java.net.http.WebSocket.NORMAL_CLOSURE, "Client closing" );
					}
					
					@Override
					public void abort() {
						synchronized( this ) {
							if( internal != null )
								internal.OnExternalEvent( this, Event.WEBSOCKET_THIS_CLOSE_ABRUPTLY );
							if( webSocketFuture != null )
								webSocketFuture.thenAccept( ws -> { if( ws != null && !ws.isOutputClosed() ) ws.abort(); } );
						}
						shutdownScheduler();
					}
					
					/**
					 * Called when the WebSocket handshake is complete. This completes the user's connection
					 * promise and fires the connect event.
					 */
					@Override
					@SuppressWarnings( "unchecked" )
					
					public void onOpen( java.net.http.WebSocket ws ) {
						CompletableFuture< INT > promise = connectionPromise.getAndSet( null );
						if( promise != null )
							
							promise.complete( ( INT ) Internal() );
						
						java.net.http.WebSocket.Listener.super.onOpen( ws );
						resetReceiveTimeout( ws );
						
						internal.OnExternalEvent( this, Event.WEBSOCKET_THIS_CONNECT );
						internal.BytesSrc().subscribe_on_new_bytes_to_transmit_arrive( src -> {
							if( transmitLock.compareAndSet( false, true ) )
								try {
									transmitLoop( ws, getNextFragment() );
								} catch( Exception e ) {
									onFailure.accept( Client.this, e );
									finishSend();
								}
						} );
					}
					
					@Override
					public CompletionStage< ? > onBinary( java.net.http.WebSocket ws, ByteBuffer data, boolean last ) {
						resetReceiveTimeout( ws );
						try {
							if( internal != null && internal.BytesDst() != null )
								internal.BytesDst().write( data );
						} catch( Throwable e ) {
							onFailure.accept( Client.this, e );
						}
						return java.net.http.WebSocket.Listener.super.onBinary( ws, data, last );
					}
					
					@Override
					public CompletionStage< ? > onClose( java.net.http.WebSocket webSocket, int statusCode, String reason ) {
						if( internal != null )
							internal.OnExternalEvent( this, Event.WEBSOCKET_REMOTE_CLOSE_GRACEFUL );
						shutdownScheduler();
						return java.net.http.WebSocket.Listener.super.onClose( webSocket, statusCode, reason );
					}
					
					@Override
					public void onError( java.net.http.WebSocket ws, Throwable e ) {
						onFailure.accept( Client.this, e );
						// If an error occurs during the connection phase, ensure the promise is failed.
						CompletableFuture< INT > promise = connectionPromise.getAndSet( null );
						if( promise != null ) {
							promise.completeExceptionally( e );
						}
						if( internal != null )
							internal.OnExternalEvent( this, Event.WEBSOCKET_REMOTE_CLOSE_ABRUPTLY );
						shutdownScheduler();
						java.net.http.WebSocket.Listener.super.onError( ws, e );
					}
					
					private void transmitLoop( java.net.http.WebSocket ws, ByteBuffer firstFragment ) {
						if( firstFragment == null ) {
							finishSend();
							return;
						}
						try {
							ByteBuffer nextFragment = getNextFragment();
							boolean    isLast       = ( nextFragment == null );
							sendWithTimeout( ws, firstFragment, isLast ).whenComplete( ( v, ex ) -> {
								if( ex != null ) {
									onFailure.accept( Client.this, ex );
									if( ex instanceof TimeoutException )
										internal.OnExternalEvent( this, Event.WEBSOCKET_TRANSMIT_TIMEOUT );
									finishSend();
								}
								else if( isLast )
									finishSend();
								else
									transmitLoop( ws, nextFragment );
							} );
						} catch( Exception ex ) {
							onFailure.accept( Client.this, ex );
							finishSend();
						}
					}
					
					private ByteBuffer getNextFragment() throws Exception {
						transmitBuffer.clear();
						int bytesRead = internal.BytesSrc().read( transmitBuffer );
						if( bytesRead <= 0 )
							return null;
						transmitBuffer.flip();
						return transmitBuffer.duplicate();
					}
					
					private CompletionStage< Void > sendWithTimeout( java.net.http.WebSocket ws, ByteBuffer data, boolean last ) {
						CompletableFuture< Void > cf = new CompletableFuture<>();
						if( TransmitTimeout > 0 && TransmitTimeout < Integer.MAX_VALUE ) {
							ScheduledFuture< ? > timeoutFuture = watchdogScheduler.schedule( () -> cf.completeExceptionally( new TimeoutException( "Send operation timed out after " + TransmitTimeout + "ms" ) ), TransmitTimeout, TimeUnit.MILLISECONDS );
							ws.sendBinary( data, last ).whenComplete( ( v, e ) -> {
								timeoutFuture.cancel( false );
								if( e != null )
									cf.completeExceptionally( e );
								else
									cf.complete( null );
							} );
						}
						else {
							ws.sendBinary( data, last ).whenComplete( ( v, e ) -> {
								if( e != null )
									cf.completeExceptionally( e );
								else
									cf.complete( null );
							} );
						}
						return cf;
					}
					
					private void finishSend() {
						transmitLock.set( false );
						if( isClosingGracefully )
							closeAndDispose();
					}
					
					private void resetReceiveTimeout( java.net.http.WebSocket ws ) {
						ScheduledFuture< ? > oldFuture = watchdogFuture.getAndSet( null );
						if( oldFuture != null )
							oldFuture.cancel( false );
						if( 0 < ReceiveTimeout && ReceiveTimeout < Integer.MAX_VALUE ) {
							ScheduledFuture< ? > newFuture = watchdogScheduler.schedule( () -> {
								if( ws.isInputClosed() )
									return;
								internal.OnExternalEvent( this, Event.WEBSOCKET_RECEIVE_TIMEOUT );
								TimeoutException ex = new TimeoutException( "Receive timed out. No data received for " + ReceiveTimeout + "ms." );
								onFailure.accept( Client.this, ex );
								ws.sendClose( java.net.http.WebSocket.NORMAL_CLOSURE, "Idle timeout" );
							}, ReceiveTimeout, TimeUnit.MILLISECONDS );
							watchdogFuture.set( newFuture );
						}
					}
				}
			}
		}
		
		/**
		 * An asynchronous, non-blocking TCP server.
		 * <p>
		 * This class listens on one or more network interfaces, accepting incoming TCP connections.
		 * It manages a pool of channels to handle multiple concurrent clients and includes a
		 * maintenance thread for periodic tasks like timeout checks and resource cleanup.
		 */
		public static class Server extends TCP {
			
			/**
			 * The shared {@code ForkJoinPool} used for all asynchronous channel operations.
			 */
			public static final ForkJoinPool             executor = ForkJoinPool.commonPool();
			/**
			 * The {@code AsynchronousChannelGroup} that manages resources for the server's channels.
			 */
			final               AsynchronousChannelGroup group    = AsynchronousChannelGroup.withThreadPool( executor );
			
			/**
			 * Constructs and starts a new TCP Server with onFailure = onFailurePrintConsole and buffer_size = 1024
			 *
			 * @param name        A descriptive name for this server instance.
			 * @param new_channel A factory function to create new {@link ExternalChannel} instances for accepted connections.
			 * @param ips         An array of {@link InetSocketAddress} to bind the server to.
			 * @throws IOException If a binding error occurs.
			 */
			public Server( String name,
			               Function< TCP, ExternalChannel > new_channel,
			               InetSocketAddress... ips ) throws IOException { this( name, new_channel, onFailurePrintConsole, 1024, ips ); }
			
			/**
			 * Constructs and starts a new TCP Server.
			 *
			 * @param name        A descriptive name for this server instance.
			 * @param new_channel A factory function to create new {@link ExternalChannel} instances for accepted connections.
			 * @param onFailure   A callback for handling asynchronous operation failures.
			 * @param buffer_size The I/O buffer size for each channel.
			 * @param ips         An array of {@link InetSocketAddress} to bind the server to.
			 * @throws IOException If a binding error occurs.
			 */
			public Server( String name,
			               Function< TCP, ExternalChannel > new_channel,
			               BiConsumer< Object, Throwable > onFailure,
			               int buffer_size,
			               InetSocketAddress... ips ) throws IOException {
				super( name, new_channel, onFailure, buffer_size );
				bind( ips );
			}
			
			/**
			 * A list of {@link AsynchronousServerSocketChannel}s listening for connections.
			 */
			public ArrayList< AsynchronousServerSocketChannel > tcp_listeners = new ArrayList<>();
			
			/**
			 * Binds the server to the specified addresses and begins accepting connections.
			 *
			 * @param ips The addresses to bind the server to.
			 * @throws IOException If a binding error occurs.
			 */
			public void bind( InetSocketAddress... ips ) throws IOException {
				StringBuilder serverDescription = new StringBuilder( 50 ).append( "Server " ).append( name );
				
				for( InetSocketAddress ip : ips ) {
					serverDescription.append( '\n' ).append( "\t\t -> " ).append( ip );
					final AsynchronousServerSocketChannel tcpListener = AsynchronousServerSocketChannel.open( group ).setOption( StandardSocketOptions.SO_REUSEADDR, true ).bind( ip );
					tcp_listeners.add( tcpListener );
					
					tcpListener.accept( null, new CompletionHandler< AsynchronousSocketChannel, Void >() {
						@Override
						public void completed( AsynchronousSocketChannel client, Void v ) {
							allocate().receiverConnected( client );
							tcpListener.accept( null, this ); //Continue accepting connections.
						}
						
						@Override
						public void failed( Throwable e, Void v ) { onFailure.accept( this, e ); }
					} );
				}
				toString = serverDescription.toString();
			}
			
			private String toString;
			
			@Override
			public String toString() { return toString; }
			
			/**
			 * A lock for synchronizing maintenance operations.
			 */
			private final ReentrantLock maintenance_lock  = new ReentrantLock();
			private final Condition     when              = maintenance_lock.newCondition();
			private final AtomicInteger maintenance_state = new AtomicInteger( 0 ); //0=idle, 1=running, 2=triggered
			
			protected void startMaintenance()        { maintenance_state.set( 1 ); }
			
			protected boolean restartMaintenance()   { return 1 < maintenance_state.getAndSet( 0 ); }
			
			protected boolean isMaintenanceRunning() { return 0 < maintenance_state.getAndSet( 2 ); }
			
			/**
			 * The background thread for periodic channel maintenance.
			 */
			private final Thread maintenance_thread = new Thread( "Maintain server " + name ) {
				{
					setDaemon( true );
					start();
				}
				
				/**
				 * The background thread responsible for periodic channel maintenance tasks.
				 */
				@Override
				public void run() {
					while( true ) {
						maintenance_lock.lock();
						try {
							startMaintenance();
							long waitTime = maintenance( System.currentTimeMillis() );
							if( restartMaintenance() )
								continue;
							when.awaitNanos( waitTime * 1_000_000 );
						} catch( Exception ex ) {
							onFailure.accept( this, ex );
						} finally {
							maintenance_lock.unlock();
						}
					}
				}
			};
			
			/**
			 * Forces the maintenance thread to wake up and run a cycle immediately.
			 */
			@Override
			public void trigger_maintenance() {
				if( isMaintenanceRunning() )
					return;
				maintenance_lock.lock();
				try {
					when.signal();
				} finally {
					maintenance_lock.unlock();
				}
			}
			
			/**
			 * Performs a maintenance cycle, iterating over all active channels and running their maintenance tasks.
			 *
			 * @param time The current time in milliseconds.
			 * @return The minimum time in milliseconds to wait before the next cycle.
			 */
			protected long maintenance( long time ) {
				while( true ) {
					long timeout = maintenance_duty_cycle;
					for( ExternalChannel channel = channels; channel != null; channel = channel.next )
						if( channel.isActive() && channel.isWaitingForMaintenance() ) {
							if( channel.isReadyForMaintenance() ) {
								timeout = Math.min( channel.maintenance(), timeout );
								channel.maintenanceCompleted();
							}
							else {
								timeout = 0; //Force immediate re-run if a channel is not ready.
							}
						}
					if( 0 < timeout )
						return timeout;
					Thread.yield();
				}
			}
			
			/**
			 * The default minimum duration between maintenance cycles, in milliseconds. Default is 5 seconds.
			 */
			public long maintenance_duty_cycle = 5000;
			
			/**
			 * Shuts down the server, closing all listeners and active channels.
			 */
			public void shutdown() {
				for( Closeable closeable : tcp_listeners )
					try {
						closeable.close();
					} catch( IOException e ) {
						onFailure.accept( this, e );
					}
				for( ExternalChannel channel = channels; channel != null; channel = channel.next )
					if( channel.isActive() )
						channel.abort();
			}
		}
		
		/**
		 * An asynchronous, non-blocking TCP client.
		 * <p>
		 * This class provides functionality to connect to a TCP server, send and receive data,
		 * and handle connection lifecycle events using Java's asynchronous socket channels.
		 */
		public static class Client< INT extends AdHoc.Channel.Internal > extends TCP {
			
			/**
			 * The name of this client instance.
			 */
			public final String name;
			
			/**
			 * Constructs a new TCP Client.
			 *
			 * @param name        A descriptive name for this client instance.
			 * @param newInternal A factory to create the internal channel handler.
			 * @param onFailure   A callback for handling asynchronous operation failures.
			 * @param buffer_size The I/O buffer size for the channel.
			 */
			public Client( String name, Function< AdHoc.Channel.External, INT > newInternal, BiConsumer< Object, Throwable > onFailure, int buffer_size ) {
				super( name, ExternalChannel::new, onFailure, buffer_size );
				channels.Internal( newInternal.apply( channels ) );
				this.name = name;
			}
			
			public Client( String name, Function< AdHoc.Channel.External, INT > newInternal, int bufferSize ) { this( name, newInternal, onFailurePrintConsole, bufferSize ); }
			
			public Client( String name, Function< AdHoc.Channel.External, INT > newInternal )                 { this( name, newInternal, onFailurePrintConsole, 1024 ); }
			
			/**
			 * Connects to a server with a default timeout of 5 seconds.
			 *
			 * @param server The address of the server to connect to.
			 * @return A {@link CompletableFuture} that completes with the {@link INT} on success.
			 */
			public CompletableFuture< INT > connect( InetSocketAddress server ) {
				return connect( server, Duration.ofSeconds( 5 ) );
			}
			
			/**
			 * Connects to a server with a specified timeout.
			 * <p>
			 * This method initiates an asynchronous connection attempt. The returned future will
			 * be completed with the channel upon success. If the connection fails or times out,
			 * the future will complete with a {@code null} result, and the failure will be
			 * reported to the {@code onFailure} handler.
			 *
			 * @param server  The address of the server to connect to.
			 * @param timeout The maximum duration to wait for the connection.
			 * @return A {@link CompletableFuture} that completes with the channel on success, or {@code null} on failure.
			 */
			public CompletableFuture< INT > connect( InetSocketAddress server, Duration timeout ) {
				this.toString = String.format( "Client %s -> %s", name, server );
				CompletableFuture< INT > promise = new CompletableFuture<>();
				if( !connectionPromise.compareAndSet( null, promise ) ) return connectionPromise.get();
				
				try { ( channels.ext = AsynchronousSocketChannel.open() ).connect( server, promise, onConnecting ); } catch( IOException e ) {
					onFailure.accept( this, e );
					promise.completeExceptionally( e );
				}
				
				return promise
						.orTimeout( timeout.toMillis(), TimeUnit.MILLISECONDS )
						.whenComplete(
								( channel, ex ) -> {
									connectionPromise.set( null ); // Reset state when connection attempt finishes.
									if( ex != null )
										onFailure.accept( this, ex.getCause() != null ?
										                        ex.getCause() :
										                        ex );
								} );
			}
			
			private final AtomicReference< CompletableFuture< INT > > connectionPromise = new AtomicReference<>();
			
			public boolean isConnecting() { return connectionPromise.get() != null; }
			
			public boolean isConnected()  { return !isConnecting() && channels != null && channels.ext != null && channels.ext.isOpen(); }
			
			/**
			 * A {@code CompletionHandler} for the asynchronous connection attempt.
			 */
			@SuppressWarnings( "unchecked" )
			private final CompletionHandler< Void, CompletableFuture< INT > > onConnecting = new CompletionHandler<>() {
				@Override
				public void completed( Void v, CompletableFuture< INT > promise ) {
					try {
						promise.complete( ( INT ) channels.Internal() );
						channels.transmitterConnected();
					} catch( Throwable t ) {
						promise.completeExceptionally( t );
					}
				}
				
				@Override
				public void failed( Throwable t, CompletableFuture< INT > promise ) { promise.completeExceptionally( t ); }
			};
			
			private String toString;
			
			@Override
			public String toString() { return toString; }
		}
	}
	
	/**
	 * An in-memory, direct byte stream connection between two components.
	 * <p>
	 * This class simulates a network connection entirely within memory, providing a zero-latency
	 * "wire" between a data source and a destination. It is useful for testing application logic
	 * without network overhead or for tightly coupled components within the same process.
	 */
	class Wire {
		/**
		 * The ByteBuffer used as the transfer medium.
		 */
		protected final ByteBuffer                 buffer;
		/**
		 * The data source from which bytes are read.
		 */
		protected       AdHoc.BytesSrc             src;
		/**
		 * The subscriber that reacts to new data from the source.
		 */
		protected       Consumer< AdHoc.BytesSrc > subscriber;
		
		/**
		 * Constructs a new Wire connection.
		 *
		 * @param src         The byte source to read data from.
		 * @param dst         The byte destination to write data to.
		 * @param buffer_size The size of the internal buffer for data transfer.
		 */
		public Wire( AdHoc.BytesSrc src, AdHoc.BytesDst dst, int buffer_size ) {
			buffer = ByteBuffer.wrap( new byte[ buffer_size ] );
			connect( src, dst );
		}
		
		/**
		 * Establishes the connection between a byte source and destination.
		 * <p>
		 * When the source signals that new data is available, this wire reads the data into an
		 * internal buffer and immediately writes it to the destination.
		 *
		 * @param src The byte source to connect.
		 * @param dst The byte destination to connect.
		 */
		public void connect( AdHoc.BytesSrc src, AdHoc.BytesDst dst ) {
			if( this.src != null )
				this.src.subscribe_on_new_bytes_to_transmit_arrive( subscriber ); //Unsubscribe from previous.
			
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
	
	/**
	 * A conceptual placeholder for a UDP-based network implementation.
	 * <p>
	 * A direct UDP implementation is not provided. A recommended strategy for achieving
	 * reliable, ordered, and secure UDP-like communication is to use the provided TCP
	 * implementation over a secure UDP tunnel like WireGuard.
	 *
	 * @see <a href="https://www.wireguard.com/">WireGuard</a>
	 */
	class UDP {
		//A recommended strategy is to use the TCP implementation over a WireGuard tunnel: https://www.wireguard.com/
	}
}