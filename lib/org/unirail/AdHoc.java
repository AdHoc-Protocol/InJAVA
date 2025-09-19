// Copyright 2025 Chikirev Sirguy, Unirail Group
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// For inquiries, please contact: al8v5C6HU4UtqE9@gmail.com
// GitHub Repository: https://github.com/AdHoc-Protocol

package org.unirail;

import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
import java.lang.ref.SoftReference;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Abstract base class for AdHoc communication protocol implementations.
 * Provides core functionalities for data serialization, framing, receiving, and transmitting,
 * including support for various data types, null handling, and bit-level operations.
 */
public abstract class AdHoc {
	Network.TCP.ExternalChannel externalChannel;
//#region CRC Calculation
	
	/**
	 * Length of CRC checksum in bytes (2 bytes for CRC16).
	 */
	private static final int    CRC_LEN_BYTES = 2;
	/**
	 * Lookup table for CRC16 calculation, facilitating faster computation.
	 */
	private static final char[] CRC_TABLE     = { 0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935 };
	
	/**
	 * Calculates the CRC16 checksum incrementally.
	 * <p>
	 * This implementation is based on the Redis CRC16 algorithm.
	 * See: <a href="https://github.com/redis/redis/blob/95b1979c321eb6353f75df892ab8be68cf8f9a77/src/crc16.c">Redis CRC16 Source</a>
	 * Example: "123456789" -> 31C3 (decimal 12739).
	 *
	 * @param src The input byte (0-255) for CRC calculation.
	 * @param crc The current CRC value to be updated.
	 * @return The updated CRC16 checksum.
	 */
	private static char crc16( int src, char crc ) {
		src &= 0xFF; // Ensure src is treated as a byte (0-255)
		crc = ( char ) ( CRC_TABLE[ ( crc >> 12 ^ src >> 4 ) & 0x0F ] ^ crc << 4 );
		return ( char ) ( CRC_TABLE[ ( crc >> 12 ^ src & 0x0F ) & 0x0F ] ^ crc << 4 );
	}
//#endregion
//#region Constants for Internal State Management
	
	/**
	 * Constant representing the OK state, indicating successful operation.
	 */
	protected static final int OK         = Integer.MAX_VALUE - 10;
	/**
	 * Constant representing the state for reading a String.
	 */
	protected static final int STR        = OK - 100;
	/**
	 * Constant representing the state for retry operation.
	 */
	protected static final int RETRY      = STR + 1;
	/**
	 * Constant representing the state for reading/writing a 4-byte value.
	 */
	protected static final int VAL4       = RETRY + 1;
	/**
	 * Constant representing the state for reading an 8-byte value.
	 */
	protected static final int VAL8       = VAL4 + 1;
	/**
	 * Constant representing the state for reading a 1-byte integer.
	 */
	protected static final int INT1       = VAL8 + 1;
	/**
	 * Constant representing the state for reading a 2-byte integer.
	 */
	protected static final int INT2       = INT1 + 1;
	/**
	 * Constant representing the state for reading a 4-byte integer.
	 */
	protected static final int INT4       = INT2 + 1;
	/**
	 * Constant representing the state for reading a length encoded with 0 bytes.
	 */
	protected static final int LEN0       = INT4 + 1;
	/**
	 * Constant representing the state for reading a length encoded with 1 byte.
	 */
	protected static final int LEN1       = LEN0 + 1;
	/**
	 * Constant representing the state for reading a length encoded with 2 bytes.
	 */
	protected static final int LEN2       = LEN1 + 1;
	/**
	 * Constant representing the state for reading bits.
	 */
	protected static final int BITS       = LEN2 + 1;
	/**
	 * Constant representing the state for reading bits followed by bytes.
	 */
	protected static final int BITS_BYTES = BITS + 1;
	/**
	 * Constant representing the state for reading a variable-length integer (VarInt).
	 */
	protected static final int VARINT     = BITS_BYTES + 1;
//#endregion
	
	/**
	 * Current bit position for bit-level operations.
	 */
	protected int    bit;
	/**
	 * String buffer, typically used for assembling received strings or holding strings for transmission.
	 */
	public    String str;
	
	/**
	 * Temporary buffer for bit accumulation during bit-level read/write operations.
	 */
	protected int        bits;
	/**
	 * ByteBuffer used for data processing.
	 */
	protected ByteBuffer buffer;
	/**
	 * Current operational mode of the AdHoc instance, often used for state management in data processing.
	 */
	protected int        mode;
	
	/**
	 * Provides a formatted string representation of the ByteBuffer's current state for debugging.
	 * Includes position, limit, capacity, and a hex dump of the buffer content, highlighting the current position.
	 *
	 * @return A string describing the ByteBuffer's state and content.
	 */
	public String print_data() {
		final StringBuilder sb = new StringBuilder();
		sb.append( "Position: " ).append( buffer.position() ).append( ", Limit: " ).append( buffer.limit() ).append( ", Capacity: " ).append( buffer.capacity() ).append( '\n' );
		
		sb.append( String.format( "%08d: ", 0 ) );
		for( int i = 0; i < buffer.limit(); i++ ) {
			byte b = buffer.get( i );
			sb.append( String.format( i == buffer.position() ?
					                          "%02X*" :
					                          // Mark current position with asterisk
					                          "%02X ", b ) );
			
			if( ( ( i + 1 ) & 0xF ) == 0 || i == buffer.limit() - 1 ) sb.append( '\n' ).append( String.format( "%08d: ", i ) ); // New line every 16 bytes
			else if( ( ( i + 1 ) & 0x7 ) == 0 ) sb.append( " " ); // Extra space every 8 bytes for readability
		}
		
		return sb.toString();
	}
	
	/**
	 * Temporary 4-byte integer value buffer.
	 */
	protected int  u4;
	/**
	 * Temporary 8-byte unsigned integer value buffer.
	 */
	public    long u8;
	/**
	 * Secondary temporary 8-byte unsigned integer value buffer, often used for intermediate calculations.
	 */
	public    long u8_;
	/**
	 * Number of bytes remaining to be processed in a multi-byte operation.
	 */
	protected int  bytes_left;
	/**
	 * Maximum number of bytes expected in a multi-byte operation.
	 */
	protected int  bytes_max;
	
	/**
	 * Interface for byte sources, extending ReadableByteChannel.
	 * Implementors provide a method to subscribe for notifications when new bytes are available for transmission.
	 */
	public interface BytesSrc extends ReadableByteChannel {
		/**
		 * Subscribes a consumer to be notified when new bytes are available for transmission.
		 *
		 * @param subscriber The consumer to be notified. Accepts the BytesSrc instance as argument.
		 * @return The previously set subscriber, or null if none was set.
		 */
		Consumer< BytesSrc > subscribe_on_new_bytes_to_transmit_arrive( Consumer< BytesSrc > subscriber );
	}
	
	/**
	 * Interface for byte destinations, extending WritableByteChannel.
	 * Implementors are responsible for writing bytes.
	 * <p>
	 * ATTENTION! Implementations should be aware that the data in the provided buffer "src" may change due to buffer reuse.
	 */
	public interface BytesDst extends WritableByteChannel { }
	
	public interface Channel {
		
		/**
		 * Represents a single, stateful step or phase in a data processing pipeline for a communication channel.
		 * <p>
		 * Each stage can inspect, modify, or react to data as it is transmitted or received. Implementations
		 * define the logic for various events in the channel's lifecycle, such as activation, transmission,
		 * reception, and timeouts.
		 *
		 * @param <CTX> The type of the context object, holding stateful data for the pipeline instance.
		 * @param <SND> The type of the packet headers used on sending.
		 * @param <RCV> The type of the packet headers used on receiving.
		 */
		interface Stage< CTX, SND, RCV > {
			
			/**
			 * A lifecycle callback invoked when the stage becomes active in the pipeline.
			 * This is the ideal place for initialization, resource allocation, or setting up initial state.
			 *
			 * @param context        The context object for this pipeline instance.
			 * @param prevStage      The preceding stage in the pipeline, or {@code null} if this is the first stage.
			 * @param sendHeaders    The packet headers that initiated this activation, if driven by a transmission. Can be null.
			 * @param sendPack       The outgoing packet. Can be null if the pipeline is not initiated by a transmission.
			 * @param receiveHeaders The packet headers that initiated this activation, if driven by a receivePack. Can be null.
			 * @param receivePack    The incoming packet. Can be null if the pipeline does not handle reception.
			 */
			void OnActivate( CTX context, Stage< CTX, SND, RCV > prevStage, SND sendHeaders, Channel.Transmitter.BytesSrc sendPack, RCV receiveHeaders, Channel.Receiver.BytesDst receivePack );
			
			
			/**
			 * Handles a failure event within the pipeline. This is called when an error, timeout,
			 * or connection drop occurs, allowing the stage to perform cleanup.
			 *
			 * @param context        The shared context object for this pipeline instance.
			 * @param reason         The type of failure that occurred.
			 * @param description    A human-readable description of the failure, if any.
			 * @param sendHeaders    The headers of the packet being sent at the time of failure, if any.
			 * @param sendPack       The packet being sent at the time of failure, if any.
			 * @param receiveHeaders The headers of the packet being received at the time of failure, if any.
			 * @param receivePack    The packet being received at the time of failure, if any.
			 */
			void OnFailure( CTX context, FailureReason reason, @Nullable String description, @Nullable SND sendHeaders, Channel.Transmitter.@Nullable BytesSrc sendPack, @Nullable RCV receiveHeaders, Channel.Receiver.@Nullable BytesDst receivePack );
			
			/**
			 * Enumerates the reasons for a pipeline failure or connection termination.
			 */
			enum FailureReason {
				/**
				 * The connection was terminated by the local application or pipeline logic.
				 * This is typically an intentional or controlled shutdown.
				 */
				LOCAL_DISCONNECT,
				
				/**
				 * The connection was terminated by the remote peer.
				 */
				REMOTE_DISCONNECT,
				
				/**
				 * An operation did not complete within its expected time frame.
				 */
				TIMEOUT,
				
				/**
				 * The data received from the remote peer violates the expected communication protocol.
				 * Examples include a malformed packet or an unexpected message type.
				 */
				PROTOCOL_ERROR,
				
				/**
				 * An unexpected or unhandled error occurred within the pipeline's logic,
				 * such as a critical exception or serialization failure.
				 */
				INTERNAL_ERROR
			}
			
			/**
			 * A pre-serialization hook invoked immediately before a packet object is converted into its byte representation.
			 * <p>
			 * This method can be used for last-minute modifications to the packet or its headers,
			 * performing validation, or for logging purposes before the serialization process begins.
			 *
			 * @param context The pipeline context.
			 * @param headers The headers associated with the packet about to be serialized.
			 * @param pack    The  packet  that will be serialized.
			 * @return An error message {@code String} to abort the serialization (and subsequent transmission),
			 * or {@code null} to allow it to proceed.
			 */
			String OnSerializing( CTX context, SND headers, Channel.Transmitter.BytesSrc pack );
			
			/**
			 * A post-serialization callback invoked after a packet object has been fully serialized into the send buffer.
			 * <p>
			 * This event indicates that the entire packet has been processed and its byte representation is now
			 * in the buffer. Due to the streaming nature of the dataflow, some or all of the packet's bytes
			 * may have already been written to the network socket by the time this callback is fired.
			 * <p>
			 * This is useful for updating application state (e.g., marking the packet as processed),
			 * logging, or releasing resources held by the original packet object.
			 *
			 * @param context The pipeline context.
			 * @param headers The headers of the packet that was just serialized.
			 * @param pack    The original packet that has now been fully serialized.
			 */
			void OnSerialized( CTX context, SND headers, Channel.Transmitter. BytesSrc pack );
			
			/**
			 * Processes an incoming packet header before its body is received.
			 * This allows the stage to inspect the header and decide whether to accept or reject the packet.
			 *
			 * @param context The pipeline context.
			 * @param headers The headers of the incoming packet.
			 * @param pack    The incoming packet, which is initially empty.
			 * @return An error message {@code String} to reject the packet, or {@code null} to accept it and proceed with receiving the body.
			 */
			String OnReceiving( CTX context, RCV headers, Channel.Receiver.BytesDst pack );
			
			/**
			 * Handles a fully received packet, including its header and body.
			 * This is the final step in the reception process where the complete data is available for processing.
			 *
			 * @param context The pipeline context.
			 * @param headers The headers of the fully received packet.
			 * @param pack    The received packet.
			 */
			void OnReceived( CTX context, RCV headers, Channel.Receiver.BytesDst pack );
			
			/**
			 * Provides a human-readable name for the stage, primarily for logging and debugging purposes.
			 *
			 * @return The name of the stage, defaulting to the simple class name.
			 */
			default String name() {
				return getClass().getSimpleName();
			}
		}
		
		/**
		 * Defines a contract for an external communication channel that adapts a low-level I/O resource
		 * (e.g., a network socket, serial port) to the application's internal byte stream processing system.
		 * <p>
		 * This interface acts as a bridge, facilitating bidirectional data flow between an external endpoint
		 * and the application's data producer ({@link BytesSrc}) and consumer ({@link BytesDst}).
		 * Implementations of this interface are responsible for managing the underlying resource's lifecycle,
		 * handling I/O operations, and managing timeouts.
		 *
		 * <h3>Lifecycle and Usage:</h3>
		 * An {@code External} channel instance is typically configured and used in the following sequence:
		 * <ol>
		 *     <li><b>Instantiation:</b> Create an instance of a specific implementation (e.g., {@code TcpChannel}).</li>
		 *     <li><b>Configuration:</b> Set timeouts using {@link #ReceiveTimeout(long)} and {@link #TransmitTimeout(long)}.</li>
		 *     <li><b>Connection:</b> The channel connects to the external resource. This step is implementation-specific.</li>
		 *     <li><b>Operation:</b> The channel actively transfers data between the external resource and the
		 *         internal {@link BytesSrc} and {@link BytesDst}.</li>
		 *     <li><b>Shutdown:</b> The channel is closed using one of the termination methods:
		 *         <ul>
		 *             <li>{@link #close()}: For a graceful shutdown.</li>
		 *             <li>{@link #abort()}: For an immediate, forceful shutdown.</li>
		 *             <li>{@link #closeAndDispose()}: For a final shutdown and resource cleanup.</li>
		 *         </ul>
		 *     </li>
		 * </ol>
		 */
		interface External {
			/**
			 * Gets the current timeout for receive operations, in milliseconds.
			 * <p>
			 * The returned value has special meaning based on its sign:
			 * <ul>
			 *     <li><b>Positive value:</b> The standard timeout in milliseconds.</li>
			 *     <li><b>Zero (0):</b> Wait indefinitely for data.</li>
			 *     <li><b>Negative value:</b> A graceful close is in progress. The absolute value
			 *         represents the remaining timeout for the close operation.</li>
			 * </ul>
			 *
			 * @return The receive timeout in milliseconds. A negative value indicates a graceful close is active.
			 */
			long ReceiveTimeout();
			
			/**
			 * Sets the timeout for receive operations, in milliseconds.
			 * <p>
			 * This method is dual-purpose:
			 * <ul>
			 *     <li>To set a standard timeout, provide a positive value or {@code 0} to wait indefinitely.</li>
			 *     <li>To initiate a <b>graceful close</b> on the receive side, provide a negative value. The channel
			 *         will stop accepting new data and wait for a specified duration (the absolute value of the
			 *         timeout) before closing the receive stream.</li>
			 * </ul>
			 *
			 * @param receiveTimeout The timeout duration in milliseconds. Use a negative value to trigger a graceful close.
			 */
			void ReceiveTimeout( long receiveTimeout );
			
			
			/**
			 * Gets the current timeout for transmit operations, in milliseconds.
			 * <p>
			 * The returned value has special meaning based on its sign:
			 * <ul>
			 *     <li><b>Positive value:</b> The standard timeout in milliseconds.</li>
			 *     <li><b>{@link Long#MAX_VALUE}:</b> No timeout is set.</li>
			 *     <li><b>Negative value:</b> A graceful close has been scheduled to occur after the current
			 *         transmission buffer is fully sent. The absolute value represents the timeout for that close operation.</li>
			 * </ul>
			 *
			 * @return The transmit timeout in milliseconds. A negative value indicates a graceful close is scheduled.
			 */
			long TransmitTimeout();
			
			/**
			 * Sets the timeout for transmit operations, in milliseconds.
			 * <p>
			 * This method is dual-purpose:
			 * <ul>
			 *     <li>To set a standard timeout, provide a positive value. Use {@link Long#MAX_VALUE} for no timeout.</li>
			 *     <li>To schedule a <b>graceful close</b> on the transmit side, provide a negative value. The channel
			 *         will finish sending all data currently in its buffer and then initiate a close sequence
			 *         using the absolute value as the timeout.</li>
			 * </ul>
			 *
			 * @param transmitTimeout The timeout duration in milliseconds. Use a negative value to schedule a post-transmit graceful close.
			 */
			void TransmitTimeout( long transmitTimeout );
			
			
			/**
			 * Immediately and permanently closes the communication channel and releases all associated system resources
			 * (e.g., sockets, file handles).
			 * <p>
			 * After this method is called, the object is considered disposed and cannot be reused. Any attempts to
			 * use it will result in an error or undefined behavior. This is the definitive cleanup method and
			 * should be called in a {@code finally} block to prevent resource leaks.
			 *
			 * @see #close()
			 * @see #abort()
			 */
			void closeAndDispose();
			
			/**
			 * Initiates a graceful shutdown of the communication channel.
			 * <p>
			 * This method attempts to complete pending operations, such as flushing send buffers, before closing
			 * the connection. It is the standard, non-abrupt way to terminate communication. Depending on the
			 * implementation, an object might be reconfigurable and reusable after being closed this way.
			 *
			 * @see #abort()
			 * @see #closeAndDispose()
			 */
			void close();
			
			/**
			 * Immediately terminates the connection, cancelling any pending I/O operations.
			 * <p>
			 * This is a hard stop, equivalent to "pulling the plug." It does not guarantee that all buffered data
			 * will be sent. Use this for force-closing a connection in exceptional circumstances, such as an
			 * unrecoverable error or a required immediate shutdown.
			 *
			 * @see #close()
			 */
			void abort();
			
			Internal Internal();
			void Internal(Internal internal);
		}
		
		/**
		 * Defines the contract for the internal-facing side of the communication channel.
		 * <p>
		 * This interface is implemented by the application's logic to provide the necessary data sinks and sources
		 * to the {@link External} channel, and to receive lifecycle event notifications from it. It essentially
		 * wires the external I/O adapter into the application's core data processing system.
		 */
		interface Internal {
			/**
			 * Provides the destination (sink) for data received from the external source.
			 * <p>
			 * The {@link External} channel will write all incoming bytes to this {@link BytesDst}.
			 * This must be set to a valid, non-null instance before communication begins.
			 *
			 * @return The byte stream consumer that will process incoming data. Must not be null.
			 */
			BytesDst BytesDst();
			
			/**
			 * Provides the source of data to be transmitted to the external destination.
			 * <p>
			 * The {@link External} channel will read bytes from this {@link BytesSrc} to send them.
			 * If this returns {@code null}, the channel is effectively configured as read-only.
			 *
			 * @return The byte stream producer that provides outgoing data. Can be {@code null} for a read-only channel.
			 */
			BytesSrc BytesSrc();
			
			/**
			 * A callback method invoked by the {@link External} channel to notify the application of significant lifecycle events.
			 * <p>
			 * This allows the internal system to react to state changes like connections, disconnections, or errors.
			 *
			 * @param src   The {@link External} channel instance that originated the event. This is useful when a single
			 *              {@code Internal} instance manages multiple channels.
			 * @param event The integer code representing the event. See the constants defined in
			 *              {@code Network.TCP.ExternalChannel.Event} for possible values.
			 */
			void OnExternalEvent( External src, @Network.TCP.ExternalChannel.Event int event );
		}
		
		/**
		 * Abstract base class for Receivers in the AdHoc protocol.
		 * Extends Context.Receiver and implements BytesDst, providing functionality for receiving and decoding data.
		 */
		abstract class Receiver extends Base.Receiver implements BytesDst {
			
			/**
			 * Handler for events during the receiving process. Volatile for thread-safe access.
			 */
			public volatile      EventsHandler                                          handler;
			/**
			 * Atomic updater for the 'handler' field, ensuring thread-safe updates.
			 */
			private static final AtomicReferenceFieldUpdater< Receiver, EventsHandler > exchange = AtomicReferenceFieldUpdater.newUpdater( Receiver.class, EventsHandler.class, "handler" );
			
			/**
			 * Atomically exchanges the current event handler with a new one.
			 *
			 * @param dst The new event handler to set.
			 * @return The previous event handler.
			 */
			public EventsHandler exchange( EventsHandler dst ) { return exchange.getAndSet( this, dst ); }
			
			/**
			 * Number of bytes used for packet ID.
			 */
			private final int id_bytes;
			
			/**
			 * Constructor for Receiver.
			 *
			 * @param handler  The event handler to use for receiving events.
			 * @param id_bytes Number of bytes used for packet identification.
			 */
			public Receiver( EventsHandler handler, int id_bytes ) {
				this.handler    = handler;
				this.bytes_left = this.bytes_max = this.id_bytes = id_bytes;
			}
			
			/**
			 * Default error handler for Receiver operations. Can be overridden to customize error handling.
			 */
			public static OnError.Handler error_handler = OnError.Handler.DEFAULT;
			
			/**
			 * Annotation and interface for defining error handling callbacks in Receivers.
			 */
			public @interface OnError {
				/** Error code: A sequence of 0xFF bytes was detected, possibly indicating a framing error or unexpected frame marker. */
				int FFFF_ERROR       = 0;
				/** Error code: CRC checksum mismatch, suggesting data corruption. */
				int CRC_ERROR        = 1;
				/** Error code: General byte distortion or framing issues, such as unexpected byte sequences. */
				int BYTES_DISTORTION = 3;
				/** Error code: A buffer overflow condition, e.g., received length exceeds maximum allowed. */
				int OVERFLOW         = 4;
				/** Error code: An invalid packet ID was received, meaning the packet type is unrecognized. */
				int INVALID_ID       = 5;
				/** Error code: An receiving packet is rejected by dataflow. */
				int REJECTED         = 6;
				/** Error code indicating a timeout during packet transmission or reception. */
				int TIMEOUT          = 7;
				/** Generic error code for unspecified or unexpected errors during packet processing. */
				int ERROR            = 8;
				
				/**
				 * Interface for handling errors encountered within the Receiver.
				 */
				interface Handler {
					/** Default error handler implementation that prints error messages to System.out. */
					Handler DEFAULT = new Handler() { };
					
					/**
					 * Handles errors that occur during data processing in a {@link AdHoc.BytesDst} (often a Framing decoder or the Receiver itself).
					 *
					 * @param dst   The {@link AdHoc.BytesDst} receiver, where the error occurred.
					 * @param error The error code, indicating the type of error (see constants from {@link OnError}).
					 * @param ex    Optional exception associated with the error, providing more details.
					 */
					default void error( AdHoc.BytesDst dst, int error, Throwable ex ) {
						// Default implementation prints to console. Override for custom logging/handling.
						String errorTypeStr = "Error dst: " + error;
						switch( error ) {
							case FFFF_ERROR:
								errorTypeStr = "FFFF_ERROR dst:"; break;
							case CRC_ERROR:
								errorTypeStr = "CRC_ERROR dst:"; break;
							case BYTES_DISTORTION:
								errorTypeStr = "BYTES_DISTORTION dst:"; break;
							case OVERFLOW:
								errorTypeStr = "OVERFLOW dst:"; break;
							case INVALID_ID:
								errorTypeStr = "INVALID_ID dst:"; break;
							case REJECTED:
								errorTypeStr = "REJECTED dst:"; break;
						}
						
						System.out.println( errorTypeStr + "\n" + dst + " at:\n" + ( ex == null ?
								"" :
								StackTracePrinter.ONE.stackTrace( ex ) ) );
					}
				}
			}
			
			/**
			 * Interface for handling events during the receiving process.
			 * Implementors can define callbacks for packet reception stages.
			 */
			public interface EventsHandler {
				
				/**
				 * Callback triggered when enough bytes are received to identify the packet type (ID is read).
				 * Called before the full packet payload is received, allowing for initial processing or setup.
				 *
				 * @param src The Receiver instance that triggered the event.
				 * @param dst The {@link Receiver.BytesDst} (specific packet handler) that will process the payload.
				 */
				default void OnReceiving( Receiver src, BytesDst dst ) {
				}
				
				/**
				 * Callback triggered when a complete packet (including payload) is received and ready for processing.
				 * Indicates that all bytes of a packet have been successfully received and, if applicable, CRC checked.
				 *
				 * @param src  The Receiver instance that triggered the event.
				 * @param pack The {@link Receiver.BytesDst} (specific packet handler) representing the received packet data.
				 */
				default void OnReceived( Receiver src, BytesDst pack ) {
				}
			}
			
			
			/**
			 * Interface for a destination of received bytes, specific to a packet type within the Receiver.
			 * Implementors define how to process incoming byte streams for a particular packet.
			 */
			public interface BytesDst {
				/**
				 * Processes incoming bytes for this packet handler.
				 * Implementors should handle byte-by-byte deserialization logic here, using the Receiver's state and getter methods.
				 *
				 * @param src The Receiver instance providing the bytes and context.
				 * @return True if more bytes are expected for the current operation/packet, false if the operation/packet is complete.
				 */
				boolean __put_bytes( Receiver src );
				
				/**
				 * Returns the ID associated with this packet handler.
				 * This ID typically matches the packet ID used for dispatching.
				 *
				 * @return An integer ID representing the type or identifier of this packet handler.
				 */
				int __id();
			}
			
			/**
			 * A framing decoder for byte-oriented protocols that use special character escaping and CRC.
			 * This class handles frame synchronization, decodes escaped characters, and verifies CRC checksums.
			 * It acts as a {@link AdHoc.BytesDst} to receive raw framed data and passes decoded payload to an upper layer {@link Receiver}.
			 * <p>Expected frame format: 0xFF (start marker) + encoded payload + 2-byte CRC.
			 * <p>The encoding/decoding mechanism is a bit-oriented transformation designed to handle `0x7F` and `0xFF`
			 * within the payload, ensuring they don't conflict with the frame marker (`0xFF`).
			 * - Original `0x7F` is transformed into `0x7F` followed by a byte `N` where `N`'s LSB is 0.
			 * - Original `0xFF` is transformed into `0x7F` followed by a byte `N` where `N`'s LSB is 1.
			 * An unescaped `0xFF` in the stream is treated as a frame marker.
			 */
			public static class Framing implements AdHoc.BytesDst, EventsHandler {
				/** Upper layer Receiver to which decoded packet payloads are passed. */
				public               Receiver                                              upper_layer;
				/** Event handler for Framing events (delegated from/to upper_layer). */
				public volatile      EventsHandler                                         handler;
				/** Atomic updater for the 'handler' field. */
				private static final AtomicReferenceFieldUpdater< Framing, EventsHandler > exchange = AtomicReferenceFieldUpdater.newUpdater( Framing.class, EventsHandler.class, "handler" );
				
				/**
				 * Atomically exchanges the current event handler with a new one.
				 *
				 * @param dst The new event handler.
				 * @return The previous event handler.
				 */
				public EventsHandler exchange( EventsHandler dst ) {
					return exchange.getAndSet( this, dst );
				}
				
				/**
				 * Constructor for Framing.
				 *
				 * @param upper_layer The Receiver to pass decoded data to.
				 */
				public Framing( Receiver upper_layer ) {
					switch_to( upper_layer );
				}
				
				/**
				 * Switches the framing decoder to a new upper layer Receiver.
				 * Resets the decoder state and manages event handler hooks.
				 *
				 * @param upper_layer The new Receiver to switch to.
				 */
				public void switch_to( Receiver upper_layer ) {
					reset();
					
					if( this.upper_layer != null ) {
						this.upper_layer.reset();
						upper_layer.exchange( handler ); // Unhook previous handler from old upper_layer.
					}
					
					handler = ( this.upper_layer = upper_layer ).exchange( this ); //hook new handler
				}
				
				/**
				 * Resets the framing decoder state due to an error.
				 * Notifies the error handler and resets internal state variables.
				 *
				 * @param error The error code (see {@link OnError}).
				 */
				private void error_reset( @OnError int error ) {
					error_handler.error( this, error, null );
					reset();
				}
				
				/** Closes the framing decoder and its upper layer. */
				@Override
				public void close() {
					reset();
					upper_layer.close();
				}
				
				/**
				 * Resets internal state variables and clears buffers.
				 * Called on initialization, error conditions, and when switching receivers.
				 */
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
					
					if( !ffDetected ) // A packet is received, but next packet start FF mark does not detected yet, so switch to SEEK_FF mode
						state = State.SEEK_FF;
				}
				
				/**
				 * Writes encoded bytes to the destination buffer.
				 * Handles special character sequences, maintains frame synchronization, and performs CRC checks.
				 *
				 * @param src Source buffer containing encoded data.
				 *            ATTENTION! The data in the provided buffer "src" may change due to buffer reuse.
				 * @return Number of bytes processed from the source buffer.
				 * @throws IOException If an I/O error occurs during writing.
				 */
				@Override
				public int write( ByteBuffer src ) throws IOException {
					if( src == null ) {
						reset();
						return -1; // Indicate end of stream
					}
					final int remaining = src.remaining();
					if( remaining < 1 ) return 0; // No bytes to process
					final int limit = src.limit();
					dst_byte = 0; // Initialize destination byte counter

init_loop:
					// Label for breaking out of the initialization loop
					switch( state ) {
						case State.SEEK_FF: // State: Seeking frame start marker (0xFF) after potential byte distortion
							while( src.hasRemaining() ) if( src.get() == ( byte ) 0xFF ) {
								state = State.NORMAL; // Transition to normal processing state
								if( ffDetected ) error_handler.error( this, OnError.FFFF_ERROR, null ); // Consecutive FF error
								ffDetected = true; // Mark FF as detected
								if( src.hasRemaining() )
									break init_loop; // Break to continue processing remaining bytes
								
								return remaining; // Processed all input, return remaining count
							}
							else ffDetected = false; // Reset FF detection flag
							return remaining; // Processed all input, return remaining count
						
						case State.Ox7F: // State: Processing escape sequence starting with 0x7F
							
							if( ffDetected = ( raw = src.get() & 0xFF ) == 0xFF ) { // Check for invalid 0xFF after 0x7F
								error_reset( OnError.BYTES_DISTORTION ); // Handle byte distortion error
								break init_loop; // Break to reset state
							}
							
							bits |= ( ( raw & 1 ) << 7 | 0x7F ) << shift; // Decode escaped byte
							put( src, 0 ); // Write decoded byte to destination buffer
							
							write( src, 1, State.NORMAL ); // Process remaining bytes in normal state
							src.position( 1 ).limit( limit ); // Adjust source buffer position and limit
						case State.Ox7F_: // State: Processing consecutive 0x7F escape sequences
							
							while( raw == 0x7F ) {
								if( !src.hasRemaining() ) {
									write( src, dst_byte, State.Ox7F_ ); // Save state and return if no more bytes
									return remaining; // Return remaining byte count
								}
								
								if( ffDetected = ( raw = src.get() & 0xFF ) == 0xFF ) { // Check for invalid 0xFF after 0x7F
									error_reset( OnError.BYTES_DISTORTION ); // Handle byte distortion error
									break init_loop; // Break to reset state
								}
								
								bits |= ( raw << 6 | 0x3F ) << shift; // Decode escaped byte
								if( ( shift += 7 ) < 8 ) continue; // Continue processing if shift is less than 8 bits
								shift -= 8; // Adjust shift after processing 8 bits
								
								put( src, dst_byte++ ); // Write decoded byte to destination buffer
							}
							
							bits |= raw >> 1 << shift; // Decode remaining bits after escape sequence
							if( ( shift += 7 ) < 8 ) break; // Break if shift is less than 8 bits
							
							shift -= 8; // Adjust shift after processing 8 bits
							
							if( src.position() == dst_byte ) {
								write( src, dst_byte, State.NORMAL ); // Write decoded bytes in normal state
								src.position( dst_byte ).limit( limit ); // Adjust source buffer position and limit
								dst_byte = 0; // Reset destination byte counter
							}
							put( src, dst_byte++ ); // Write decoded byte to destination buffer
							
							state = State.NORMAL; // Transition to normal processing state
					}
					
					while( src.hasRemaining() ) {
						if( ( raw = src.get() & 0xFF ) == 0x7F ) { // Escape character 0x7F detected
							ffDetected = false; // Reset FF detection flag
							if( !src.hasRemaining() ) {
								write( src, dst_byte, State.Ox7F ); // Save state and return if no more bytes
								return remaining; // Return remaining byte count
							}
							
							if( ffDetected = ( raw = src.get() & 0xFF ) == 0xFF ) { // Check for invalid 0xFF after 0x7F
								error_reset( OnError.BYTES_DISTORTION ); // Handle byte distortion error
								continue; // Continue to next byte after error reset
							}
							
							bits |= ( ( raw & 1 ) << 7 | 0x7F ) << shift; // Decode escaped byte
							
							put( src, dst_byte++ ); // Write decoded byte to destination buffer
							
							while( raw == 0x7F ) {
								if( !src.hasRemaining() ) {
									write( src, dst_byte, State.Ox7F_ ); // Save state and return if no more bytes
									return remaining; // Return remaining byte count
								}
								
								if( ffDetected = ( raw = src.get() & 0xFF ) == 0xFF ) { // Check for invalid 0xFF after 0x7F
									error_reset( OnError.BYTES_DISTORTION ); // Handle byte distortion error
									continue; // Continue to next byte after error reset
								}
								
								bits |= ( ( raw & 1 ) << 6 | 0x3F ) << shift; // Decode escaped byte
								if( ( shift += 7 ) < 8 ) continue; // Continue processing if shift is less than 8 bits
								
								shift -= 8; // Adjust shift after processing 8 bits
								
								put( src, dst_byte++ ); // Write decoded byte to destination buffer
							}
							
							bits |= raw >> 1 << shift; // Decode remaining bits after escape sequence
							if( ( shift += 7 ) < 8 ) continue; // Continue processing if shift is less than 8 bits
							
							shift -= 8; // Adjust shift after processing 8 bits
						}
						else if( raw == 0xFF ) { // Frame start marker 0xFF detected
							if( ffDetected ) {
								error_handler.error( this, OnError.FFFF_ERROR, null ); // Consecutive FF error
								continue; // Continue to next byte after error handling
							}
							
							ffDetected = true; // Mark FF as detected
							if( state == State.SEEK_FF ) { // Check if in SEEK_FF state after reset
								reset(); // Reset decoder state
								state = State.NORMAL; // Transition to normal processing state
							}
							else {
								final int fix = src.position(); // Store current position for potential rollback
								
								write( src, dst_byte, State.NORMAL ); // Write decoded bytes in normal state
								src.limit( limit ).position( fix ); // Rollback source buffer position and limit
							}
							
							continue; // Continue to next byte
						}
						else bits |= raw << shift; // Normal byte processing: accumulate bits
						
						ffDetected = false; // Reset FF detection flag
						put( src, dst_byte++ ); // Write decoded byte to destination buffer
					}
					write( src, dst_byte, State.NORMAL ); // Write any remaining decoded bytes
					
					return remaining; // Return processed byte count
				}
				
				/**
				 * Processes a single fully decoded byte: updates CRC history and places the byte into the
				 * provided {@code dst} buffer (which is typically the input {@code src} buffer, used as temporary storage).
				 *
				 * @param dst       ByteBuffer (acting as scratch space) to place the decoded byte.
				 * @param dst_index Index in {@code dst} to place the byte.
				 */
				private void put( ByteBuffer dst, int dst_index ) {
					
					crc3 = crc2; // Shift CRC history: crc3 = crc2
					crc2 = crc1; // Shift CRC history: crc2 = crc1
					crc1 = crc0; // Shift CRC history: crc1 = crc0
					
					crc0 = crc16( bits, crc1 ); // Calculate new CRC value
					dst.put( dst_index, ( byte ) bits ); // Write the decoded byte to the destination buffer
					
					bits >>= 8; // Shift bits to prepare for next byte
				}
				
				/** Forwards the 'on_receiving' event to this Framing's handler (usually the application's handler). */
				@Override
				public void OnReceiving( Receiver src, BytesDst dst ) {
					if( handler != null ) handler.OnReceiving( src, dst );
				}
				
				/**
				 * Handles the 'on_received' event from the {@link #upper_layer} Receiver, meaning upper_layer
				 * finished parsing a payload. Now, this Framing instance expects CRC bytes.
				 *
				 * @param src  The {@link #upper_layer} Receiver.
				 * @param pack The {@link Receiver.BytesDst} (packet handler) for the received packet.
				 */
				@Override
				public void OnReceived( Receiver src, BytesDst pack ) {
					pack_crc                     = 0; // Initialize packet CRC
					pack_crc_byte                = CRC_LEN_BYTES - 1; // Initialize CRC byte counter
					waiting_for_dispatching_pack = pack; // Store the received packet
					dispatch_on_0                = false; // Reset dispatch flag
					
					while( src.buffer.hasRemaining() && waiting_for_dispatching_pack != null ) getting_crc( src.buffer.get() & 0xFF ); // Process CRC bytes from buffer
				}
				
				/**
				 * Writes decoded bytes (from {@code src} buffer's decoded section) to the {@link #upper_layer}.
				 * Also handles receiving CRC bytes if {@link #waiting_for_dispatching_pack} is set.
				 *
				 * @param src         ByteBuffer containing decoded bytes at the beginning. Position/limit define this section.
				 * @param limit       Number of decoded bytes in {@code src}.
				 * @param state_if_ok State to transition to if write is successful and no CRC pending.
				 * @throws IOException If an I/O error occurs during write to upper layer.
				 */
				private void write( ByteBuffer src, int limit, int state_if_ok ) throws IOException {
					state = state_if_ok; // Update decoder state
					if( limit == 0 ) return; // No decoded bytes to write
					
					src.position( 0 ).limit( limit ); // Position buffer to decoded bytes section
					
					while( waiting_for_dispatching_pack != null ) {
						getting_crc( src.get() & 0xFF ); // Process CRC bytes
						if( !src.hasRemaining() ) return; // Return if no more bytes in buffer
					}
					
					upper_layer.write( src ); // Write decoded bytes to upper layer
					if( upper_layer.mode == OK || !ffDetected )
						return; // Not enough bytes to complete packet or next frame detected, exit
					error_reset( OnError.BYTES_DISTORTION ); // Handle byte distortion error
				}
				
				/**
				 * Stores the packet waiting for dispatching after CRC verification.
				 */
				private BytesDst waiting_for_dispatching_pack;
				/**
				 * Flag indicating if packet dispatch should occur on receiving a zero byte.
				 * Used for secondary CRC check mode.
				 */
				private boolean  dispatch_on_0;
				
				/**
				 * Processes incoming CRC bytes, verifies CRC checksum, and dispatches packet if CRC is valid.
				 * Supports primary and secondary CRC check modes for error resilience.
				 *
				 * @param crc_byte Next byte of the CRC value being received.
				 */
				private void getting_crc( int crc_byte ) {
					
					if( dispatch_on_0 ) {
						if( crc_byte == 0 ) {
							if( handler != null ) handler.OnReceived( upper_layer, waiting_for_dispatching_pack ); // Dispatch packet on zero byte
						}
						else error_handler.error( this, OnError.CRC_ERROR, null ); // CRC error if byte is not zero
						reset(); // Reset decoder state
						return; // Exit CRC processing
					}
					
					pack_crc |= crc_byte << pack_crc_byte * 8; // Accumulate CRC bytes
					pack_crc_byte--; // Decrement CRC byte counter
					if( -1 < pack_crc_byte ) return; // Need more CRC bytes, exit
					
					if( crc2 == pack_crc ) {
						if( handler != null ) handler.OnReceived( upper_layer, waiting_for_dispatching_pack ); // Dispatch packet if CRC matches crc2
					}
					else if( crc16( pack_crc >> 8, crc3 ) == crc2 ) {
						dispatch_on_0 = true; // Set flag for secondary CRC check mode
						return; // Exit, wait for zero byte dispatch confirmation
					}
					else error_handler.error( this, OnError.CRC_ERROR, null ); // CRC error if no match
					reset(); // Reset decoder state
				}
				
				/** Accumulator for bits during decoding. */
				private int  bits     = 0;
				/** Current bit shift for bit manipulation during decoding. */
				private int  shift    = 0;
				/** CRC value received from the packet being decoded. */
				private char pack_crc = 0;
				/** CRC history: crc0 is current, crc1 is previous, etc. Used for error detection. */
				private char crc0     = 0, crc1 = 0, crc2 = 0, crc3 = 0;
				/** Counter for received CRC bytes (counts down). */
				private int     pack_crc_byte;
				/** Last fetched raw byte from input stream. */
				private int     raw        = 0;
				/** Index for writing decoded bytes to the temporary section of the source ByteBuffer. */
				private int     dst_byte   = 0;
				/** Flag indicating if a frame start marker (0xFF) has been detected and is being processed. */
				private boolean ffDetected = false;
				/** Current state of the framing decoder state machine. */
				private @State
				int state = State.SEEK_FF;
				
				/** Defines states for the framing decoder's state machine. */
				private @interface State {
					/** Normal byte processing state. */
					int NORMAL  = 0;
					/** State after encountering an 0x7F escape character, expecting the next byte. */
					int Ox7F    = 1;
					/** State for handling sequences of 0x7F characters. */
					int Ox7F_   = 2;
					/** State for seeking the 0xFF frame start marker, e.g., after an error or at stream start. */
					int SEEK_FF = 3;
				}
				
				/**
				 * Checks if the upper layer channel is open.
				 *
				 * @return True if the upper layer channel is open, false otherwise.
				 */
				@Override
				public boolean isOpen() {
					return upper_layer.isOpen();
				}
			}
			//#region Slot
			
			/**
			 * Represents a slot in the receiver's processing chain, managing state for (potentially nested)
			 * data structures being deserialized. Extends {@link Base.Receiver.Slot}.
			 */
			public static class Slot extends Base.Receiver.Slot {
				
				/**
				 * Destination BytesDst associated with this slot for receiving bytes.
				 */
				BytesDst dst;
				
				public BytesDst dst( BytesDst dst ) {
					state = 0;
					return this.dst = dst;
				}
				
				/**
				 * Bitmask to track null fields within the current data structure being processed in this slot.
				 */
				public int fields_nulls;
				
				/**
				 * Retrieves the BytesDst associated with the next slot in the chain.
				 *
				 * @param <DST> Type of BytesDst.
				 * @return The BytesDst of the next slot, cast to the specified type.
				 */
				@SuppressWarnings( "unchecked" )
				public < DST extends BytesDst > DST get_bytes() {
					return ( DST ) next.dst;
				}
				
				/**
				 * Reference to the next slot in the processing chain.
				 */
				private       Slot next;
				/**
				 * Reference to the previous slot in the processing chain.
				 */
				private final Slot prev;
				
				/**
				 * Constructor for Slot.
				 *
				 * @param dst  The Receiver associated with this slot.
				 * @param prev The previous slot in the chain, or null if this is the first slot.
				 */
				public Slot( Receiver dst, Slot prev ) {
					super( dst );
					this.prev = prev;
					if( prev != null ) prev.next = this; // Chain this slot to the previous one
				}
			}
			
			/**
			 * Checks if the receiver is currently in an open or active state (i.e., processing data).
			 *
			 * @return True if the receiver slot is not null, indicating it is active, false otherwise.
			 */
			public boolean isOpen() {
				return slot != null;
			}
			
			/**
			 * Current slot in the receiver's processing chain. Manages the current state of data reception.
			 */
			public  Slot                  slot;
			/**
			 * Soft reference to a Slot instance, used for slot recycling and memory management.
			 * Soft references are cleared by the garbage collector when memory is low, allowing for efficient resource usage.
			 */
			private SoftReference< Slot > slot_ref = new SoftReference<>( new Slot( this, null ) );
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
			//#endregion
			
			/**
			 * Retrieves null field flags (a byte) from the buffer and stores them in the current slot's {@code fields_nulls}.
			 * If not enough bytes are available, sets mode to {@link #RETRY} and state to {@code this_case}.
			 *
			 * @param this_case The state to transition to if a retry is needed.
			 * @return True if null flags were successfully read, false otherwise (retry needed).
			 */
			public boolean get_fields_nulls( int this_case ) {
				if( buffer.hasRemaining() ) {
					slot.fields_nulls = buffer.get() & 0xFF; // Read null flags byte
					return true; // Successfully read null flags
				}
				
				slot.state = this_case; // Set next state if not enough bytes
				mode       = RETRY; // Set mode to retry
				return false; // Indicate not enough bytes
			}
			
			/**
			 * Checks if a specific field is null based on the current null field flags.
			 *
			 * @param field        Bitmask representing the field to check for null.
			 * @param if_null_case State to transition to if the field is null.
			 * @return False if the field is not null (bit is set in fields_nulls), true if field is null (bit is not set).
			 */
			public boolean is_null( int field, int if_null_case ) {
				if( ( slot.fields_nulls & field ) != 0 ) return false; // Field is not null
				slot.state = if_null_case; // Set next state if field is null
				return true; // Indicate field is null
			}
			
			/**
			 * Reads a byte representing a null-indicator bit position. If non-zero, sets that bit in {@code u8_} (and {@code u8})
			 * and transitions to {@code if_null_case}. Used for dynamic null indication.
			 *
			 * @param if_null_case State to transition to if a null-indicating byte is found.
			 * @return True if a null-indicating byte was processed, false otherwise (byte was zero).
			 */
			public boolean byte_nulls( int if_null_case ) {
				int null_bit = get_byte(); // Read a byte representing null bit position
				if( null_bit == 0 ) return false; // No null bit detected (byte is zero)
				u8         = u8_ |= 1L << null_bit; // Set the corresponding bit in u8_
				slot.state = if_null_case; // Set next state if null bit is detected
				return true; // Indicate null byte detected
			}
			
			/**
			 * Reads a byte. If non-zero, sets {@code u8_} (and {@code u8}) to {@code null_value}
			 * and transitions to {@code if_null_case}.
			 *
			 * @param null_value   Value to assign to {@code u8_} if null is indicated.
			 * @param if_null_case State to transition to if a null-indicating byte is found.
			 * @return True if a null-indicating byte was processed, false otherwise.
			 */
			public boolean byte_nulls( long null_value, int if_null_case ) {
				int null_bit = get_byte(); // Read a byte representing null bit position
				if( null_bit == 0 ) return false; // No null bit detected (byte is zero)
				
				u8         = u8_ |= null_value; // Set u8_ to the specified null value
				slot.state = if_null_case; // Set next state if null bit is detected
				return true; // Indicate null byte detected
			}
			
			/**
			 * Checks for null using a byte, specific bit, and null value.
			 * Sets u8_ to null_value if null_bit matches bit, otherwise sets a bit at null_bit position.
			 *
			 * @param bit          Specific bit to check against null_bit.
			 * @param null_value   Value to set u8_ to if null_bit matches bit.
			 * @param if_null_case State to transition to if a null byte is detected.
			 * @return True if a null byte was detected, false otherwise.
			 */
			public boolean byte_nulls( int bit, long null_value, int if_null_case ) {
				int null_bit = get_byte(); // Read a byte representing null bit position
				if( null_bit == 0 ) return false; // No null bit detected (byte is zero)
				
				u8         = u8_ |= null_bit == bit ?
						// Check if null_bit matches specific bit
						null_value :
						// Set u8_ to null_value if bit matches
						1L << null_bit; // Otherwise, set bit at null_bit position
				slot.state = if_null_case; // Set next state if null bit is detected
				return true; // Indicate null byte detected
			}
			
			/**
			 * Reads a single bit for null indication. If the bit is 1 (true), it indicates null.
			 * Transitions to {@code if_null_case} if null is indicated.
			 *
			 * @param if_null_case State to transition to if the bit indicates null.
			 * @return True if null is indicated (bit was 1), false otherwise (bit was 0).
			 */
			public boolean bit_null( int if_null_case ) {
				if( get_bits() == 0 ) return false; // Bit is not null (1)
				slot.state = if_null_case; // Set next state if bit is null (0)
				return true; // Indicate bit is null (0)
			}
			
			/** Checks if the receiver is idle (no active slot). */
			public boolean idle() {
				return slot == null;
			}
			
			/**
			 * Checks if not enough bytes are available for a 4-byte read operation and updates internal state for retry.
			 *
			 * @return True if more bytes are needed and retry state is set, false if enough bytes are available.
			 */
			boolean not_get4() {
				if( buffer.remaining() < bytes_left ) {
					int r = buffer.remaining(); // Get available bytes
					u4 |= get4( r ) << ( bytes_max - bytes_left ) * 8; // Accumulate available bytes to u4
					bytes_left -= r; // Update remaining bytes count
					return true; // Indicate more bytes are needed
				}
				
				u4 |= get4( bytes_left ) << ( bytes_max - bytes_left ) * 8; // Accumulate remaining bytes to u4
				return false; // Indicate enough bytes are available
			}
			
			/**
			 * Abstract method to obtain a packet-specific handler ({@link Receiver.BytesDst}) based on the packet ID.
			 * This is called after the packet ID has been read from the stream.
			 *
			 * @param id Packet ID identifying the type of incoming packet.
			 * @return {@link Receiver.BytesDst} instance to handle the received packet data.
			 * Should throw an exception if the ID is unrecognized or invalid.
			 */
			protected abstract BytesDst _OnReceiving( int id ); //throws Exception if wrong id
			
			protected abstract void _OnReceived( BytesDst received );
			
			/** Closes the receiver, resetting its state and clearing resources. */
			@Override
			public void close() {
				reset();
			}
			
			/**
			 * Resets the receiver to its initial state. Clears active slots, buffers,
			 * and resets state variables for processing new data.
			 */
			protected void reset() {
				if( slot == null ) return; // No active slot to reset
				
				for( Slot s = slot; s != null; s = s.next ) s.dst = null; // Release BytesDst references in slots
				slot = null; // Detach active slot chain
				
				buffer = null; // Release buffer reference
				chs    = null; // Release char array reference
				
				mode       = OK; // Reset operational mode to OK
				bytes_left = bytes_max = id_bytes; // Reset byte counters
				u4         = 0; // Reset 4-byte value buffer
				//dont u8 = 0; preserve probably a value pack data for framing layer.
				//dont str = null; preserve probably a value pack data for framing layer.
			}
			
			/**
			 * Writes bytes from the input ByteBuffer {@code src} to the receiver.
			 * This is the main entry point for feeding data into the receiver. It handles packet identification,
			 * state transitions for reading various data types, and dispatches to appropriate packet handlers.
			 *
			 * @param src ByteBuffer containing bytes to write.
			 *            ATTENTION! The data in "src" may change due to buffer reuse.
			 * @return Number of bytes processed from {@code src}. Returns -1 if a handler reset the receiver during an event.
			 */
			public int write( ByteBuffer src ) {
				
				final int remaining = src.remaining(); // Get initial remaining bytes
write_loop:
				// Label for breaking out of the write loop
				{
					for( buffer = src; src.hasRemaining(); ) { // Loop while source buffer has bytes
						// Active slot and destination exist, process data based on mode
						// Check if no active slot or destination
						if( slot == null || slot.dst == null )
							try {
								if( not_get4() ) break write_loop; // Break if not enough bytes for ID and retry
								
								final BytesDst dst = _OnReceiving( u4 ); // Identify packet type based on ID
								if( ( slot = slot_ref.get() ) == null ) slot_ref = new SoftReference<>( slot = new Slot( this, null ) ); // Get or create a new slot
								
								slot.dst   = dst; // Assign destination to slot
								bytes_left = bytes_max = id_bytes; // Reset byte counters for new packet
								u4         = 0; // Reset 4-byte value buffer
								u8         = 0; // Reset 8-byte value buffer
								u8_        = 0; // Reset secondary 8-byte value buffer
								slot.state = 0; // Reset slot state
								if( handler != null ) handler.OnReceiving( this, dst ); // Notify event handler about receiving start
								if( slot == null ) return -1; // Receiving event handler has reset this, return error
							} catch( Exception ex ) {
								error_handler.error( this, OnError.INVALID_ID, ex ); // Handle invalid ID error
								reset(); // Reset receiver on exception
								break; // Exit write loop after error
							}
						else switch( mode ) {
							case INT1: // Reading 1-byte integer
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								u8 = ( byte ) u4; // Cast to byte
								break;
							case INT2: // Reading 2-byte integer
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								u8 = ( short ) u4; // Cast to short
								break;
							case INT4: // Reading 4-byte integer
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								u8 = u4; // Assign integer value
								break;
							case VAL4: // Reading 4-byte value
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								break; // Value already in u4 from not_get4
							case VAL8: // Reading 8-byte value
								if( buffer.remaining() < bytes_left ) {
									int r = buffer.remaining(); // Get available bytes
									u8 |= get8( r ) << ( bytes_max - bytes_left ) * 8; // Accumulate available bytes to u8
									bytes_left -= r; // Update remaining bytes count
									break write_loop; // Break and retry after getting more bytes
								}
								
								u8 |= get8( bytes_left ) << ( bytes_max - bytes_left ) * 8; // Accumulate remaining bytes to u8
								
								break;
							case LEN0: // Reading length (0 bytes)
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								slot.check_len0( u4 ); // Check length 0 condition
								break;
							case LEN1: // Reading length (1 byte)
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								slot.check_len1( u4 ); // Check length 1 condition
								break;
							case LEN2: // Reading length (2 bytes)
								if( not_get4() ) break write_loop; // Break if not enough bytes and retry
								slot.check_len2( u4 ); // Check length 2 condition
								break;
							case VARINT: // Reading VarInt
								if( varint() ) break; // Continue if VarInt read successfully
								break write_loop; // Break and retry if VarInt read is incomplete
							
							case STR: // Reading String
								if( !varint() )
									break write_loop; // Break and retry if VarInt read is incomplete (string length)
								
								// Check if string length has been received
								if( u8_ == -1 ) if( check_length_and_getting_string() )
									break; // Continue if string length and string read successfully
								else break write_loop; // Break and retry if string reading is incomplete
								
								chs[ u4++ ] = ( char ) u8; // Accumulate string characters
								if( getting_string() ) break; // Continue if string read is complete
								break write_loop; // Break and retry if string reading is incomplete
						}
						
						mode = OK; // Reset mode to OK after processing

dispatch_loop:
						// Label for dispatching loop
						for( ; ; )
							if( !this.slot.dst.__put_bytes( this ) )
								break write_loop; // Data processing over for current BytesDst, break write loop
							else {
								
								if( slot.prev == null ) break dispatch_loop; // No previous slot, break dispatch loop
								slot = slot.prev; // Move to previous slot in chain
							}
						_OnReceived( slot.dst );
						if( handler != null ) handler.OnReceived( this, slot.dst ); // Notify event handler about packet received
						u4         = 0; // Reset 4-byte value buffer
						bytes_left = bytes_max = id_bytes; // Reset byte counters
						if( slot == null ) return -1;   // Received event handler has reset this, return error
						slot.dst = null; // Ready to read next packet data
					}
					
					if( slot != null && slot.dst == null ) reset(); // Reset receiver if slot is active but destination is null (error state)
				} //write_loop
				
				buffer = null; // Release buffer reference
				
				return remaining; // Return initial remaining byte count
			}
			
			/**
			 * Retrieves bytes for a specific BytesDst.
			 *
			 * @param <DST> Type of BytesDst.
			 * @param dst   BytesDst instance to retrieve bytes for.
			 * @return The provided BytesDst instance after processing.
			 */
			public < DST extends BytesDst > DST get_bytes( DST dst ) {
				slot.state = 0; // Reset slot state
				dst.__put_bytes( this ); // Process bytes for the given BytesDst
				return dst; // Return the BytesDst instance
			}
			
			
			/**
			 * Attempts to retrieve bytes for a BytesDst and transitions to a next state on failure.
			 *
			 * @param <DST>     Type of BytesDst.
			 * @param dst       BytesDst instance to retrieve bytes for.
			 * @param next_case State to transition to if byte retrieval fails.
			 * @return The provided BytesDst instance if retrieval is successful, null otherwise.
			 */
			public < DST extends BytesDst > DST try_get_bytes( DST dst, int next_case ) {
				
				final Slot s = slot; // Store current slot
				
				( slot = s.next == null ?
						// Get next slot or create a new one if necessary
						s.next = new Slot( this, s ) :
						s.next ).dst = dst; // Assign BytesDst to the slot
				this.slot.state      = 0; // Reset slot state
				u8_                  = 0; // Reset secondary 8-byte value buffer
				if( dst.__put_bytes( this ) ) { // Attempt to process bytes for BytesDst
					slot = s; // Restore previous slot on success
					return dst; // Return BytesDst instance
				}
				
				s.state = next_case; // Set state of the previous slot to next_case on failure
				
				return null; // Return null indicating failure
			}
			
			public int get_bytes( byte[] dst, int dst_byte, int dst_bytes, int retry_case ) {
				int r = buffer.remaining();
				if( r < dst_bytes ) {
					dst_bytes = r;
					retry_at( retry_case );
				}
				buffer.get( dst, dst_byte, dst_bytes );
				return dst_bytes;
			}
			
			/**
			 * Sets the receiver to retry at a specific state.
			 *
			 * @param the_case State to retry at.
			 */
			public void retry_at( int the_case ) {
				slot.state = the_case; // Set slot state to retry case
				mode       = RETRY; // Set mode to retry
			}
			
			/**
			 * Checks if there are remaining bytes in the buffer, otherwise sets retry state.
			 *
			 * @param next_case State to transition to if no bytes are remaining.
			 * @return True if bytes are remaining, false otherwise and retry state is set.
			 */
			public boolean has_bytes( int next_case ) {
				if( buffer.hasRemaining() ) return true; // Bytes are remaining
				mode       = RETRY; // Set mode to retry
				slot.state = next_case; // Set slot state to next case
				return false; // Indicate no bytes remaining
			}
			
			/** Checks if at least 1 byte is available, otherwise sets retry state for a 1-byte read. */
			public boolean has_1bytes( int get_case ) { return buffer.hasRemaining() || retry_get4( 1, get_case ); }
			
			/** Gets a boolean value from {@code u4} (result of an incremental read). Assumes {@code u4} holds 0 or 1. */
			public boolean get_boolean_() { return u4 == 1; }
			
			/** Gets a boolean value (1 byte: 0 for false, 1 for true) directly from the buffer. */
			public boolean get_boolean() { return buffer.get() == 1; }
			
			/** Gets a byte value from {@code u4} (result of an incremental read). */
			public byte get_byte_() { return ( byte ) u4; }
			
			/** Gets a byte value directly from the buffer. */
			public byte get_byte() { return buffer.get(); }
			
			/** Gets an unsigned byte value (as char) directly from the buffer. */
			public char get_ubyte() { return ( char ) ( buffer.get() & 0xFF ); }
			
			/** Gets an unsigned byte value (as char) from {@code u4}. */
			public char get_ubyte_() { return ( char ) ( u4 & 0xFF ); }
			
			/** Checks if at least 2 bytes are available, otherwise sets retry state for a 2-byte read. */
			public boolean has_2bytes( int get_case ) { return 1 < buffer.remaining() || retry_get4( 2, get_case ); }
			
			/** Gets a short value from {@code u4}. */
			public short get_short_() { return ( short ) u4; }
			
			/** Gets a short value directly from the buffer. */
			public short get_short() { return buffer.getShort(); }
			
			/** Gets a char value directly from the buffer. */
			public char get_char() { return buffer.getChar(); }
			
			/** Gets a char value from {@code u4}. */
			public char get_char_() { return ( char ) u4; }
			
			/** Checks if at least 4 bytes are available, otherwise sets retry state for a 4-byte read. */
			public boolean has_4bytes( int get_case ) { return 3 < buffer.remaining() || retry_get4( 4, get_case ); }
			
			/** Gets an int value directly from the buffer. */
			public int get_int() { return buffer.getInt(); }
			
			/** Gets an int value from {@code u4}. */
			public int get_int_() { return u4; }
			
			/** Gets an unsigned int value (as long) directly from the buffer. */
			public long get_uint() { return buffer.getInt() & 0xFFFFFFFFL; }
			
			/** Gets an unsigned int value (as long) from {@code u4}. */
			public long get_uint_() { return u4 & 0xFFFFFFFFL; }
			
			/** Checks if at least 8 bytes are available, otherwise sets retry state for an 8-byte read. */
			public boolean has_8bytes( int get_case ) { return 7 < buffer.remaining() || retry_get8( 8, get_case ); }
			
			/** Gets a long value directly from the buffer. */
			public long get_long() { return buffer.getLong(); }
			
			/** Gets a long value from {@code u8}. */
			public long get_long_() { return u8; }
			
			/** Gets a double value directly from the buffer. */
			public double get_double() { return buffer.getDouble(); }
			
			/** Gets a double value from {@code u8} (long bits). */
			public double get_double_() { return Double.longBitsToDouble( u8 ); }
			
			/** Gets a float value directly from the buffer. */
			public float get_float() { return buffer.getFloat(); }
			
			/** Gets a float value from {@code u4} (int bits). */
			public float get_float_() { return Float.intBitsToFloat( u4 ); }
			
			/** Gets a byte value, stores in {@code u8}. Retries if needed, setting mode to {@link #INT1}. */
			public boolean get_byte_u8( int get_case ) {
				if( buffer.hasRemaining() ) {
					u8 = buffer.get(); // Read byte into u8.
					return true;
				}
				retry_get4( 1, get_case ); // Not enough data, setup retry for 1 byte (via get4 logic).
				mode = INT1; // Next time, write() will complete using INT1 case.
				return false;
			}
			
			/** Gets an unsigned byte value, stores in {@code u8}. Retries if needed. */
			public boolean get_ubyte_u8( int get_case ) {
				if( !buffer.hasRemaining() ) return retry_get8( 1, get_case ); // Use get8 logic for 1 byte into u8.
				u8 = buffer.get() & 0xFF;
				return true;
			}
			
			/** Gets a short value, stores in {@code u8}. Retries if needed, setting mode to {@link #INT2}. */
			public boolean get_short_u8( int get_case ) {
				if( 1 < buffer.remaining() ) {
					u8 = buffer.getShort();
					return true;
				}
				retry_get4( 2, get_case );
				mode = INT2;
				return false;
			}
			
			/** Gets a char value (unsigned short), stores in {@code u8}. Retries if needed. */
			public boolean get_char_u8( int get_case ) {
				if( buffer.remaining() < 2 ) return retry_get8( 2, get_case );
				u8 = buffer.getChar();
				return true;
			}
			
			/** Gets an int value, stores in {@code u8}. Retries if needed, setting mode to {@link #INT4}. */
			public boolean get_int_u8( int get_case ) {
				if( 3 < buffer.remaining() ) {
					u8 = buffer.getInt();
					return true;
				}
				retry_get4( 4, get_case );
				mode = INT4;
				return false;
			}
			
			/** Gets an unsigned int value, stores in {@code u8}. Retries if needed. */
			public boolean get_uint_u8( int get_case ) {
				if( buffer.remaining() < 4 ) return retry_get8( 4, get_case );
				u8 = buffer.getInt() & 0xFFFFFFFFL;
				return true;
			}
			
			/** Gets a long value, stores in {@code u8}. Retries if needed. */
			public boolean get_long_u8( int get_case ) {
				if( buffer.remaining() < 8 ) return retry_get8( 8, get_case );
				u8 = buffer.getLong();
				return true;
			}
			//#region 8
			
			/**
			 * Attempts to read {@code bytes} into {@code u8}. Retries if not enough bytes are available.
			 *
			 * @param bytes     Number of bytes to read (1-8).
			 * @param next_case State for retry.
			 * @return True if read completely, false if retry is set.
			 */
			public boolean try_get8( int bytes, int next_case ) {
				if( buffer.remaining() < bytes )
					return retry_get8( bytes, next_case );
				u8 = get8( bytes );
				return true;
			}
			
			/**
			 * Sets up retry for an 8-byte (or less) read into {@code u8}. Reads available bytes.
			 *
			 * @param bytes     Total bytes for the value (1-8).
			 * @param get8_case State for retry.
			 * @return Always false (indicates retry is needed).
			 */
			public boolean retry_get8( int bytes, int get8_case ) {
				bytes_left = ( bytes_max = bytes ) - buffer.remaining();
				u8         = get8( buffer.remaining() );
				slot.state = get8_case;
				mode       = VAL8;
				return false;
			}
			
			/** Returns the current value in {@code u8}. */
			public long get8() { return u8; }
			
			/**
			 * Reads {@code bytes} from buffer and constructs a long. Bytes are read LSB first from buffer for MSB part of long.
			 * This means if bytes=1, it reads a byte and returns it as long. If bytes=2, reads short, etc.
			 * This is for constructing a right-aligned value in a long from fewer than 8 bytes.
			 *
			 * @param bytes Number of bytes to read (0-8).
			 * @return Long value constructed from read bytes.
			 */
			public long get8( int bytes ) {
				int limit = buffer.limit();
				int pos   = buffer.position();
				
				if( pos + 8 <= limit ) {
					long value = buffer.getLong( pos );
					buffer.position( pos + bytes );
					int bits = 8 - bytes << 3;
					return value << bits >>> bits;
				}
				switch( bytes ) {
					case 8:
						return buffer.getLong();
					case 7:
						return buffer.getInt() & 0xFFFF_FFFFL |
						       ( buffer.getShort() & 0xFFFFL ) << 32 |
						       ( buffer.get() & 0xFFL ) << 48;
					case 6:
						return buffer.getInt() & 0xFFFF_FFFFL |
						       ( buffer.getShort() & 0xFFFFL ) << 32;
					case 5:
						return buffer.getInt() & 0xFFFF_FFFFL |
						       ( buffer.get() & 0xFFL ) << 32;
					case 4:
						return buffer.getInt() & 0xFFFF_FFFFL;
					case 3:
						return buffer.getShort() & 0xFFFFL |
						       ( buffer.get() & 0xFFL ) << 16;
					case 2:
						return buffer.getShort() & 0xFFFFL;
					case 1:
						return buffer.get() & 0xFFL;
				}
				return 0;
			}
			
			
			//#endregion
			//#region 4
			
			/** Attempts to read {@code bytes} into {@code u4}. Retries if needed. */
			public boolean try_get4( int bytes, int next_case ) {
				if( buffer.remaining() < bytes )
					return retry_get4( bytes, next_case );
				u4 = get4( bytes );
				return true;
			}
			
			/** Sets up retry for a 4-byte (or less) read into {@code u4}. Reads available bytes. */
			public boolean retry_get4( int bytes, int get_case ) {
				bytes_left = ( bytes_max = bytes ) - buffer.remaining();
				u4         = get4( buffer.remaining() );
				slot.state = get_case;
				mode       = VAL4;
				return false;
			}
			
			/** Returns the current value in {@code u4}. */
			public int get4() { return u4; }
			
			/**
			 * Reads {@code num_bytes} from buffer and constructs an int. Bytes are right-aligned.
			 *
			 * @param bytes Number of bytes to read (0-4).
			 * @return Int value constructed from read bytes.
			 */
			public int get4( int bytes ) {
				int limit = buffer.limit();
				int pos   = buffer.position();
				
				if( pos + 4 <= limit ) {
					int value = buffer.getInt( pos );
					buffer.position( pos + bytes );
					int bits = 8 - bytes << 3;
					return value << bits >>> bits;
				}
				
				switch( bytes ) {
					case 4:
						return buffer.getInt();
					case 3:
						return buffer.getShort() & 0xFFFF |
						       ( buffer.get() & 0xFF ) << 16;
					case 2:
						return buffer.getShort() & 0xFFFF;
					case 1:
						return buffer.get() & 0xFF;
				}
				return 0;
			}
			//#endregion
			//#region bits
			
			/** Initializes bit-level reading. Resets internal bit buffer and bit position. */
			public void init_bits() {
				bits = 0; // Bit accumulator.
				bit  = 8; // Bit position (8 means next get_bits(len) will fetch a new byte if needed).
			}
			
			/** Gets the last fully read byte from bit operations (stored in {@code u4} by {@code try_get_bits}). */
			public byte get_bits() { return ( byte ) u4; } // This implies u4 holds the result of the last try_get_bits
			
			/**
			 * Gets specified number of bits from the stream. Manages internal bit buffer.
			 *
			 * @param len_bits Number of bits to read (1-8).
			 * @return Integer value constructed from the read bits.
			 */
			public int get_bits( int len_bits ) {
				int ret;
				if( bit + len_bits < 9 ) { // Check if bits can be read from current byte
					ret = bits >> bit & 0xFF >> 8 - len_bits; // Extract bits from current byte
					bit += len_bits;
				}
				else { // Need to read from next byte
					ret = ( bits >> bit | ( bits = buffer.get() & 0xFF ) << 8 - bit ) & 0xFF >> 8 - len_bits; // Read next byte, combine bits
					bit = bit + len_bits - 8;
				}
				
				return ret; // Return extracted bits
			}
			
			/**
			 * Attempts to get specified number of bits, storing result in {@code u4}. Retries if buffer is exhausted.
			 *
			 * @param len_bits  Number of bits to get (1-8).
			 * @param this_case State for retry.
			 * @return True if bits read successfully, false if retry is set.
			 */
			public boolean try_get_bits( int len_bits, int this_case ) {
				if( bit + len_bits < 9 ) { // Check if bits can be read from current byte
					u4 = bits >> bit & 0xFF >> 8 - len_bits; // Extract bits from current byte and store in u4
					bit += len_bits;
				}
				else if( buffer.hasRemaining() ) {
					u4  = ( bits >> bit | ( bits = buffer.get() & 0xFF ) << 8 - bit ) & 0xFF >> 8 - len_bits; // Read next byte, combine bits and store in u4
					bit = bit + len_bits - 8;
				}
				else { // Not enough bytes in buffer for bits
					retry_at( this_case ); // Set retry state
					return false;
				}
				return true; // Bits read successfully
			}
			//#endregion
			//#region varint
			
			/** Helper for {@code try_get_varint_...} to read the value part after length is known. */
			public boolean try_get8( int next_case ) { return try_get8( bytes_left, next_case ); }
			
			/**
			 * For VarInts where length is encoded in 1 bit (+1 offset for actual length).
			 * Reads the 1 bit for length, then sets up for reading the value.
			 *
			 * @param bits      Number of bits for length (should be 1).
			 * @param this_case State for retry.
			 * @return True if length bit read, false if retry.
			 */
			public boolean try_get_varint_bits1( int bits, int this_case ) {
				if( !try_get_bits( bits, this_case ) ) return false; // Retry if bits not available
				bytes_left = bytes_max = get_bits() + 1; // Get VarInt length and set bytes_left/bytes_max
				return true; // VarInt length bits read successfully
			}
			
			/**
			 * For VarInts where length is encoded in {@code bits}.
			 * Reads length bits, then sets up for reading the value.
			 *
			 * @param bits      Number of bits for length.
			 * @param this_case State for retry.
			 * @return True if length bits read, false if retry.
			 */
			public boolean try_get_varint_bits( int bits, int this_case ) {
				if( !try_get_bits( bits, this_case ) ) return false; // Retry if bits not available
				bytes_left = bytes_max = get_bits(); // Get VarInt length and set bytes_left/bytes_max
				return true; // VarInt length bits read successfully
			}
			
			/**
			 * Attempts to read a standard VarInt into {@code u8}. Retries if incomplete.
			 *
			 * @param next_case State for retry.
			 * @return True if VarInt read completely, false if retry.
			 */
			public boolean try_get_varint( int next_case ) {
				u8         = 0; // Reset VarInt accumulator.
				bytes_left = 0; // VarInt shift (0, 7, 14...).
				if( varint() ) return true; // varint() reads into u8.
				
				// Incomplete, set up retry.
				slot.state = next_case;
				mode       = VARINT; // VARINT mode handles incremental VarInt read.
				return false;
			}
			
			/** Reads a VarInt value from the buffer into {@code u8}. {@code bytes_left} tracks bit shift. */
			private boolean varint() {
				
				// Loop until VarInt is complete or buffer is empty
				for( byte b; buffer.hasRemaining(); u8 |= ( b & 0x7FL ) << bytes_left, bytes_left += 7 )
					if( -1 < ( b = buffer.get() ) ) { // Check if current byte is the last byte of VarInt
						u8 |= ( long ) b << bytes_left; // Accumulate last byte value to u8
						return true; // VarInt read completely
					}
				
				return false; // VarInt read incomplete
			}
			
			/** Decodes a zig-zag encoded long value to its original signed form. */
			public static long zig_zag( long src ) { return -( src & 1 ) ^ src >>> 1; }
			//#endregion
			//#region dims
			
			/** Empty integer array constant, used for initializing {@link #dims}. */
			private static final int[] empty = new int[ 0 ];
			/** Array to store dimensions, e.g., for multi-dimensional arrays or variable-length lists. */
			private              int[] dims  = empty; //temporary buffer for the receiving string and more
			
			/** Initializes the dimensions array {@link #dims} if {@code size} is larger than current capacity. {@code u8} is reset to 1. */
			public void init_dims( int size ) {
				u8 = 1; // u8 often used to accumulate product of dimensions.
				if( size <= dims.length ) return;
				dims = new int[ size ];
			}
			
			/** Gets a dimension value from the {@link #dims} array at a specific index. */
			public int dim( int index ) { return dims[ index ]; }
			
			/**
			 * Reads a dimension value (assumed to be in {@code u4}), checks against {@code max},
			 * stores it in {@link #dims}, and updates {@code u8} by multiplying with this dimension.
			 *
			 * @param max   Max allowed value for this dimension.
			 * @param index Index in {@link #dims} to store this dimension.
			 */
			public void dim( int max, int index ) {
				int dim = u4; // Get dimension value from u4
				if( max < dim ) error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "Dimension " + dim + " exceeds max " + max ) );
				
				dims[ index ] = dim;
				                u8 *= dim;  // Accumulate product of dimensions.
			}
			
			/**
			 * Reads a length value (assumed to be in {@code u4}) and checks against {@code max}.
			 *
			 * @param max Maximum allowed length.
			 * @return Length value if within limit, or 0 if overflow (error is handled).
			 */
			public int length( long max ) {
				int len = u4; // Get length value from u4
				if( len <= max ) return len; // Length is within limit, return length
				
				error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "In length  (long max){} max < len : " + max + " < " + len ) );
				u8 = 0; // Reset u8 to 0 on overflow
				return 0; // Return 0 indicating overflow
			}
			//#endregion
			//#region string
			
			/** Gets the string result from {@link #str} (populated by string reading operations) and clears {@link #str}. */
			public String get_string() {
				String result = str;
				str = null; // Clear for next string.
				return result;
			}
			
			/**
			 * Attempts to read a VarInt-encoded string. Retries if incomplete.
			 * Max length in chars is {@code max_chars}. String length is read as VarInt first, then chars as VarInt.
			 *
			 * @param max_chars       Max allowed characters for the string.
			 * @param get_string_case State for retry.
			 * @return True if string read completely, false if retry.
			 */
			public boolean try_get_string( int max_chars, int get_string_case ) {
				u4  = max_chars; // Set maximum characters count in u4
				u8_ = -1; // Indicate state before string length received
				
				u8         = 0;         //varint receiving string char holde
				bytes_left = 0; //varint pointer
				if( varint() && //getting string length into u8
				    check_length_and_getting_string() ) return true; // String read successfully
				
				slot.state = get_string_case; // Set slot state to retry case
				mode       = STR; // Set mode to read string
				return false;
			}
			
			/** Soft reference to a char array, for string building, to reduce GC pressure. */
			private SoftReference< char[] > chs_ref = new SoftReference<>( null );
			/** Char array buffer for storing received string characters. */
			private char[]                  chs     = null;
			
			/**
			 * After string length is read (into {@code u8}), checks length against max (in {@code u4}),
			 * allocates/reuses {@link #chs} buffer, and starts {@link #getting_string()} for characters.
			 *
			 * @return True if length valid and char reading can proceed/completed, false on overflow or if char reading needs retry.
			 */
			private boolean check_length_and_getting_string() {
				
				if( u4 < u8 ) error_handler.error( this, OnError.OVERFLOW, new IllegalArgumentException( "In check_length_and_getting_string  (){} u4 < u8 : " + u4 + " < " + u8 ) );
				
				if( chs == null && ( chs = chs_ref.get() ) == null || chs.length < u8 ) chs_ref = new SoftReference<>( chs = new char[ ( int ) u8 ] ); // Get or create char array buffer
				
				u8_ = u8; // Store string length in u8_
				u4  = 0;   //index 1receiving char
				
				return getting_string(); // Start getting string characters
			}
			
			/** Reads VarInt-encoded characters into {@link #chs} until string is complete. {@code u4} is current char index, {@code u8_} is total. */
			private boolean getting_string() {
				
				while( u4 < u8_ ) {
					u8         = 0; // Reset u8 for character value
					bytes_left = 0; // Reset bytes_left for VarInt
					if( varint() ) chs[ u4++ ] = ( char ) u8; // Accumulate character to char array
					else return false; // String read incomplete, retry needed
				}
				str = new String( chs, 0, u4 ); // Construct string from char array
				return true; // String read completely
			}
			//#endregion
			
			/** Gets the number of remaining bytes in the current {@link #buffer}. */
			public int remaining() { return buffer.remaining(); }
			
			/** Gets the current position of the {@link #buffer}. */
			public int position() { return buffer.position(); }
			
			/** Provides a string representation of the Receiver, including its class name and current slot chain state for debugging. */
			@Override
			public String toString() {
				if( slot == null ) return super.toString() + " \uD83D\uDCA4"; // Indicate idle state with emoji
				Slot s = slot;
				while( s.prev != null ) s = s.prev; // Get to the head of the slot chain
				StringBuilder sb     = new StringBuilder( super.toString() + "\n" ); // Initialize string builder
				String        offset = ""; // Initialize offset for indentation
				for( ; s != slot; s = s.next, offset += "\t" ) sb.append( offset ).append( s.dst.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" ); // Append slot info with indentation
				
				sb.append( offset ).append( s.dst.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" ); // Append current slot info
				
				return sb.toString(); // Return string representation
			}
		}
		
		/**
		 * Abstract base class for Transmitters in the AdHoc protocol.
		 * Extends {@link Base.Transmitter} and implements {@link AdHoc.BytesSrc},
		 * providing functionality for transmitting and encoding data into a byte stream.
		 */
		abstract class Transmitter extends Base.Transmitter implements BytesSrc {
			
			
			/**
			 * Default error handler for Transmitting operations. Can be overridden to customize error handling.
			 */
			public static OnError.Handler error_handler = OnError.Handler.DEFAULT;
			
			/**
			 * Annotation and interface for defining error handling callbacks in Receivers.
			 */
			public @interface OnError {
				/** Error code: Transmitting packet is rejected by dataflow. */
				int REJECTED = 0;
				/** Error code: A transmitting items number exceeds maximum allowed. */
				int OVERFLOW = 1;
				/** Error code indicating a timeout during packet transmission or reception. */
				int TIMEOUT  = 2;
				/** Generic error code for unspecified or unexpected errors during packet processing. */
				int ERROR    = 3;
				
				/**
				 * Interface for handling errors encountered within the Receiver.
				 */
				interface Handler {
					/** Default error handler implementation that prints error messages to System.out. */
					Handler DEFAULT = new Handler() { };
					
					/**
					 * Handles errors that occur during data transmitting in the {@link AdHoc.BytesSrc}.
					 *
					 * @param src   The {@link AdHoc.BytesSrc} transmitter where the error occurred .
					 * @param error The error code, indicating the type of error (see constants in {@link OnError}).
					 * @param ex    Optional exception associated with the error, providing more details.
					 */
					default void error( AdHoc.BytesSrc src, int error, Throwable ex ) {
						switch( error ) {
							case OVERFLOW:
								System.out.println( "OVERFLOW src:\n" + src + " at:\n" + ( ex == null ?
										"" :
										StackTracePrinter.ONE.stackTrace( ex ) ) );
							case REJECTED:
								System.out.println( "REJECTED src:\n" + src + " at:\n" + ( ex == null ?
										"" :
										StackTracePrinter.ONE.stackTrace( ex ) ) );
								break;
							default:
								System.out.println( "Error src: " + error + " src:\n" + src + " at:\n" + ( ex == null ?
										"" :
										StackTracePrinter.ONE.stackTrace( ex ) ) );
						}
					}
				}
			}
			
			
			/** Interface for handling events during the transmission process. */
			public interface EventsHandler {
				
				/**
				 * Callback triggered before sending a packet from internal representation to the external stream (e.g., before framing).
				 *
				 * @param dst The Transmitter instance that triggered the event.
				 * @param src The {@link Transmitter.BytesSrc} (packet data source) providing data to be sent.
				 */
				default void OnSerializing( Transmitter dst, Transmitter.BytesSrc src ) { }
				
				/**
				 * Callback triggered after a packet is fully processed by the transmitter (e.g., after framing and CRC).
				 * Note: This does not guarantee that all bytes have been physically transmitted by the underlying socket/channel.
				 *
				 * @param dst The Transmitter instance that triggered the event.
				 * @param src The {@link Transmitter.BytesSrc} (packet data source) that was sent.
				 */
				default void OnSerialized( Transmitter dst, Transmitter.BytesSrc src ) { }
			}
			
			/** Interface for a source of bytes to be transmitted, specific to a packet type within the Transmitter. */
			public interface BytesSrc {
				/**
				 * Provides bytes for transmission by serializing data into the Transmitter's buffer.
				 * Implementors use Transmitter's {@code put_...} methods.
				 *
				 * @param dst The Transmitter instance requesting bytes and providing context/buffer.
				 * @return True if bytes successfully provided and more might be available (or if this part is done but parent continues);
				 * false if no more bytes for this operation or an error/retry is set.
				 */
				boolean __get_bytes( Transmitter dst );
				
				/** Returns the ID associated with this packet data source. */
				int __id();
			}
			
			/** Event handler for transmission events. Volatile for thread-safe access. */
			public volatile      EventsHandler                                             handler;
			/** Atomic updater for the 'handler' field. */
			private static final AtomicReferenceFieldUpdater< Transmitter, EventsHandler > exchange = AtomicReferenceFieldUpdater.newUpdater( Transmitter.class, EventsHandler.class, "handler" );
			
			/** Atomically exchanges the current event handler with a new one. */
			public EventsHandler exchange( EventsHandler dst ) {
				return exchange.getAndSet( this, dst );
			}
			
			/** Constructor with default sending queue size (32, from 2^5). */
			public Transmitter( EventsHandler handler ) { this( handler, 5 ); }
			
			/**
			 * Constructor for Transmitter.
			 *
			 * @param handler                       Event handler for transmission events.
			 * @param power_of_2_sending_queue_size Determines sending queue size (2<sup>power_of_2_sending_queue_size</sup>).
			 */
			public Transmitter( EventsHandler handler, int power_of_2_sending_queue_size ) {
				super( power_of_2_sending_queue_size );
				this.handler = handler;
			}
			
			/** Subscriber to be notified when new bytes are available for transmission. */
			protected Consumer< AdHoc.BytesSrc > subscriber;
			
			
			/**
			 * Subscribes a consumer for notifications when new bytes are ready for transmission.
			 * If data is already pending in the send queue, the subscriber is notified immediately.
			 *
			 * @param subscriber The consumer to notify. Accepts this Transmitter (as {@link AdHoc.BytesSrc}) as argument.
			 * @return The previously set subscriber.
			 */
			@Override
			public Consumer< AdHoc.BytesSrc > subscribe_on_new_bytes_to_transmit_arrive( Consumer< AdHoc.BytesSrc > subscriber ) {
				Consumer< AdHoc.BytesSrc > tmp = this.subscriber; // Store current subscriber
				this.subscriber = subscriber;
				notify_subscribers();
				return tmp; // Return previous subscriber
			}
			
			protected void notify_subscribers() { if( subscriber != null && IsIdle() ) subscriber.accept( this ); } // Notify subscriber if pending bytes exist
			
			//#region sending
			
			/** Lock for thread-safe access to sending queue operations. 0 for unlocked, 1 for locked. */
			private volatile     int                                      sending_lock = 0;
			private static final AtomicIntegerFieldUpdater< Transmitter > SENDING_LOCK = AtomicIntegerFieldUpdater.newUpdater( Transmitter.class, "sending_lock" );
			
			/** Acquires the sending lock using a spin-wait. */
			protected void sending_lock_acquire() { while( !SENDING_LOCK.compareAndSet( this, 0, 1 ) ) Thread.onSpinWait(); }
			
			protected void sending_lock_release() { sending_lock = 0; }
			
			//do not forget to  set u8 = sending_out.value;
			protected abstract Transmitter.BytesSrc _OnSerializing();
			
			protected abstract void _OnSerialized( Transmitter.BytesSrc transmitted );
			
			public abstract boolean IsIdle();
			
			
			//#endregion
			
			
			//#region value_pack transfer
			
			/**
			 * Initiates transmission for a {@link Transmitter.BytesSrc} that uses an associated long value.
			 * The value is placed in {@code u8}.
			 *
			 * @param src       The long value.
			 * @param handler   The {@link Transmitter.BytesSrc} for serialization.
			 * @param next_case State for the parent slot if this operation needs retry.
			 * @return True if successfully initiated/completed, false if retry.
			 */
			public boolean put_bytes( long src, BytesSrc handler, int next_case ) {
				
				u8 = src;
				return put_bytes( handler, next_case );
			}
			
			/**
			 * Initiates transmission for a {@link Transmitter.BytesSrc}, skipping packet ID writing (state 1).
			 * Typically for top-level packets where ID is handled by {@link #read(ByteBuffer)}.
			 *
			 * @param src The {@link Transmitter.BytesSrc} for serialization.
			 */
			public void put_bytes( BytesSrc src ) {
				
				slot.state = 1; // Start serialization from state 1 (skip ID write).
				src.__get_bytes( this ); // Get bytes from BytesSrc for transmission
			}
			
			/**
			 * Initiates transmission for a nested {@link Transmitter.BytesSrc}.
			 *
			 * @param src       The nested {@link Transmitter.BytesSrc}.
			 * @param next_case State for parent slot if retry is needed.
			 * @return True if successfully initiated/completed, false if retry.
			 */
			public boolean put_bytes( BytesSrc src, int next_case ) {
				
				final Slot s = slot; // Store current slot
				
				( slot = s.next == null ?
						// Get next slot or create a new one if necessary
						s.next = new Slot( this, s ) :
						s.next ).src = src; // Assign BytesSrc to the slot
				this.slot.state      = 1; // Nested structures start serializing payload directly.
				
				if( src.__get_bytes( this ) ) { // Get bytes from BytesSrc for transmission
					slot = s; // Restore previous slot on success
					return true; // Bytes put successfully
				}
				
				s.state = next_case; // Set state of the previous slot to next_case on failure
				return false;
			}
			//#endregion
			
			/**
			 * A framing encoder for byte-oriented protocols that use special character escaping and CRC.
			 * This class takes raw packet data from an {@link #upper_layer} {@link Transmitter},
			 * prepends a frame marker (0xFF), encodes the payload using a bit-oriented transformation
			 * for 0x7F/0xFF, and appends a CRC. It acts as a {@link AdHoc.BytesSrc} producing framed data.
			 * <p>Frame structure: 0xFF (start marker) + encoded payload + 2-byte CRC.
			 * <p>Payload encoding transforms original bytes to avoid collision with 0xFF frame marker:
			 * - Original `B` (neither 0x7F nor 0xFF) -> `B`
			 * - Original `0x7F` -> `0x7F` then next emitted byte `N` has LSB=0.
			 * - Original `0xFF` -> `0x7F` then next emitted byte `N` has LSB=1.
			 * CRC is calculated on original, unescaped bytes.
			 */
			public static class Framing implements AdHoc.BytesSrc, EventsHandler {
				/** Upper layer Transmitter from which raw packet data is pulled. */
				public               Transmitter                                           upper_layer;
				/** Event handler for Framing events (delegated from/to upper_layer). */
				public volatile      EventsHandler                                         handler;
				/** Atomic updater for the 'handler' field. */
				private static final AtomicReferenceFieldUpdater< Framing, EventsHandler > exchange = AtomicReferenceFieldUpdater.newUpdater( Framing.class, EventsHandler.class, "handler" );
				
				/** Atomically exchanges the current event handler. */
				public EventsHandler exchange( EventsHandler handler ) {
					return exchange.getAndSet( this, handler );
				}
				
				
				public Framing( Transmitter upper_layer ) { switch_to( upper_layer ); }
				
				/** Switches to a new upper layer Transmitter. Resets state and handlers. */
				public void switch_to( Transmitter upper_layer ) {
					bits  = 0;
					shift = 0;
					crc   = 0;
					if( this.upper_layer != null ) {
						this.upper_layer.reset();
						this.upper_layer.exchange( this.handler ); // Unhook from old.
					}
					// If there was a previous upper layer, reset it and exchange its handler
					handler = ( this.upper_layer = upper_layer ).exchange( this ); // Set new upper layer and hook its handler
				}
				
				/** Current write position in the output ByteBuffer for encoded bytes. */
				private int enc_position;
				/** Current read position in the output ByteBuffer for raw bytes from upper_layer. */
				private int raw_position;
				
				/**
				 * Allocates space in {@code buffer} for upper_layer to write raw bytes.
				 * Reserves space for frame marker, worst-case payload expansion, and CRC.
				 * Sets {@code buffer}'s position to where upper_layer should write.
				 *
				 * @param buffer The output ByteBuffer.
				 * @return True if space allocated, false if buffer too small.
				 */
				private boolean allocate_raw_bytes_space( ByteBuffer buffer ) {
					//divide free space.
					raw_position = ( enc_position = buffer.position() ) + // Set start position for encoded bytes
					               1 +                                  // Space for 0xFF frame start marker
					               buffer.remaining() / 8 +             // Worst case byte expansion (escape sequences)
					               CRC_LEN_BYTES + 2;                   // CRC plus possible expansion
					
					if( raw_position < buffer.limit() ) {
						buffer.position( raw_position ); // Set buffer position to allocated space
						return true; // Return true if there is enough space
					}
					
					buffer.position( enc_position ).limit( enc_position ); //no more space. prevent continue
					return false; // Return false if no space left
				}
				
				/** Closes this framing encoder and its upper layer. */
				@Override
				public void close() {
					reset(); // Reset framing encoder state
					upper_layer.close(); // Close upper layer transmitter
				}
				
				/** Resets framing encoder state (CRC, bit accumulator, upper_layer). */
				private void reset() {
					upper_layer.reset(); // Reset upper layer transmitter
					bits  = 0; // Reset bit accumulator
					shift = 0; // Reset shift counter
					crc   = 0; // Reset CRC value
				}
				
				/**
				 * Reads data using this framing encoder into {@code dst}.
				 * Pulls raw data from {@link #upper_layer}, frames it (marker, encoding, CRC), and writes to {@code dst}.
				 *
				 * @param dst Destination buffer for framed data.
				 * @return Number of bytes written to {@code dst}, or -1 if upper_layer EOS and no more framing work.
				 * @throws IOException If I/O error from upper_layer.
				 */
				@Override
				public int read( ByteBuffer dst ) throws IOException {
					
					final int dst_byte = dst.position(); // Store initial destination buffer position
					while( allocate_raw_bytes_space( dst ) ) { // Allocate space in destination buffer for encoding
						int len = upper_layer.read( dst ); // Get raw bytes from upper layer
						
						if( len < 1 ) { // If no more bytes were read, return encoded bytes count or error code
							dst.limit( enc_position ).position( enc_position ); // Limit buffer to encoded bytes section
							return dst_byte < enc_position ?
									enc_position - dst_byte :
									// Return encoded bytes count
									len; // Return error code from upper layer
						}
						
						encode( dst ); // Encode the raw bytes
					}
					// Return the number of encoded bytes written to the destination buffer
					return dst_byte < enc_position ?
							enc_position - dst_byte :
							// Return encoded bytes count
							0; // Return 0 if no bytes were encoded in this call
				}
				
				/** Called by upper_layer (via event) before it starts writing a packet's payload. Insert 0xFF frame marker. */
				@Override // Handle the sending event: Write the frame start marker (0xFF)
				public void OnSerializing( Transmitter dst, BytesSrc src ) {
					if( handler != null ) handler.OnSerializing( dst, src ); // Notify event handler about sending start
					dst.buffer.put( enc_position++, ( byte ) 0xFF ); // Write frame start marker 0xFF
				}
				
				/** Called by upper_layer (via event) after it has written a packet's payload. Encode CRC and finalize frame. */
				public void OnSerialized( Transmitter dst, BytesSrc pack ) {
					encode( dst.buffer ); // Encode any remaining raw bytes
					
					//the packet sending completed write crc
					int fix = crc; // Fix CRC value to avoid changes during encoding
					encode( fix >> 8 & 0xFF, dst.buffer ); // Write high byte of CRC
					encode( fix & 0xFF, dst.buffer ); // Write low byte of CRC
					if( 0 < shift ) { // Check for remaining bits in accumulator
						dst.put( ( byte ) bits ); // Write remaining bits to buffer
						if( bits == 0x7F ) dst.put( ( byte ) 0 ); // Handle special case for escaped 0x7F
					}
					
					// Update the buffer position or prevent further writing if no space is left
					allocate_raw_bytes_space( dst.buffer ); // Re-allocate space if needed
					
					bits  = 0; // Reset bit accumulator
					shift = 0; // Reset shift counter
					crc   = 0; // Reset CRC value
					if( handler != null ) handler.OnSerialized( dst, pack ); // Notify event handler about send completion
				}
				
				/**
				 * Encodes raw bytes from the upper layer using escape sequences and updates CRC.
				 * Reads bytes from raw_position up to current buffer position and encodes them in place.
				 *
				 * @param buffer ByteBuffer containing raw bytes to encode.
				 */
				// Encode each byte read from upper layer
				private void encode( ByteBuffer buffer ) {
					final int raw_position_max = buffer.position(); // Get current buffer position
					buffer.position( enc_position ); //switch to encoded position
					while( raw_position < raw_position_max ) encode( buffer.get( raw_position++ ) & 0xFF, buffer ); // Encode each raw byte
					enc_position = buffer.position(); // Update encoded position
				}
				
				/**
				 * Encodes a single raw byte, handling special cases for 0x7F and updating CRC.
				 * Manages bit accumulation and shift register for efficient byte packing.
				 *
				 * @param src Source byte to encode (0-255).
				 * @param dst Destination buffer for encoded bytes.
				 */
				private void encode( int src, ByteBuffer dst ) {
					
					crc = crc16( src, crc ); // Update CRC with source byte
					final int v = ( bits |= src << shift ) & 0xFF; // Accumulate source bits into bit buffer
					
					if( ( v & 0x7F ) == 0x7F ) { // Check if lower 7 bits are all 1 (0x7F)
						dst.put( ( byte ) 0x7F ); // Write escape character 0x7F
						bits >>= 7; // Shift out processed bits
						
						if( shift < 7 ) shift++; // Increment shift counter if less than 7 bits shifted
						else // Handle full byte in the shift register
						{
							if( ( bits & 0x7F ) == 0x7F ) {
								dst.put( ( byte ) 0x7F ); // Write escape character 0x7F again if needed
								bits >>= 7; // Shift out processed bits
								
								shift = 1; // Reset shift counter to 1
								return; // Exit encoding
							}
							
							dst.put( ( byte ) bits );// Write the remaining bits
							shift = 0; // Reset shift counter
							bits  = 0; // Reset bit accumulator
						}
						return; // Exit encoding
					}
					
					dst.put( ( byte ) v ); // Write encoded byte to destination buffer
					bits >>= 8; // Shift out processed byte
				}
				
				/** Forwards subscription to the upper layer. */
				@Override
				public Consumer< AdHoc.BytesSrc > subscribe_on_new_bytes_to_transmit_arrive( Consumer< AdHoc.BytesSrc > subscriber ) { return upper_layer.subscribe_on_new_bytes_to_transmit_arrive( subscriber ); }
				
				/** Accumulator for outgoing bits, LSB aligned. */
				private int  bits  = 0;
				/** Number of valid bits currently in {@code bits} starting from LSB. Next src byte shifted by this amount. */
				private int  shift = 0;
				/** CRC checksum for the current frame being encoded (on raw bytes). */
				private char crc   = 0;
				
				/** Checks if the upper layer channel is open. */
				@Override
				public boolean isOpen() { return upper_layer.isOpen(); }
			}
			//#region Slot
			
			/**
			 * Represents a slot in the transmitter's processing chain, managing state for (potentially nested)
			 * data structures being serialized. Extends {@link Base.Transmitter.Slot}.
			 */
			public static final class Slot extends Base.Transmitter.Slot {
				
				/** The {@link Transmitter.BytesSrc} (packet data source) associated with this slot. */
				BytesSrc src;
				
				public BytesSrc src( BytesSrc src ) {
					state = 1;
					return this.src = src;
				}
				
				/** Bitmask to track null fields for the current data structure being transmitted from this slot. */
				int fields_nulls;
				
				/** Reference to the next slot in the chain (for nested structures). */
				private       Slot next;
				/** Reference to the previous slot in the chain. */
				private final Slot prev;
				
				/**
				 * Constructor for Slot.
				 *
				 * @param src  The Transmitter associated with this slot.
				 * @param prev The previous slot in the chain, or null if this is the first slot.
				 */
				public Slot( Transmitter src, Slot prev ) {
					super( src );
					this.prev = prev;
					if( prev != null ) prev.next = this;
				}
			}
			
			/** Soft reference to a Slot instance for recycling. */
			protected SoftReference< Slot > slot_ref = new SoftReference<>( new Slot( this, null ) );
			/** Current active slot in the transmitter's chain, managing state of current packet/structure serialization. */
			public    Slot                  slot;
			
			/** Checks if the transmitter is active (has a slot). */
			public boolean isOpen() { return slot != null; }
			//#endregion
			
			/** Closes the transmitter, resetting state and clearing queues. */
			@Override
			public void close() {
				reset();
			}
			
			/** Resets the transmitter to initial state. Clears slots, send queue, buffers, and state variables. */
			protected void reset() {
				if( slot == null ) return; // No active slot to reset
				
				for( Slot s = slot; s != null; s = s.next ) s.src = null; // Release BytesSrc references in slots
				slot = null; // Detach active slot chain
				
				buffer     = null; // Release buffer reference
				mode       = OK; // Reset operational mode to OK
				u4         = 0; // Reset 4-byte value buffer
				bytes_left = 0; // Reset byte counter
			}
			
			/** Gets current position of the {@link #buffer} used for writing. */
			public int position() { return buffer.position(); }
			
			/** Gets remaining capacity in the {@link #buffer}. */
			public int remaining() { return buffer.remaining(); }
			
			/**
			 * Initializes null field tracking for transmission. Allocates 1 byte for the nulls bitmap.
			 *
			 * @param field0_bit Initial bitmask for null fields (e.g., if first field is known to be non-null).
			 * @param this_case  State to retry at if buffer allocation fails.
			 * @return True if successful, false if retry (buffer full).
			 */
			public boolean init_fields_nulls( int field0_bit, int this_case ) {
				if( !allocate( 1, this_case ) ) return false; // Retry if buffer allocation fails
				slot.fields_nulls = field0_bit; // Initialize null field flags in slot
				return true; // Null flags initialized successfully
			}
			
			/** Sets a specific field as non-null (sets corresponding bit) in current slot's {@code fields_nulls}. */
			public void set_fields_nulls( int field ) { slot.fields_nulls |= field; }
			
			/** Writes the accumulated null field bitmap (from {@code slot.fields_nulls}) to the buffer. */
			public void flush_fields_nulls() { put( ( byte ) slot.fields_nulls ); }
			
			/**
			 * Checks if a field is null (corresponding bit in {@code slot.fields_nulls} is 0).
			 * If null, transitions to {@code next_field_case} to skip writing this field.
			 *
			 * @param field           Bitmask for the field.
			 * @param next_field_case State to jump to if field is null.
			 * @return True if field is null (and state is set), false if not null (field should be written).
			 */
			public boolean is_null( int field, int next_field_case ) {
				if( ( slot.fields_nulls & field ) == 0 ) {
					slot.state = next_field_case; // Set next state if field is not null
					return true; // Indicate field is null
				}
				return false; // Indicate field is not null
			}
			
			/**
			 * Reads data from the sending queue and writes it to the output ByteBuffer {@code dst}.
			 * This is the main method for external callers to get transmittable bytes.
			 * Handles packet retrieval from queue, serialization via {@link Transmitter.BytesSrc#__get_bytes},
			 * state transitions, and invokes {@code on_sending}/{@code sent} events.
			 *
			 * @param dst ByteBuffer to write serialized and framed bytes to.
			 * @return Number of bytes written to {@code dst}. 0 if no space or no data. -1 if send queue empty and reset.
			 */
			@Override // From AdHoc.BytesSrc (this Transmitter can be a source for an outer layer)
			public int read( ByteBuffer dst ) {
				
				buffer = dst; // Set destination buffer
				final int fix = buffer.position(); // Store initial buffer position
read_loop:
				// Label for breaking out of the read loop
				{
					for( ; buffer.hasRemaining(); ) { // Loop while destination buffer has space
						// Active slot and source exist, process data based on mode
						if( slot == null || slot.src == null ) { // Check if no active slot or source
							
							u4 = 0;//used by value packs
							u8 = 0;
							final BytesSrc src = _OnSerializing(); // Get next BytesSrc from sending queue
							
							if( src == null ) {
								int ret = buffer.position() - fix; // Calculate bytes written
								this.reset(); // Reset transmitter if no more packets
								return 0 < ret ?
										ret :
										// Return bytes written if any
										-1; // Return -1 indicating no more packets
							}
							
							
							if( slot == null )
								if( ( slot = slot_ref.get() ) == null ) slot_ref = new SoftReference<>( slot = new Slot( this, null ) ); // Get or create new slot
							
							slot.src   = src; // Assign BytesSrc to slot
							slot.state = 0; // Set initial slot state (write ID request)
							bytes_left = 0; // Reset byte counter
							
							if( handler != null ) handler.OnSerializing( this, src ); // Notify event handler about sending start
							if( slot == null ) return -1; // Sending event handler has reset this, return error
						}
						else switch( mode ) //the packet transmission was interrupted, recall where we stopped
						{
							case STR: // String transmission state
								if( !varint() ) break read_loop; // Break and retry if VarInt write is incomplete (string length)
								if( u4 == -1 ) u4 = 0; //now ready getting string
								
								while( u4 < str.length() ) if( !varint( str.charAt( u4++ ) ) ) break read_loop; // Break and retry if VarInt write is incomplete (string char)
								
								str = null; // Clear string buffer after transmission
								break;
							case VAL4: // 4-byte value transmission state
								if( buffer.remaining() < bytes_left ) break read_loop; // Break and retry if not enough space in buffer
								put_val( u4, bytes_left ); // Write 4-byte value to buffer
								break;
							case VAL8: // 8-byte value transmission state
								if( buffer.remaining() < bytes_left ) break read_loop; // Break and retry if not enough space in buffer
								put_val( u8, bytes_left ); // Write 8-byte value to buffer
								break;
							case BITS_BYTES: // Bits with bytes transmission state
								if( buffer.remaining() < bits_transaction_bytes_ ) break read_loop;                //space for one full transaction
								bits_byte = buffer.position(); //preserve space for bits info
								buffer.position( bits_byte + 1 ); // Skip 1 byte for bits info
								put_val( u8, bytes_left ); // Write value bytes to buffer
								break;
							case VARINT: // VarInt transmission state
								if( varint() ) break; // Continue if VarInt write is successful
								break read_loop; // Break and retry if VarInt write is incomplete
							case BITS: // Bits transmission state
								if( buffer.remaining() < bits_transaction_bytes_ ) break read_loop;                //space for one full transaction
								bits_byte = buffer.position(); //preserve space for bits info
								buffer.position( bits_byte + 1 ); // Skip 1 byte for bits info
								break;
						}
						
						mode = OK; // Reset mode to OK after processing
dispatch_loop:
						// Label for dispatching loop
						for( ; ; )
							if( !slot.src.__get_bytes( this ) )
								break read_loop; // Data providing over for current BytesSrc, break read loop
							else {
								
								if( slot.prev == null ) break dispatch_loop; // No previous slot, break dispatch loop
								slot = slot.prev; // Move to previous slot in chain
							}
						_OnSerialized( slot.src );
						if( handler != null ) handler.OnSerialized( this, slot.src ); // Notify event handler about packet sent
						if( slot == null ) return -1;   // Sent event handler has reset this, return error
						slot.src = null; // Signal for next packet data request
					} //read loop
					
					if( slot != null && slot.src == null ) slot = null; // Reset slot if active but source is null (error state)
				}
				
				int ret = buffer.position() - fix; // Calculate bytes written
				buffer = null; // Release buffer reference
				
				return 0 < ret ?
						ret :
						// Return bytes written if any
						-1; // Return -1 if no bytes written in this call
			}
			
			/**
			 * Allocates specified number of bytes in the {@link #buffer}. Sets retry if allocation fails.
			 *
			 * @param bytes     Number of bytes to allocate.
			 * @param this_case State to retry at if buffer allocation fails.
			 * @return True if successful, false if retry (buffer full).
			 */
			public boolean allocate( int bytes, int this_case ) {
				slot.state = this_case; // Set slot state to specified case
				if( bytes <= buffer.remaining() ) return true; // Buffer allocation successful
				mode = RETRY; // Set mode to retry
				return false;
			}
			//#region bits
			
			/** Buffer position where current byte for bit accumulation is/will be stored. -1 if not active. */
			private int bits_byte = -1;
			/** Number of payload bytes associated with a bit transaction (for buffer allocation checks). */
			private int bits_transaction_bytes_;
			
			/**
			 * (Advanced) Initializes bit-level transmission assuming transaction_bytes includes space for bit-info byte AND payload.
			 * Used when bit-info byte is written AFTER payload bytes.
			 *
			 * @param transaction_bytes Total bytes for this bit transaction (bit-info byte + payload).
			 * @param this_case         State for retry if buffer allocation fails.
			 * @return True if successful, false if retry.
			 */
			public boolean init_bits_( int transaction_bytes, int this_case ) {
				//26 byte wost case 83: 3 bits x 3times x 8 bytes
				if( ( bits_transaction_bytes_ = transaction_bytes ) <= buffer.remaining() )
					return true; // Buffer allocation successful
				
				slot.state = this_case; // Set slot state to specified case
				buffer.position( bits_byte ); //trim byte at bits_byte index
				
				mode = BITS; // Set mode to bits transmission
				return false;
			}
			
			/**
			 * Initializes bit-level transmission. Reserves 1 byte for bit accumulation.
			 *
			 * @param transaction_bytes Bytes needed for payload that will follow bit fields (for allocation check).
			 * @param this_case         State for retry if buffer allocation fails.
			 * @return True if successful, false if retry.
			 */
			public boolean init_bits( int transaction_bytes, int this_case ) {
				if( buffer.remaining() < ( bits_transaction_bytes_ = transaction_bytes ) ) {
					slot.state = this_case; // Set slot state to specified case
					mode       = RETRY; // Set mode to retry
					return false;
				}
				
				bits = 0; // Reset bit buffer
				bit  = 0; // Reset bit position
				
				bits_byte = buffer.position(); //place fixation
				buffer.position( bits_byte + 1 ); // Skip 1 byte for bits info
				return true; // Bit initialization successful
			}
			
			/**
			 * Puts {@code len_bits} from LSB of {@code src} into the bit stream.
			 * Writes to buffer when a full byte is accumulated in {@link #bits}.
			 *
			 * @param src      Value containing bits to put.
			 * @param len_bits Number of bits to put (1-8).
			 */
			public void put_bits( int src, int len_bits ) {
				bits |= src << bit; // Accumulate bits into bit buffer
				//full. it is might be redundant
				if( ( bit += len_bits ) < 9 )
					return; //yes 9! not 8! to avoid allocating the next byte after the current one is
				
				buffer.put( bits_byte, ( byte ) bits ); //sending
				
				bits >>= 8; // Shift out processed byte
				bit -= 8;
				
				bits_byte = buffer.position(); // Set new bit byte position
				if( buffer.hasRemaining() ) buffer.position( bits_byte + 1 ); // Skip 1 byte for bits info if buffer has space
			}
			
			/**
			 * Puts bits, retrying if buffer space for next bit-byte becomes insufficient.
			 * {@code bits_payload_bytes_len} is used to check if remaining buffer can hold next bit-byte AND payload.
			 *
			 * @param src              Value with bits to put.
			 * @param len_bits         Number of bits (1-8).
			 * @param continue_at_case State for retry.
			 * @return True if successful, false if retry.
			 */
			public boolean put_bits( int src, int len_bits, int continue_at_case ) {
				bits |= src << bit; // Accumulate bits into bit buffer
				//full. it is might be redundant
				if( ( bit += len_bits ) < 9 )
					return true; //yes 9! not 8! to avoid allocating the next byte after the current one is
				
				buffer.put( bits_byte, ( byte ) bits ); //sending
				
				bits >>= 8; // Shift out processed byte
				bit -= 8;
				
				if( buffer.remaining() < bits_transaction_bytes_ ) {
					slot.state = continue_at_case; // Set slot state to retry case
					return false;
				}
				
				bits_byte = buffer.position(); // Set new bit byte position
				buffer.position( bits_byte + 1 ); // Skip 1 byte for bits info
				return true; // Bits put successfully
			}
			
			/** Finalizes bit-level transmission. Writes any remaining bits in {@link #bits} to {@code bits_byte_pos}. If no bits pending, may trim reserved byte. */
			public void end_bits() {
				if( 0 < bit ) buffer.put( bits_byte, ( byte ) bits ); // Write remaining bits to buffer
				else buffer.position( bits_byte ); //trim byte at bits_byte index. allocated, but not used
			}
			
			/**
			 * Puts {@code nulls_bits} representing {@code nulls} (e.g., for optional fields presence).
			 * Retries if buffer space insufficient.
			 *
			 * @param nulls            Value representing nulls pattern.
			 * @param nulls_bits       Number of bits for this value.
			 * @param continue_at_case State for retry.
			 * @return True if successful, false if retry.
			 */
			public boolean put_nulls( int nulls, int nulls_bits, int continue_at_case ) {
				if( put_bits( nulls, nulls_bits, continue_at_case ) ) return true; // Null bits put successfully
				
				mode = BITS; // Set mode to bits transmission
				return false;
			}
			
			/**
			 * Continues bit-level transmission at a specified state, trimming unused byte in buffer.
			 *
			 * @param continue_at_case State to transition to for continuation.
			 */
			public void continue_bits_at( int continue_at_case ) {
				slot.state = continue_at_case; // Set slot state to continuation case
				buffer.position( bits_byte ); //trim byte at bits_byte index
				mode = BITS; // Set mode to bits transmission
			}
			
			/** Puts a nullable Boolean: 00 for null, 01 for true, 10 for false (2 bits). */
			public void put( Boolean src ) {
				put_bits( src == null ?
						          0 :
						          // Null value
						          src ?
								          1
								          // True value
								          :
								          2, // False value
				          2 ); // Use 2 bits for nullable boolean
			}
			
			/** Puts a boolean: 0 for false, 1 for true (1 bit). */
			public void put( boolean src ) {
				put_bits( src ?
						          1 :
						          // True value
						          0, 1 ); // False value, Use 1 bit for boolean
			}
			//#endregion
			//#region varint
			
			/** Encodes {@code info} (using {@code info_bits}) followed by {@code value} (double, as long bits, using {@code value_bytes}). Retries if needed. */
			public boolean put_bits_bytes( int info, int info_bits, double value, int value_bytes, int continue_at_case ) { return put_bits_bytes( info, info_bits, Double.doubleToLongBits( value ), value_bytes, continue_at_case ); }
			
			/** Encodes {@code info} (using {@code info_bits}) followed by {@code value} (float, as int bits, using {@code value_bytes}). Retries if needed. */
			public boolean put_bits_bytes( int info, int info_bits, float value, int value_bytes, int continue_at_case ) { return put_bits_bytes( info, info_bits, Float.floatToIntBits( value ), value_bytes, continue_at_case ); }
			
			/**
			 * Core "bits-then-bytes" encoding. Puts {@code info} (using {@code info_bits}), then {@code value} (using {@code value_bytes}).
			 * Retries if buffer space is insufficient for bits or value.
			 *
			 * @param info             Info bits (e.g., length category).
			 * @param info_bits        Number of bits for {@code info}.
			 * @param value            The main value to write.
			 * @param value_bytes      Number of bytes for {@code value}.
			 * @param continue_at_case State for retry.
			 * @return True if successful, false if retry.
			 */
			public boolean put_bits_bytes( int info, int info_bits, long value, int value_bytes, int continue_at_case ) {
				if( put_bits( info, info_bits, continue_at_case ) ) {
					put_val( value, value_bytes ); // Write value bytes to buffer
					return true; // Value put successfully
				}
				
				u8         = value; // Store value for retry
				bytes_left = value_bytes; // Store value byte count for retry
				mode       = BITS_BYTES; // Set mode to bits bytes transmission
				return false;
			}
			
			/** Determines bytes needed for value up to 2^16-1: 1 for <256, 2 otherwise. */
			private static int bytes1( long src ) {
				return src < 1 << 8 ?
						1 :
						2;
			}
			
			/** Encodes {@code src_val} (max 2 bytes value) using 1 bit for length (0 for 1B, 1 for 2B) then value. Retries if needed. */
			public boolean put_varint21( long src, int continue_at_case ) {
				int bytes = bytes1( src ); // Get byte count for VarInt21 encoding
				return put_bits_bytes( bytes - 1, 1, src & 0xFFFFL, bytes, continue_at_case ); // Put VarInt21 encoded value
			}
			
			/**
			 * Puts a VarInt21 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt21 encoding uses 1 bit for byte count, nulls_bits for nulls, and 21 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param nulls_bits       Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint21( long src, int continue_at_case, int nulls, int nulls_bits ) {
				int bytes = bytes1( src ); // Get byte count for VarInt21 encoding
				return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 1, src & 0xFFFFL, bytes, continue_at_case ); // Put VarInt21 encoded value with nulls
			}
			
			/**
			 * Gets the number of bytes required to represent a value for VarInt32 encoding (1 to 3 bytes).
			 *
			 * @param src Value to check.
			 * @return 1 if value fits in 1 byte, 2 if it fits in 2 bytes, 3 if it fits in 3 bytes.
			 */
			private static int bytes2( long src ) {
				return src < 1 << 8 ?
						1 :
						// 1 byte if value < 256
						src < 1 << 16 ?
								2 :
								// 2 bytes if value < 65536
								3; // 3 bytes otherwise
			}
			
			/**
			 * Puts a VarInt32 encoded value, retrying if buffer space is insufficient.
			 * VarInt32 encoding uses 2 bits for byte count and 32 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint32( long src, int continue_at_case ) {
				int bytes = bytes2( src ); // Get byte count for VarInt32 encoding
				return put_bits_bytes( bytes, 2, src & 0xFFFF_FFL, bytes, continue_at_case ); // Put VarInt32 encoded value
			}
			
			/**
			 * Puts a VarInt32 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt32 encoding uses 2 bits for byte count, nulls_bits for nulls, and 32 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param nulls_bits       Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint32( long src, int continue_at_case, int nulls, int nulls_bits ) {
				
				int bytes = bytes2( src ); // Get byte count for VarInt32 encoding
				return put_bits_bytes( bytes << nulls_bits | nulls, nulls_bits + 2, src & 0xFFFF_FFL, bytes, continue_at_case ); // Put VarInt32 encoded value with nulls
			}
			
			/**
			 * Gets the number of bytes required to represent a value for VarInt42 encoding (1 to 4 bytes).
			 *
			 * @param src Value to check.
			 * @return 1 if value fits in 1 byte, 2 if it fits in 2 bytes, 3 if it fits in 3 bytes, 4 if it fits in 4 bytes.
			 */
			private static int bytes3( long src ) {
				return src < 1L << 16 ?
						src < 1L << 8 ?
								1 :
								// 1 byte if value < 256
								2 :
						// 2 bytes if value < 65536
						src < 1L << 24 ?
								3 :
								// 3 bytes if value < 16777216
								4; // 4 bytes otherwise
			}
			
			/**
			 * Puts a VarInt42 encoded value, retrying if buffer space is insufficient.
			 * VarInt42 encoding uses 2 bits for byte count and 42 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint42( long src, int continue_at_case ) {
				int bytes = bytes3( src ); // Get byte count for VarInt42 encoding
				return put_bits_bytes( bytes - 1, 2, src & 0xFFFF_FFFFL, bytes, continue_at_case ); // Put VarInt42 encoded value
			}
			
			/**
			 * Puts a VarInt42 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt42 encoding uses 2 bits for byte count, nulls_bits for nulls, and 42 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param nulls_bits       Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint42( long src, int continue_at_case, int nulls, int nulls_bits ) {
				int bytes = bytes3( src ); // Get byte count for VarInt42 encoding
				return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 2, src & 0xFFFF_FFFFL, bytes, continue_at_case ); // Put VarInt42 encoded value with nulls
			}
			
			/**
			 * Gets the number of bytes required to represent a value for VarInt73 encoding (1 to 7 bytes).
			 *
			 * @param src Value to check.
			 * @return 1 if value fits in 1 byte, 2 if it fits in 2 bytes, ..., 7 if it fits in 7 bytes.
			 */
			private static int bytes4( long src ) {
				return src < 1 << 24 ?
						src < 1 << 16 ?
								src < 1 << 8 ?
										1 :
										// 1 byte if value < 256
										2 :
								// 2 bytes if value < 65536
								3 :
						// 3 bytes if value < 16777216
						src < 1L << 32 ?
								4 :
								// 4 bytes if value < 4294967296
								src < 1L << 40 ?
										5 :
										// 5 bytes if value < 1099511627776
										src < 1L << 48 ?
												6 :
												// 6 bytes if value < 281474976710656
												7; // 7 bytes otherwise
			}
			
			/**
			 * Puts a VarInt73 encoded value, retrying if buffer space is insufficient.
			 * VarInt73 encoding uses 3 bits for byte count and 73 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint73( long src, int continue_at_case ) {
				int bytes = bytes4( src ); // Get byte count for VarInt73 encoding
				
				return put_bits_bytes( bytes, 3, src, bytes, continue_at_case ); // Put VarInt73 encoded value
			}
			
			/**
			 * Puts a VarInt73 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt73 encoding uses 3 bits for byte count, bits for nulls, and 73 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param bits             Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint73( long src, int continue_at_case, int nulls, int bits ) {
				int bytes = bytes4( src ); // Get byte count for VarInt73 encoding
				
				return put_bits_bytes( bytes << bits | nulls, bits + 3, src, bytes, continue_at_case ); // Put VarInt73 encoded value with nulls
			}
			
			/**
			 * Gets the number of bytes required to represent a value for VarInt83 encoding (1 to 8 bytes).
			 *
			 * @param src Value to check.
			 * @return 1 if value fits in 1 byte, 2 if it fits in 2 bytes, ..., 8 if it fits in 8 bytes.
			 */
			private static int bytes5( long src ) {
				return src < 0 ?
						8 :
						// 8 bytes if value is negative (full long)
						src < 1L << 32 ?
								src < 1 << 16 ?
										src < 1 << 8 ?
												1 :
												// 1 byte if value < 256
												2 :
										// 2 bytes if value < 65536
										src < 1 << 24 ?
												3 :
												// 3 bytes if value < 16777216
												4
								// 4 bytes if value < 4294967296
								:
								src < 1L << 48 ?
										src < 1L << 40 ?
												5 :
												// 5 bytes if value < 1099511627776
												6
										// 6 bytes if value < 281474976710656
										:
										src < 1L << 56 ?
												7 :
												// 7 bytes if value < 72057594037927936
												8; // 8 bytes otherwise
			}
			
			/**
			 * Puts a VarInt83 encoded value, retrying if buffer space is insufficient.
			 * VarInt83 encoding uses 3 bits for byte count and 83 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint83( long src, int continue_at_case ) {
				int bytes = bytes5( src ); // Get byte count for VarInt83 encoding
				return put_bits_bytes( bytes - 1, 3, src, bytes, continue_at_case ); // Put VarInt83 encoded value
			}
			
			/**
			 * Puts a VarInt83 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt83 encoding uses 3 bits for byte count, nulls_bits for nulls, and 83 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param nulls_bits       Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint83( long src, int continue_at_case, int nulls, int nulls_bits ) {
				int bytes = bytes5( src ); // Get byte count for VarInt83 encoding
				return put_bits_bytes( bytes - 1 << nulls_bits | nulls, nulls_bits + 3, src, bytes, continue_at_case ); // Put VarInt83 encoded value with nulls
			}
			
			/**
			 * Puts a VarInt84 encoded value, retrying if buffer space is insufficient.
			 * VarInt84 encoding uses 4 bits for byte count and 84 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint84( long src, int continue_at_case ) {
				int bytes = bytes5( src ); // Get byte count for VarInt84 encoding
				return put_bits_bytes( bytes, 4, src, bytes, continue_at_case ); // Put VarInt84 encoded value
			}
			
			/**
			 * Puts a VarInt84 encoded value with nulls, retrying if buffer space is insufficient.
			 * VarInt84 encoding uses 4 bits for byte count, nulls_bits for nulls, and 84 bits for value.
			 *
			 * @param src              Value to encode and put.
			 * @param continue_at_case State to transition to if buffer space is insufficient.
			 * @param nulls            Number of nulls to put.
			 * @param nulls_bits       Number of bits to represent nulls value.
			 * @return Result of put_bits_bytes operation.
			 */
			public boolean put_varint84( long src, int continue_at_case, int nulls, int nulls_bits ) {
				int bytes = bytes5( src ); // Get byte count for VarInt84 encoding
				return put_bits_bytes( bytes << nulls_bits | nulls, nulls_bits + 4, src, bytes, continue_at_case ); // Put VarInt84 encoded value with nulls
			}
			
			/**
			 * Puts a VarInt encoded long value, retrying if buffer space is insufficient.
			 * Standard VarInt encoding, using continuation bit.
			 *
			 * @param src       Long value to encode and put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of varint(long) operation.
			 */
			public boolean put_varint( long src, int next_case ) {
				
				if( varint( src ) ) return true; // VarInt put successfully
				
				slot.state = next_case; // Set slot state to retry case
				mode       = VARINT; // Set mode to VarInt transmission
				return false;
			}
			
			/**
			 * Puts the current u8 value as VarInt, retrying if buffer space is insufficient.
			 *
			 * @return Result of varint() operation.
			 */
			private boolean varint() { return varint( u8_ ); }
			
			/**
			 * Puts a VarInt encoded long value into the buffer.
			 * Standard VarInt encoding, using continuation bit.
			 *
			 * @param src Long value to encode and put.
			 * @return True if VarInt is put completely, false otherwise.
			 */
			private boolean varint( long src ) {
				
				// Loop until VarInt is complete or buffer is full
				for( ; buffer.hasRemaining(); buffer.put( ( byte ) ( 0x80 | src ) ), src >>>= 7 )
					if( ( src & 0x7F ) == src ) {
						buffer.put( ( byte ) src ); // Put last byte of VarInt
						return true; // VarInt put completely
					}
				u8_ = src; // Store remaining value for retry
				return false; // VarInt put incomplete
			}
			
			/**
			 * Encodes a zig-zag encoded long value for efficient representation of signed integers.
			 *
			 * @param src   Signed long value to encode.
			 * @param right Number of right shifts for zig-zag encoding.
			 * @return Zig-zag encoded long value.
			 */
			public static long zig_zag( long src, int right ) { return src << 1 ^ src >> right; }
			//#endregion
			
			/**
			 * Puts a long value to the buffer with a specified number of bytes, retrying if buffer space is insufficient.
			 *
			 * @param src       Long value to put.
			 * @param bytes     Number of bytes to use for putting the value (1-8).
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return True if value is put successfully, false otherwise and retry state is set.
			 */
			public boolean put_val( long src, int bytes, int next_case ) {
				if( buffer.remaining() < bytes ) {
					put( src, bytes, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put_val( src, bytes ); // Put value to buffer
				return true; // Value put successfully
			}
			
			/**
			 * Puts a long value to the buffer with a specified number of bytes.
			 *
			 * @param src   Long value to put.
			 * @param bytes Number of bytes to use for putting the value (1-8).
			 */
			public void put_val( long src, int bytes ) {
				int pos   = buffer.position();
				int limit = buffer.limit();
				if( pos + 8 <= limit ) {
					buffer.putLong( pos, src );
					buffer.position( pos + bytes );
					return;
				}
				
				switch( bytes ) {
					
					case 7:
						buffer.putInt( ( int ) src ); // Put lower 4 bytes as int
						buffer.putShort( ( short ) ( src >> 32 ) ); // Put next 2 bytes as short
						buffer.put( ( byte ) ( src >> 48 ) ); // Put remaining 1 byte
						return;
					case 6:
						buffer.putInt( ( int ) src ); // Put lower 4 bytes as int
						buffer.putShort( ( short ) ( src >> 32 ) ); // Put remaining 2 bytes as short
						return;
					case 5:
						buffer.putInt( ( int ) src ); // Put lower 4 bytes as int
						buffer.put( ( byte ) ( src >> 32 ) ); // Put remaining 1 byte
						return;
					case 4:
						buffer.putInt( ( int ) src ); // Put 4 bytes as int
						return;
					case 3:
						buffer.putShort( ( short ) src ); // Put lower 2 bytes as short
						buffer.put( ( byte ) ( src >> 16 ) ); // Put remaining 1 byte
						return;
					case 2:
						buffer.putShort( ( short ) src ); // Put 2 bytes as short
						return;
					case 1:
						buffer.put( ( byte ) src ); // Put 1 byte
				}
			}
			
			/**
			 * Puts an int value to the buffer with a specified number of bytes, retrying if buffer space is insufficient.
			 *
			 * @param src       Int value to put.
			 * @param bytes     Number of bytes to use for putting the value (1-4).
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return True if value is put successfully, false otherwise and retry state is set.
			 */
			public boolean put_val( int src, int bytes, int next_case ) {
				if( buffer.remaining() < bytes ) {
					put( src, bytes, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put_val( src, bytes );
				return true;
			}
			
			/**
			 * Puts an int value to the buffer with a specified number of bytes.
			 *
			 * @param src   Int value to put.
			 * @param bytes Number of bytes to use for putting the value (1-4).
			 */
			public void put_val( int src, int bytes ) {
				int pos   = buffer.position();
				int limit = buffer.limit();
				if( pos + 4 <= limit ) {
					buffer.putInt( pos, src );
					buffer.position( pos + bytes );
					return;
				}
				
				switch( bytes ) {
					case 4:
						buffer.putInt( ( int ) src ); // Put 4 bytes as int
						return;
					case 3:
						buffer.putShort( ( short ) src ); // Put lower 2 bytes as short
						buffer.put( ( byte ) ( src >> 16 ) ); // Put remaining 1 byte
						return;
					case 2:
						buffer.putShort( ( short ) src ); // Put 2 bytes as short
						return;
					case 1:
						buffer.put( ( byte ) src ); // Put 1 byte
				}
			}
			
			/**
			 * Puts a string value to the buffer using VarInt encoding for length and characters, retrying if buffer space is insufficient.
			 *
			 * @param src       String value to put.
			 * @param next_case State to transition to if buffer space is insufficient during string put.
			 * @return Result of varint(String) operation.
			 */
			public boolean put( String src, int next_case ) {
put_loop:
				// Label for breaking out of the put loop
				{
					u4 = -1; //indicate state before string length send
					if( !varint( src.length() ) )
						break put_loop; // Break and retry if VarInt write is incomplete (string length)
					u4 = 0; //indicate state after string length sent
					
					while( u4 < src.length() ) if( !varint( src.charAt( u4++ ) ) )
						break put_loop; // Break and retry if VarInt write is incomplete (string char)
					return true; // String put successfully
				}
				
				slot.state = next_case; //switch to sending internally
				str        = src; // Store string for retry
				mode       = STR; // Set mode to string transmission
				return false;
			}
			
			/**
			 * Sets retry state for 4-byte value transmission and initializes state variables.
			 *
			 * @param src       4-byte value to put.
			 * @param bytes     Number of bytes to use (4).
			 * @param next_case State to transition to for retry operation.
			 */
			private void put( int src, int bytes, int next_case ) {
				slot.state = next_case; // Set slot state to retry case
				bytes_left = bytes; // Set bytes_left to number of bytes to put
				u4         = src; // Store value to put in u4
				mode       = VAL4; // Set mode to 4-byte value transmission
			}
			
			/**
			 * Sets retry state for 8-byte value transmission and initializes state variables.
			 *
			 * @param src       8-byte value to put.
			 * @param bytes     Number of bytes to use (8).
			 * @param next_case State to transition to for retry operation.
			 */
			private void put( long src, int bytes, int next_case ) {
				slot.state = next_case; // Set slot state to retry case
				bytes_left = bytes; // Set bytes_left to number of bytes to put
				u8         = src; // Store value to put in u8
				mode       = VAL8; // Set mode to 8-byte value transmission
			}
			
			/**
			 * Sets retry state for transmission at a specified state.
			 *
			 * @param the_case State to retry at.
			 */
			public void retry_at( int the_case ) {
				slot.state = the_case; // Set slot state to retry case
				mode       = RETRY; // Set mode to retry
			}
			
			
			/**
			 * Puts a boolean value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Boolean value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of put(byte, int) operation.
			 */
			public boolean put( boolean src, int next_case ) {
				return put( src ?
						            ( byte ) 1 :
						            // Byte value for true
						            0, next_case ); // Byte value for false
			}
			
			/**
			 * Puts a byte value to the buffer.
			 *
			 * @param src Byte value to put.
			 */
			public void put( byte src ) { buffer.put( src ); }
			
			/**
			 * Puts a byte value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Byte value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of allocate(int, int) and put(byte) operations.
			 */
			public boolean put( byte src, int next_case ) {
				if( buffer.hasRemaining() ) {
					put( src ); // Put byte to buffer if space available
					return true; // Byte put successfully
				}
				
				put( src, 1, next_case ); // Retry if not enough buffer space
				return false;
			}
			
			public int put( byte[] src, int src_byte, int src_bytes, int retry_case ) {
				
				int r = buffer.remaining();
				if( r < src_byte ) {
					src_bytes = r;
					retry_at( retry_case );
				}
				buffer.put( src, src_byte, src_bytes );
				return src_bytes;
			}
			
			/**
			 * Puts a short value to the buffer.
			 *
			 * @param src Short value to put.
			 */
			public void put( short src ) { buffer.putShort( src ); }
			
			/**
			 * Puts a short value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Short value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of allocate(int, int) and put(short) operations.
			 */
			public boolean put( short src, int next_case ) {
				if( buffer.remaining() < 2 ) {
					put( src, 2, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put( src ); // Put short to buffer if space available
				return true; // Short put successfully
			}
			
			
			/**
			 * Puts a char value to the buffer.
			 *
			 * @param src Char value to put.
			 */
			public void put( char src ) { buffer.putChar( src ); }
			
			/**
			 * Puts a char value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Char value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of allocate(int, int) and put(char) operations.
			 */
			public boolean put( char src, int next_case ) {
				if( buffer.remaining() < 2 ) {
					put( src, 2, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put( src ); // Put char to buffer if space available
				return true; // Char put successfully
			}
			
			
			/**
			 * Puts an int value to the buffer.
			 *
			 * @param src Int value to put.
			 */
			public void put( int src ) { buffer.putInt( src ); }
			
			/**
			 * Puts an int value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Int value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of allocate(int, int) and put(int) operations.
			 */
			public boolean put( int src, int next_case ) {
				if( buffer.remaining() < 4 ) {
					put( src, 4, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put( src ); // Put int to buffer if space available
				return true; // Int put successfully
			}
			
			
			/**
			 * Puts a long value to the buffer.
			 *
			 * @param src Long value to put.
			 */
			public void put( long src ) { buffer.putLong( src ); }
			
			/**
			 * Puts a long value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Long value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of allocate(int, int) and put(long) operations.
			 */
			public boolean put( long src, int next_case ) {
				if( buffer.remaining() < 8 ) {
					put( src, 8, next_case ); // Retry if not enough buffer space
					return false;
				}
				
				put( src ); // Put long to buffer if space available
				return true; // Long put successfully
			}
			
			
			/**
			 * Puts a float value to the buffer.
			 *
			 * @param src Float value to put.
			 */
			public void put( float src ) { buffer.putFloat( src ); }
			
			/**
			 * Puts a float value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Float value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of put(int, int) operation, using float bits representation.
			 */
			public boolean put( float src, int next_case ) { return put( Float.floatToIntBits( src ), next_case ); }
			
			/**
			 * Puts a double value to the buffer.
			 *
			 * @param src Double value to put.
			 */
			public void put( double src ) { buffer.putDouble( src ); }
			
			/**
			 * Puts a double value to the buffer, retrying if buffer space is insufficient.
			 *
			 * @param src       Double value to put.
			 * @param next_case State to transition to if buffer space is insufficient.
			 * @return Result of put(long, int) operation, using double bits representation.
			 */
			public boolean put( double src, int next_case ) { return put( Double.doubleToLongBits( src ), next_case ); }
			
			/**
			 * Returns a string representation of the Transmitter, including its class name and slot chain state.
			 * Used for debugging and logging.
			 *
			 * @return String representation of the Transmitter and its state.
			 */
			@Override
			public String toString() {
				if( slot == null ) return super.toString() + " \uD83D\uDCA4 "; // Indicate idle state with emoji
				Slot s = slot;
				while( s.prev != null ) s = s.prev; // Get to the head of the slot chain
				StringBuilder str    = new StringBuilder( super.toString() + "\n" ); // Initialize string builder
				String        offset = ""; // Initialize offset for indentation
				for( ; s != slot; s = s.next, offset += "\t" ) str.append( offset ).append( s.src.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" ); // Append slot info with indentation
				
				str.append( offset ).append( s.src.getClass().getCanonicalName() ).append( "\t" ).append( s.state ).append( "\n" ); // Append current slot info
				
				return str.toString(); // Return string representation
			}
		}
	}
	
	/**
	 * Generic object pool using {@link SoftReference} to hold the list of pooled items.
	 * This allows the pool itself to be garbage collected under memory pressure.
	 *
	 * @param <T> Type of objects in the pool.
	 */
	public static class Pool< T > {
		
		/**
		 * Soft reference to an ArrayList holding pooled objects.
		 * SoftReference allows garbage collection of the list when memory is low.
		 */
		private SoftReference< ArrayList< T > > list = new SoftReference<>( new ArrayList<>( 3 ) );
		/**
		 * Supplier for creating new objects when the pool is empty.
		 */
		final   Supplier< T >                   factory;
		
		/**
		 * Constructor for Pool.
		 *
		 * @param factory Supplier for creating new objects.
		 */
		public Pool( Supplier< T > factory ) { this.factory = factory; }
		
		/**
		 * Gets an object from the pool. If the pool is empty, creates a new object using the factory.
		 *
		 * @return An object from the pool or a new object if the pool is empty.
		 */
		public T get() {
			ArrayList< T > list = this.list.get(); // Get object list from soft reference
			return list == null || list.isEmpty() ?
					factory.get() :
					// Create new object if pool is empty
					list.remove( list.size() - 1 ); // Remove and return object from pool
		}
		
		/**
		 * Puts an object back into the pool for reuse.
		 *
		 * @param item Object to put back into the pool.
		 */
		public void put( T item ) {
			ArrayList< T > list = this.list.get(); // Get object list from soft reference
			if( list == null ) this.list = new SoftReference<>( list = new ArrayList<>( 3 ) ); // Create new list if soft reference is null
			
			list.add( item ); // Add object back to the pool
		}
	}
	
	/**
	 * Flag indicating debug mode, enabled if JVM is running with JDWP (Java Debug Wire Protocol).
	 */
	public static final boolean debug_mode = java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments().toString().indexOf( "jdwp" ) > 0;
	
	/**
	 * Utility class for printing stack traces to a string without console output.
	 * Extends PrintStream and overrides methods to capture stack trace output into a StringBuilder.
	 */
	public static final class StackTracePrinter extends PrintStream {
		/**
		 * Private constructor to prevent external instantiation.
		 */
		private StackTracePrinter() {
			super( new OutputStream() {
				@Override
				public void write( int b ) throws IOException { } // Dummy OutputStream to discard output
			} );
		}
		
		/**
		 * Atomic reference to a Thread, used as a lock for thread-safe StringBuilder access.
		 */
		private AtomicReference< Thread > lock = new AtomicReference<>( null );
		/**
		 * StringBuilder to store the captured stack trace string.
		 */
		private StringBuilder             sb   = new StringBuilder();
		
		/**
		 * Appends a CharSequence to the StringBuilder, followed by a newline.
		 *
		 * @param csq CharSequence to append.
		 * @return This PrintStream instance.
		 */
		@Override
		public PrintStream append( CharSequence csq ) {
			sb.append( csq ); // Append CharSequence to StringBuilder
			sb.append( '\n' ); // Append newline
			return this; // Return this PrintStream instance
		}
		
		/**
		 * Appends a subsequence of a CharSequence to the StringBuilder, followed by a newline.
		 *
		 * @param csq   CharSequence to append from.
		 * @param start Start index of subsequence.
		 * @param end   End index of subsequence.
		 * @return This PrintStream instance.
		 */
		@Override
		public PrintStream append( CharSequence csq, int start, int end ) {
			sb.append( csq, start, end ); // Append subsequence to StringBuilder
			sb.append( '\n' ); // Append newline
			return this; // Return this PrintStream instance
		}
		
		/**
		 * Prints an Object to the StringBuilder, followed by a newline.
		 *
		 * @param obj Object to print.
		 */
		@Override
		public void println( Object obj ) { sb.append( obj ).append( '\n' ); }
		
		/**
		 * Captures the stack trace of a Throwable as a string.
		 * Uses a lock to ensure thread-safe access to the StringBuilder.
		 *
		 * @param e Throwable exception to print stack trace for.
		 * @return Stack trace as a string.
		 */
		String stackTrace( Throwable e ) {
			while( !lock.compareAndSet( null, Thread.currentThread() ) ) Thread.onSpinWait(); // Acquire lock using atomic operation with spin wait
			e.printStackTrace( this ); // Print stack trace to this PrintStream (StringBuilder)
			String ret = sb.toString(); // Get stack trace string from StringBuilder
			sb.setLength( 0 ); // Clear StringBuilder for next use
			lock.set( null ); // Release lock
			return ret; // Return stack trace string
		}
		
		/**
		 * Singleton instance of StackTracePrinter.
		 */
		public static final StackTracePrinter ONE = new StackTracePrinter();
	}
	
	/**
	 * Implements CharSequence interface over a byte array.
	 * Allows treating byte arrays as character sequences for text processing, e.g., regex.
	 */
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
		/**
		 * Byte array backing the CharSequence.
		 */
		public byte[] bytes;
		/**
		 * Length of the CharSequence view over the byte array.
		 */
		public int    length;
		/**
		 * Offset in the byte array for the CharSequence view.
		 */
		public int    offset;
		
		/**
		 * Constructor for BytesAsCharSequence, using the entire byte array as the sequence.
		 *
		 * @param bytes Byte array to wrap.
		 */
		public BytesAsCharSequence( byte[] bytes ) { this( bytes, 0, bytes.length ); }
		
		/**
		 * Constructor for BytesAsCharSequence, using a portion of the byte array as the sequence.
		 *
		 * @param bytes  Byte array to wrap.
		 * @param offset Starting offset in the byte array.
		 * @param length Length of the sequence view.
		 */
		public BytesAsCharSequence( byte[] bytes, int offset, int length ) { set( bytes, offset, length ); }
		
		/**
		 * Sets the underlying byte array and the view parameters (offset, length).
		 *
		 * @param bytes  Byte array to use.
		 * @param offset Starting offset in the byte array.
		 * @param length Length of the sequence view.
		 */
		public void set( byte[] bytes, int offset, int length ) {
			this.bytes  = bytes; // Set byte array
			this.offset = offset; // Set offset
			this.length = length; // Set length
		}
		
		/**
		 * Gets the length of the CharSequence.
		 *
		 * @return Length of the sequence view.
		 */
		@Override
		public int length() { return length; }
		
		/**
		 * Gets the character at a specified index.
		 *
		 * @param index Index of the character to get.
		 * @return Character at the specified index, as an unsigned byte converted to char.
		 */
		@Override
		public char charAt( int index ) { return ( char ) ( bytes[ offset + index ] & 0xff ); }
		
		/**
		 * Gets a subsequence of this CharSequence.
		 *
		 * @param start Start index of subsequence.
		 * @param end   End index of subsequence.
		 * @return New BytesAsCharSequence instance representing the subsequence.
		 */
		@Override
		public CharSequence subSequence( int start, int end ) { return new BytesAsCharSequence( bytes, offset + start, end - start ); }
	}
	
	/**
	 * Annotation interface for unsigned long operations.
	 * Provides utility methods for working with unsigned 64-bit integers in Java.
	 * <p>
	 * The unsigned long value range is from 0 to 2^64-1 (18,446,744,073,709,551,615),
	 * while signed long range is from -2^63 to 2^63-1 (-9,223,372,036,854,775,808 to 9,223,372,036,854,775,807).
	 */
	@Target( ElementType.TYPE_USE )
	public @interface ULong {
		/**
		 * Interface containing static utility methods for unsigned long operations.
		 * All operations treat input values as unsigned, even though they're stored in signed long variables.
		 */
		interface Val {
			
			//  -1
			//   ↑
			//Long.MIN_VALUE
			//   ↑
			//Long.MAX_VALUE
			//   ↑
			//   0
			
			/**
			 * Maximum value for unsigned long (2^64-1), represented as -1L in signed long.
			 */
			long MAX_VALUE = -1L; // All bits set to 1
			
			/**
			 * Minimum value for unsigned long (0), same as signed long minimum.
			 */
			long MIN_VALUE = 0L;
			
			/**
			 * Divides two unsigned long values.
			 *
			 * @param dividend Unsigned long dividend.
			 * @param divisor  Unsigned long divisor.
			 * @return Unsigned long quotient.
			 */
			static long divide( long dividend, long divisor ) { return Long.divideUnsigned( dividend, divisor ); }
			
			/**
			 * Gets the remainder of unsigned long division.
			 *
			 * @param dividend Unsigned long dividend.
			 * @param divisor  Unsigned long divisor.
			 * @return Unsigned long remainder.
			 */
			static long remainder( long dividend, long divisor ) { return Long.remainderUnsigned( dividend, divisor ); }
			
			/**
			 * Parses an unsigned long from a string in base 10.
			 *
			 * @param string String representation of unsigned long.
			 * @return Parsed unsigned long value.
			 */
			static long parse( String string ) { return Long.parseUnsignedLong( string, 10 ); }
			
			/**
			 * Parses an unsigned long from a string in a specified radix (base).
			 *
			 * @param string String representation of unsigned long.
			 * @param radix  Radix (base) for parsing.
			 * @return Parsed unsigned long value.
			 */
			static long parse( String string, int radix ) { return Long.parseUnsignedLong( string, radix ); }
			
			/**
			 * Compares two unsigned long values.
			 *
			 * @param if_bigger_plus  First unsigned long value.
			 * @param if_bigger_minus Second unsigned long value.
			 * @return 0 if equal, positive if first is greater, negative if second is greater (unsigned comparison).
			 */
			static int compare( long if_bigger_plus, long if_bigger_minus ) { return Long.compareUnsigned( if_bigger_plus, if_bigger_minus ); }
			
			/**
			 * Converts an unsigned long value to its string representation in base 10.
			 *
			 * @param value Unsigned long value to convert.
			 * @return String representation of unsigned long.
			 */
			static String toString( long value ) { return toString( value, 10 ); }
			
			/**
			 * Converts an unsigned long value to its string representation in a specified radix (base).
			 * Efficiently handles unsigned long to string conversion, especially for large values.
			 *
			 * @param ulong Unsigned long value to convert.
			 * @param radix Radix (base) for conversion.
			 * @return String representation of unsigned long in the specified radix.
			 */
			static String toString( long ulong, int radix ) { //This is the most efficient way to get a string of an unsigned long in Java.
				
				if( 0 <= ulong ) return Long.toString( ulong, radix ); // Use standard Long.toString for positive longs
				final long quotient = ( ulong >>> 1 ) / radix << 1; // Efficient quotient calculation
				final long rem      = ulong - quotient * radix; // Remainder calculation
				return rem < radix ?
						Long.toString( quotient, radix ) + Long.toString( rem, radix ) :
						// Combine quotient and remainder strings
						Long.toString( quotient + 1, radix ) + Long.toString( rem - radix, radix ); // Handle remainder overflow
			}
		}
	}
	
	/**
	 * Annotation interface for nullable boolean values.
	 * Provides utility methods for working with nullable booleans, represented by long values.
	 */
	@Target( ElementType.TYPE_USE ) @interface NullableBool {
		/**
		 * Interface containing static utility methods for nullable boolean values.
		 */
		interface value {
			/**
			 * Checks if a nullable boolean value has a value (not NULL).
			 *
			 * @param src Nullable boolean value to check.
			 * @return True if value is not NULL, false otherwise.
			 */
			static boolean hasValue( @NullableBool long src ) { return src != NULL; }
			
			/**
			 * Gets the boolean value from a nullable boolean.
			 * Assumes that hasValue(src) is true before calling this method.
			 *
			 * @param src Nullable boolean value to get boolean from.
			 * @return Boolean value (true if src == 1, false if src == 0).
			 */
			static boolean get( @NullableBool long src ) { return src == 1; }
			
			/**
			 * Sets a boolean value to a nullable boolean representation.
			 *
			 * @param src Boolean value to set.
			 * @return Nullable boolean representation (1 for true, 0 for false).
			 */
			static @NullableBool
			byte set( boolean src ) {
				return src ?
						( byte ) 1 :
						// Byte value for true
						( byte ) 0; // Byte value for false
			}
			
			/**
			 * Gets the NULL representation for nullable boolean.
			 *
			 * @return NULL value for nullable boolean.
			 */
			static @NullableBool
			long to_null() { return NULL; }
		}
		
		/**
		 * Constant representing the NULL value for nullable boolean, encoded as 2L.
		 */
		@NullableBool
		long NULL = 2;
	}
	
	/**
	 * Decoding table for base64 characters to byte values.
	 */
	private static final byte[] char2byte = new byte[ 256 ];
	
	static {
		for( int i = 'A'; i <= 'Z'; i++ ) char2byte[ i ] = ( byte ) ( i - 'A' ); // Decode A-Z to 0-25
		for( int i = 'a'; i <= 'z'; i++ ) char2byte[ i ] = ( byte ) ( i - 'a' + 26 ); // Decode a-z to 26-51
		for( int i = '0'; i <= '9'; i++ ) char2byte[ i ] = ( byte ) ( i - '0' + 52 ); // Decode 0-9 to 52-61
		char2byte[ '+' ] = 62; // Decode '+' to 62
		char2byte[ '/' ] = 63; // Decode '/' to 63
	}
	
	/**
	 * Decodes base64 encoded bytes in place within a byte array.
	 *
	 * @param bytes    The byte array containing base64 encoded data.
	 * @param srcIndex The starting index in the source array for decoding.
	 * @param dstIndex The starting index in the destination array to write decoded bytes.
	 * @param len      The length of the base64 encoded data to decode.
	 * @return The length of the decoded bytes written to the destination array.
	 */
	public static int base64decode( byte[] bytes, int srcIndex, int dstIndex, int len ) {
		int max = srcIndex + len; // Calculate end index
		
		//Adjust the length for padding characters
		while( bytes[ max - 1 ] == '=' ) max--; // Decrement max index if padding character '=' found
		
		int newLen = max - srcIndex; // Calculate new length without padding
		for( int i = newLen >> 2; i > 0; i-- ) { //Process full 4-character blocks
			int b = char2byte[ bytes[ srcIndex++ ] ] << 18 | // Decode 1st character and shift
			        char2byte[ bytes[ srcIndex++ ] ] << 12 | // Decode 2nd character and shift
			        char2byte[ bytes[ srcIndex++ ] ] << 6 | // Decode 3rd character and shift
			        char2byte[ bytes[ srcIndex++ ] ]; // Decode 4th character
			
			bytes[ dstIndex++ ] = ( byte ) ( b >> 16 ); // Extract 1st byte from combined value
			bytes[ dstIndex++ ] = ( byte ) ( b >> 8 ); // Extract 2nd byte from combined value
			bytes[ dstIndex++ ] = ( byte ) b; // Extract 3rd byte from combined value
		}
		
		switch( newLen & 3 ) {
			case 3:
				//If there are 3 characters remaining, decode them into 2 bytes
				int b = char2byte[ bytes[ srcIndex++ ] ] << 12 | // Decode 1st character and shift
				        char2byte[ bytes[ srcIndex++ ] ] << 6 | // Decode 2nd character and shift
				        char2byte[ bytes[ srcIndex ] ]; // Decode 3rd character
				bytes[ dstIndex++ ] = ( byte ) ( b >> 10 ); //Extract first byte
				bytes[ dstIndex++ ] = ( byte ) ( b >> 2 );  //Extract second byte
				break;
			case 2:
				//If there are 2 characters remaining, decode them into 1 byte
				bytes[ dstIndex++ ] = ( byte ) ( ( char2byte[ bytes[ srcIndex++ ] ] << 6 | char2byte[ bytes[ srcIndex ] ] ) >> 4 ); // Decode 2 characters into 1 byte
				break;
		}
		
		return dstIndex; // Return index in destination array after decoding
	}
	
	/**
	 * Creates a DNS TXT record request for a given domain name.
	 *
	 * @param domain The domain name to query for TXT record.
	 * @return Byte array representing the DNS TXT record request packet.
	 */
	private static byte[] create_DNS_TXT_Record_Request( String domain ) {
		int id = new Random().nextInt( 65536 ); //Generate a random query ID
		
		byte[] request = new byte[ 12 + domain.length() + 2 + 4 ]; //Initialize the request packet
		
		//Set DNS header fields
		request[ 0 ] = ( byte ) ( id >> 8 ); // Query ID (high byte)
		request[ 1 ] = ( byte ) ( id & 0xFF ); // Query ID (low byte)
		request[ 2 ] = 0x01; //QR=0, OPCODE=0, AA=0, TC=0, RD=1 (Standard query, Recursion desired)
		request[ 5 ] = 0x01; //QDCOUNT=1 (One question in query section)
		
		//Add the domain name to the question section
		int index = 12; // Start of question section
		int p     = index++; // Pointer to length byte
		
		for( int i = 0, ch; i < domain.length(); i++ )
			if( ( ch = domain.charAt( i ) ) == '.' ) {
				request[ p ] = ( byte ) ( index - p - 1 ); // Set length of label
				p            = index++; // Move pointer to next label
			}
			else request[ index++ ] = ( byte ) ch; // Add character to label
		
		request[ p ] = ( byte ) ( index - p - 1 ); //Set the length for the last label
		
		index += 2; //Terminate domain name, set question type (TXT) and class (IN)
		request[ index++ ] = 0x10; //QTYPE = TXT (Query type: TXT record)
		request[ ++index ] = 0x01; //QCLASS = IN (Query class: Internet)
		
		return request; // Return DNS TXT record request packet
	}
	
	/**
	 * Parses a DNS TXT record response and extracts TXT records as ByteBuffers.
	 *
	 * @param response Byte array containing the DNS response packet.
	 * @return Array of ByteBuffers, each containing a TXT record, or null if parsing fails.
	 */
	private static ByteBuffer[] parse_DNS_TXT_Record_Response( byte[] response ) {
		int questionCount = ( response[ 4 ] << 8 ) | response[ 5 ]; //Extract question and answer counts from the header
		int answerCount   = ( response[ 6 ] << 8 ) | response[ 7 ];
		
		int index = 12; // Start of DNS message body
		
		for( int i = 0; i < questionCount; i++, index += 5 ) //Skip the question section
			while( response[ index ] != 0 ) index += response[ index ] + 1; // Skip domain name labels
		
		int          dst_index  = 0; // Destination index for TXT record data
		int          dst_index_ = 0; // Start index of current TXT record data
		ByteBuffer[] records    = new ByteBuffer[ answerCount ]; // Array to store TXT records as ByteBuffers
		for( int i = 0; i < answerCount; i++ ) //Parse each answer
		{
			index += 2; //Skip NAME field (pointer to domain name)
			//TYPE            two octets containing one of the RR TYPE codes.
			int TYPE = ( response[ index ] << 8 ) | response[ index + 1 ]; // Get record type
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
			index += 8;                                                //Skip all above (CLASS, TTL, RDLENGTH offset)
			int RDLENGTH = response[ index ] << 8 | response[ index + 1 ]; //an unsigned 16 bit integer that specifies the length in  octets of the RDATA field.
			index += 2; // Skip RDLENGTH field
			//TXT-DATA        One or more <character-string>s. where <character-string> is a single length octet followed by that number of characters
			//!!! attention records in reply may follow in arbitrary order
			
			if( TYPE == 16 ) //TXT record (Type code 16 for TXT record)
				for( int max = index + RDLENGTH; index < max; ) {
					byte len = response[ index++ ]; // Get length of TXT record chunk
					System.arraycopy( response, index, response, dst_index, len ); // Copy TXT record chunk to destination array
					dst_index += len; // Update destination index
					index += len; // Skip processed chunk
				}
			
			records[ i ] = ByteBuffer.wrap( response, dst_index_, dst_index - dst_index_ ); // Wrap TXT record data in ByteBuffer
			dst_index_   = dst_index; // Update start index for next TXT record
		}
		
		return records; // Return array of ByteBuffers containing TXT records
	}
	
	/**
	 * Retrieves the default DNS server IP address configured in the operating system.
	 * Uses nslookup command to query a known address (1.1.1.1) and extracts the DNS server IP from the output.
	 *
	 * @return InetAddress of the default OS DNS server, or null if retrieval fails.
	 */
	private static InetAddress get_default_OS_dns_server() {
		try {
			ProcessBuilder pb = new ProcessBuilder( System.getProperty( "os.name" ).toLowerCase().contains( "win" ) ?
					                                        new String[]{ "cmd.exe", "/c", "nslookup", "1.1.1.1" } :
					                                        // Windows command
					                                        new String[]{ "/bin/sh", "-c", "nslookup", "1.1.1.1" } ); // Linux/Unix command
			byte[] out = pb.start().getInputStream().readAllBytes(); // Execute nslookup and get output
			int    s   = 0;
			while( out[ s++ ] != ':' ) ; // Skip to first colon
			while( out[ s++ ] != ':' ) ; // Skip to second colon
			int e = s += 2; // Start of IP address
			while( out[ e ] != '\n' && out[ e ] != '\r' ) e++; // Find end of IP address
			return InetAddress.getByName( new String( out, s, e - s ) ); // Create InetAddress from extracted IP string
		} catch( IOException e ) { }
		return null; // Return null if DNS server retrieval fails
	}
	
	/**
	 * Retrieves TXT record values for a given key using DNS TXT record lookup.
	 * Uses DNS protocol to query TXT records for the given domain name (key).
	 *
	 * @param key Domain name (key) to lookup TXT records for.
	 * @return Array of ByteBuffers, each containing a TXT record value, or null if lookup fails.
	 */
	//Using DNS as readonly key-value storage https://datatracker.ietf.org/doc/html/rfc1035
	public static ByteBuffer[] value( String key ) {
		try( DatagramSocket socket = new DatagramSocket() ) { // Create DatagramSocket for DNS query
			byte[]         request    = create_DNS_TXT_Record_Request( key ); // Create DNS TXT record request
			DatagramPacket sendPacket = new DatagramPacket( request, request.length, get_default_OS_dns_server(), 53 ); // Create DatagramPacket for sending
			socket.send( sendPacket ); // Send DNS query
			
			byte[]         receiveData   = new byte[ 1024 ]; // Buffer for DNS response
			DatagramPacket receivePacket = new DatagramPacket( receiveData, receiveData.length ); // DatagramPacket for receiving response
			socket.receive( receivePacket ); // Receive DNS response
			
			return parse_DNS_TXT_Record_Response( receivePacket.getData() ); // Parse DNS response and return TXT records
		} catch( Exception e ) { }
		
		return null; // Return null if DNS lookup fails
	}
	
	/**
	 * Calculates the number of bytes required to VarInt encode a String.
	 * Calls varint_bytes(String, int, int) with full string range.
	 *
	 * @param src String to calculate VarInt encoded byte length for.
	 * @return Number of bytes required to VarInt encode the string.
	 */
	public static int varint_bytes( String src ) { return varint_bytes( src, 0, src.length() ); }
	
	/**
	 * Calculates the number of bytes required to VarInt encode a substring.
	 * VarInt encoding uses variable byte length based on character value.
	 *
	 * @param src      String to calculate VarInt encoded byte length for.
	 * @param src_from Start index of the substring.
	 * @param src_to   End index of the substring (exclusive).
	 * @return Number of bytes required to VarInt encode the substring.
	 */
	public static int varint_bytes( String src, int src_from, int src_to ) {
		int  bytes = 0; // Initialize byte count
		char ch;
		//Determine the number of bytes needed for each character:
		//- 1 byte for ASCII characters (0-127)
		//- 2 bytes for characters between 128 and 16,383
		//- 3 bytes for characters between 16,384 and 65,535
		while( src_from < src_to ) bytes += ( ch = src.charAt( src_from++ ) ) < 0x80 ?
				1 :
				// 1 byte for ASCII
				ch < 0x4000 ?
						2 :
						// 2 bytes for characters up to 0x3FFF
						3; // 3 bytes for characters up to 0xFFFF
		
		return bytes; // Return calculated byte count
	}
	
	/**
	 * Counts the number of characters represented by a ByteBuffer containing VarInt encoded data.
	 * VarInt encoded characters are terminated by a byte with MSB (Most Significant Bit) set to 0.
	 *
	 * @param src ByteBuffer containing VarInt encoded data.
	 * @return Number of characters represented in the ByteBuffer.
	 */
	public static int varint_chars( ByteBuffer src ) {
		int chars = 0; // Initialize character count
		//Increment the character count for each byte that doesn't have
		//its most significant bit set (i.e., value < 128).
		//This indicates the end of a varint-encoded character.
		while( src.hasRemaining() )
			if( -1 < src.get() ) chars++; // Increment character count for each non-continuation byte
		
		return chars; // Return character count
	}
	
	/**
	 * VarInt encodes a substring into a ByteBuffer.
	 *
	 * @param src       String to VarInt encode.
	 * @param from_char Start index of the substring in the string.
	 * @param dst       ByteBuffer to write VarInt encoded data to.
	 * @return Index in the source string of the first character not processed.
	 */
	public static int varint( String src, int from_char, ByteBuffer dst ) {
		for( int src_max = src.length(), ch; from_char < src_max; from_char++ )
			if( ( ch = src.charAt( from_char ) ) < 0x80 ) //Most frequent case: ASCII characters (0-127)
			{
				if( !dst.hasRemaining() ) break; // Break if no space left in destination buffer
				dst.put( ( byte ) ch ); // Put ASCII character as single byte
			}
			else if( ch < 0x4_000 ) {
				if( dst.remaining() < 2 ) break; // Break if not enough space for 2-byte encoding
				dst.put( ( byte ) ( 0x80 | ch ) ); // Put continuation byte and lower 7 bits
				dst.put( ( byte ) ( ch >> 7 ) ); // Put next byte with higher bits
			}
			else //Less frequent case
			{
				if( dst.remaining() < 3 ) break; // Break if not enough space for 3-byte encoding
				dst.put( ( byte ) ( 0x80 | ch ) ); // Put continuation byte and lower 7 bits
				dst.put( ( byte ) ( 0x80 | ch >> 7 ) ); // Put continuation byte and next 7 bits
				dst.put( ( byte ) ( ch >> 14 ) ); // Put last byte with remaining bits
			}
		
		return from_char; // Return index of next character to process
	}
	
	/**
	 * VarInt decodes data from a ByteBuffer into a StringBuilder.
	 *
	 * @param src ByteBuffer containing VarInt encoded data.
	 * @param ret Integer value to carry over partial character data from previous calls.
	 * @param dst StringBuilder to append decoded characters to.
	 * @return Integer value to carry over partial character data for next calls.
	 */
	public static int varint( ByteBuffer src, int ret, StringBuilder dst ) {
		int  ch = ret & 0xFFFF; // Get partial character value from ret
		byte s  = ( byte ) ( ret >> 16 ); // Get shift value from ret
		int  b;
		
		while( src.hasRemaining() ) if( -1 < ( b = src.get() ) ) {
			dst.append( ( char ) ( ( b & 0xFF ) << s | ch ) ); //Combine the partial character with the current byte and append to StringBuilder
			s  = 0; // Reset shift value
			ch = 0; // Reset partial character value
		}
		else {
			ch |= ( b & 0x7F ) << s; // Accumulate byte value to partial character
			s += 7; // Increment shift value by 7
		}
		
		return s << 16 | ch; //Return the current state (partial character and shift) for potential continuation
	}
	
	/**
	 * Counts the number of characters represented by a byte array containing VarInt encoded data.
	 * Calls varint_chars(byte[], int, int) with full byte array range.
	 *
	 * @param src Byte array containing VarInt encoded data.
	 * @return Number of characters represented in the byte array.
	 */
	public static int varint_chars( byte[] src ) { return varint_chars( src, 0, src.length ); }
	
	/**
	 * Counts the number of characters represented by a byte array (substring) containing VarInt encoded data.
	 * VarInt encoded characters are terminated by a byte with MSB (Most Significant Bit) set to 0.
	 *
	 * @param src      Byte array containing VarInt encoded data.
	 * @param src_from Start index of the substring in the byte array.
	 * @param src_to   End index of the substring in the byte array (exclusive).
	 * @return Number of characters represented in the byte array substring.
	 */
	public static int varint_chars( byte[] src, int src_from, int src_to ) {
		int chars = 0; // Initialize character count
		while( src_from < src_to )
			if( -1 < src[ src_from++ ] ) chars++; // Increment character count for each non-continuation byte
		
		return chars; // Return character count
	}
	
	/**
	 * VarInt encodes a substring into a byte array.
	 *
	 * @param src      String to VarInt encode.
	 * @param src_from Start index of the substring in the string.
	 * @param dst      Byte array to write VarInt encoded data to.
	 * @param dst_from Start index in the destination byte array.
	 * @return Long value containing processed string index (high 32 bits) and bytes written count (low 32 bits).
	 */
	public static long varint( String src, int src_from, byte[] dst, int dst_from ) {
		
		for( int src_max = src.length(), dst_max = dst.length, ch; src_from < src_max; src_from++ )
			if( ( ch = src.charAt( src_from ) ) < 0x80 ) {
				//Check if there's enough space in the destination array for 1 byte
				if( dst_from == dst_max ) break; // Break if no space left in destination byte array
				dst[ dst_from++ ] = ( byte ) ch; // Put ASCII character as single byte
			}
			else if( ch < 0x4_000 ) {
				//Check if there's enough space in the destination array for 2 bytes
				if( dst_max - dst_from < 2 ) break; // Break if not enough space for 2-byte encoding
				dst[ dst_from++ ] = ( byte ) ( 0x80 | ch ); // Put continuation byte and lower 7 bits
				dst[ dst_from++ ] = ( byte ) ( ch >> 7 ); // Put next byte with higher bits
			}
			else {
				//Check if there's enough space in the destination array for 3 bytes
				if( dst_max - dst_from < 3 ) break; // Break if not enough space for 3-byte encoding
				dst[ dst_from++ ] = ( byte ) ( 0x80 | ch ); // Put continuation byte and lower 7 bits
				dst[ dst_from++ ] = ( byte ) ( 0x80 | ch >> 7 ); // Put continuation byte and next 7 bits
				dst[ dst_from++ ] = ( byte ) ( ch >> 14 ); // Put last byte with remaining bits
			}
		
		//Return the result: high 32 bits contain the next character index to process,
		//low 32 bits contain the number of bytes written to the destination array
		return ( long ) src_from << 32 | dst_from; // Return processed string index and bytes written count
	}
	
	/**
	 * VarInt decodes data from a byte array into a StringBuilder.
	 * Calls varint(byte[], int, int, int, StringBuilder) with full byte array range and initial carry-over value 0.
	 *
	 * @param src Byte array containing VarInt encoded data.
	 * @param dst StringBuilder to append decoded characters to.
	 * @return Integer value to carry over partial character data for next calls.
	 */
	public static int varint( byte[] src, StringBuilder dst ) { return varint( src, 0, src.length, 0, dst ); }
	
	/**
	 * VarInt decodes data from a byte array into a StringBuilder, continuing from a previous state.
	 * Calls varint(byte[], int, int, int, StringBuilder) with full byte array range and provided carry-over value.
	 *
	 * @param src Byte array containing VarInt encoded data.
	 * @param ret Integer value to carry over partial character data from previous calls.
	 * @param dst StringBuilder to append decoded characters to.
	 * @return Integer value to carry over partial character data for next calls.
	 */
	public static int varint( byte[] src, int ret, StringBuilder dst ) { return varint( src, 0, src.length, ret, dst ); }
	
	/**
	 * VarInt decodes data from a byte array (substring) into a StringBuilder, starting from a given offset.
	 * Calls varint(byte[], int, int, int, StringBuilder) with specified byte array substring range and initial carry-over value 0.
	 *
	 * @param src      Byte array containing VarInt encoded data.
	 * @param src_from Start index of the substring in the byte array.
	 * @param src_to   End index of the substring in the byte array (exclusive).
	 * @param dst      StringBuilder to append decoded characters to.
	 * @return Integer value to carry over partial character data for next calls.
	 */
	public static int varint( byte[] src, int src_from, int src_to, StringBuilder dst ) { return varint( src, src_from, 0, src_to, dst ); }
	
	/**
	 * VarInt decodes data from a byte array (substring) into a StringBuilder, continuing from a previous state.
	 * VarInt decoding uses variable byte length characters, terminated by a byte with MSB=0.
	 *
	 * @param src      Byte array containing VarInt encoded data.
	 * @param src_from Start index of the substring in the byte array.
	 * @param src_to   End index of the substring in the byte array (exclusive).
	 * @param ret      Integer value to carry over partial character data from previous calls.
	 * @param dst      StringBuilder to append decoded characters to.
	 * @return Integer value to carry over partial character data for next calls.
	 */
	public static int varint( byte[] src, int src_from, int src_to, int ret, StringBuilder dst ) {
		int  ch = ret & 0xFFFF; // Get partial character value from ret
		byte s  = ( byte ) ( ret >> 16 ); // Get shift value from ret
		int  b;
		
		while( src_from < src_to ) if( -1 < ( b = src[ src_from++ ] ) ) {
			dst.append( ( char ) ( ( b & 0xFF ) << s | ch ) ); // Append decoded character to StringBuilder
			s  = 0; // Reset shift value
			ch = 0; // Reset partial character value
		}
		else {
			ch |= ( b & 0x7F ) << s; // Accumulate byte value to partial character
			s += 7; // Increment shift value by 7
		}
		
		return s << 16 | ch; // Return current state (shift and partial character value) for continuation
	}
	
	/**
	 * Creates a Boyer-Moore bad character heuristic pattern table for case-sensitive ASCII search.
	 *
	 * @param src Pattern string to create Boyer-Moore pattern for.
	 * @return Integer array representing the Boyer-Moore bad character heuristic pattern.
	 */
	public static int[] boyer_moore_pattern( String src ) {
		int[] ret = new int[ src.length() ]; // Initialize pattern table
		for( int i = src.length(); -1 < --i; )
			if( ret[ i ] == 0 ) for( int ii = i, ch = src.charAt( i ), p = i << 8 | ch; -1 < ii; ii-- )
				if( src.charAt( ii ) == ch ) ret[ ii ] = p; // Store pattern information (last occurrence and character)
		return ret; // Return Boyer-Moore pattern table
	}
	
	/**
	 * Performs case-sensitive Boyer-Moore search in a ByteBuffer for a given pattern (ASCII only).
	 *
	 * @param bytes   ByteBuffer to search within.
	 * @param pattern Boyer-Moore pattern array generated by boyer_moore_pattern(String).
	 * @return Index of the last byte of the first pattern match in the ByteBuffer, or -1 if not found.
	 */
	// Case-sensitive
	public static int boyer_moore_ASCII_Case_sensitive( ByteBuffer bytes, int[] pattern ) { //return pattern's last byte position in the `bytes`
ext:
		// Label for outer loop
		for( int len = pattern.length, i = 0, max = bytes.limit() - len + 1; i < max; ) {
			for( int j = len; -1 < --j; ) {
				int p = pattern[ j ];
				
				if( ( byte ) p == bytes.get( i + j ) ) continue;          // Compare characters, continue if match
				
				// Use the last occurrence to determine how far to skip
				int last = p >>> 8;            // Extract last occurrence position
				i += Math.max( 1, j - last ); // Calculate skip distance
				continue ext; // Continue outer loop after skip
			}
			
			return i + len; //return found pattern's last byte position in the `bytes`
		}
		return -1; // Pattern not found
	}
	
	/**
	 * Performs case-insensitive Boyer-Moore search in a ByteBuffer for a given pattern (ASCII only).
	 *
	 * @param bytes   ByteBuffer to search within.
	 * @param pattern Boyer-Moore pattern array generated by boyer_moore_pattern(String).
	 * @return Index of the last byte of the first pattern match in the ByteBuffer, or -1 if not found.
	 */
	// Case-insensitive
	public static int boyer_moore_ASCII_Case_insensitive( ByteBuffer bytes, int[] pattern ) { //return pattern's last byte position in the `bytes`
ext:
		// Label for outer loop
		for( int len = pattern.length, i = 0, max = bytes.limit() - len + 1; i < max; ) {
			for( int j = len; -1 < --j; ) {
				int p = pattern[ j ];
				switch( ( byte ) p - bytes.get( i + j ) ) {
					case 0: // Exact match
						continue; // Continue inner loop if characters match
					case 32: // Case difference (uppercase pattern, lowercase byte)
						if( 'a' <= p ) continue; // Continue if pattern char is uppercase
					case -32: // Case difference (lowercase pattern, uppercase byte)
						if( 'A' <= p ) continue; // Continue if pattern char is lowercase
				}
				
				// Use the last occurrence to determine how far to skip
				int last = p >>> 8;            // Extract last occurrence position
				i += Math.max( 1, j - last ); // Calculate skip distance
				continue ext; // Continue outer loop after skip
			}
			return i + len; //return found pattern's last byte position in the `bytes`
		}
		return -1; // Pattern not found
	}
	
	/**
	 * Converts a ByteBuffer to a hex string representation for debugging purposes.
	 *
	 * @param src ByteBuffer to convert to hex string.
	 * @return StringBuilder containing the hex string representation of the ByteBuffer.
	 */
	public static StringBuilder toString( ByteBuffer src ) { return toString( src, src.position(), src.limit(), new StringBuilder( ( src.limit() - src.position() ) * 5 ) ); }
	
	/**
	 * Converts a portion of a ByteBuffer to a formatted hex string representation for debugging purposes.
	 * Output format: "00000000: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX \n ...".
	 *
	 * @param src  ByteBuffer to convert to hex string.
	 * @param star Start index of the portion to convert.
	 * @param end  End index of the portion to convert (exclusive).
	 * @param dst  StringBuilder to append the hex string representation to.
	 * @return StringBuilder with the hex string representation appended.
	 */
	public static StringBuilder toString( ByteBuffer src, int star, int end, StringBuilder dst ) {
		
		for( int i = star; i < end; i += 16 ) {
			// Print the index in the first column
			dst.append( String.format( "%08d: ", i ) ); // Append index in hex format
			
			// Print 16 bytes in raw format
			for( int j = 0; j < 16; j++ )
				if( i + j < end ) dst.append( String.format( "%02X ", src.get( i + j ) ) ); // Append byte in hex format
				else dst.append( "   " ); // Pad with spaces if fewer than 16 bytes remain
			
			// Add a newline after each 16-byte row
			dst.append( "\n" ); // Append newline after each row
		}
		return dst; // Return StringBuilder with hex string representation
	}
	
	/**
	 * Packs a specified number of bits from a long value into a byte array at a given bit offset.
	 *
	 * @param src      The source long value containing the bits to pack.
	 * @param dst      The destination byte array where bits will be packed.
	 * @param dst_bit  The starting bit position in the destination array.
	 * @param dst_bits The number of bits to pack from the source.
	 */
	public static void pack( long src, byte[] dst, int dst_bit, int dst_bits ) {
		
		int i = dst_bit >> 3;
		dst_bit &= 7;
		
		int  done = Math.min( dst_bits, 8 - dst_bit );
		long mask = ( 1L << done ) - 1;
		dst[ i ] = ( byte ) ( dst[ i ] & ~( mask << dst_bit ) | ( src & mask ) << dst_bit );
		src >>>= done;
		dst_bits -= done;
		i++;
		
		for( ; 7 < dst_bits; dst_bits -= 8, src >>>= 8, i++ ) dst[ i ] = ( byte ) src;
		
		if( dst_bits == 0 ) return;
		mask = ( 1L << dst_bits ) - 1;
		
		dst[ i ] = ( byte ) ( dst[ i ] & ~mask | src & mask );
	}
	
	/**
	 * Unpacks a specified number of bits from a byte array starting at a given bit offset into a long value.
	 *
	 * @param src      The source byte array containing the bits to unpack.
	 * @param src_bit  The starting bit position in the source array.
	 * @param src_bits The number of bits to unpack.
	 * @return The unpacked bits as a long value.
	 */
	public static long unpack( byte[] src, int src_bit, int src_bits ) {
		
		int i = src_bit >> 3;
		src_bit &= 7;
		
		int  done   = Math.min( src_bits, 8 - src_bit );
		long result = ( src[ i ] & 0xFFL ) >> src_bit & ( 1L << done ) - 1;
		
		src_bits -= done;
		i++;
		
		for( ; 7 < src_bits; done += 8, src_bits -= 8, i++ ) result |= ( long ) ( src[ i ] & 0xFFL ) << done;
		
		return src_bits == 0 ?
				result :
				result | ( ( src[ i ] & 0xFFL ) & ( 1L << src_bits ) - 1 ) << done;
	}
}