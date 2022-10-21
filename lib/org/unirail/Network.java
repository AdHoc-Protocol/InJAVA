// AdHoc protocol - data interchange format and source code generator
// Copyright 2020 Chikirev Sirguy, Unirail Group. All rights reserved.
// cheblin@gmail.org
// https://github.com/orgs/AdHoc-Protocol
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package org.unirail;

import java.io.Closeable;
import java.io.IOException;
import java.lang.ref.SoftReference;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;

public interface Network {
	interface INT // internal side
	{
		interface BytesSrc extends AdHoc.EXT.BytesSrc, AdHoc.EXT.BytesSrc.Producer {
			
			BytesDst mate();
			
			void connected(TCP.Flow flow);
			
			void closed();//from network event
			
			default void close() throws IOException {//to network command
				Object token = token();
				if (token instanceof TCP.Flow) ((TCP.Flow) token).close();
			}
			
			@Override default boolean isOpen() {
				Object                    token = token();
				AsynchronousSocketChannel socket;
				return token instanceof TCP.Flow && (socket = ((TCP.Flow) token).ext_channel) != null && socket.isOpen();
			}
		}
		
		interface BytesDst extends AdHoc.EXT.BytesDst {
			BytesSrc mate();
			
			void connected(TCP.Flow flow);
			
			void closed();//full cleanup
		}
	}
	
	abstract class TCP {
		public static java.util.logging.Logger LOG = java.util.logging.Logger.getLogger("Network");
		
		public final int buffer_size;
		public TCP(int buffer_size) {this.buffer_size = buffer_size;}
		
		protected void recycle(Flow free) {
			free.server_ip = null;
			if (free.int_src != null)
			{
				free.int_src.subscribe(null, null);
				free.int_src = null;
			}
			
			free.int_dst = null;
			free.mate    = null;
			free.time      = System.currentTimeMillis();
			free.buffer.clear();
			
			flows.accept(free);
		}
		
		protected final Pool.MultiThreaded<Flow> flows = new Pool.MultiThreaded<>(Flow::new);
		
		protected abstract void cleanup(Flow flow);
		
		public abstract void shutdown();
		
		public class Flow implements CompletionHandler<Integer, Object>, Consumer<AdHoc.EXT.BytesSrc> {
			public final ByteBuffer buffer;
			
			Flow mate;
			public long time = System.currentTimeMillis();
			InetSocketAddress server_ip;
			public AsynchronousSocketChannel ext_channel;
			public Flow() {buffer = ByteBuffer.allocateDirect(buffer_size);}
			
			public void switch_to(INT.BytesDst dst, INT.BytesSrc src) {
				if (this.int_dst == null) // client
				{
					this.int_src = src;
					if (mate != null) mate.int_dst = dst;
					else if (dst != null)
					{
						
						(mate = flows.get()).mate = this; //make mate receiving flow
						mate.receive(ext_channel, dst);
					}
				}
				else//
				{
					this.int_dst = dst;
					if (mate != null) mate.int_src = src;
					else if (src != null)
					{
						
						(mate = flows.get()).mate = this; //make mate transmitting flow
						mate.ext_channel          = ext_channel;
						(mate.int_src = src).subscribe(mate, mate); //set listener
					}
				}
			}
			
			public void close() {
				
				if (ext_channel == null) return;
				boolean cleanup_mate = mate != null && mate.ext_channel != null;
				
				try
				{
					ext_channel.close();
				} catch (IOException e) {LOG.severe("ext_channel.close() " + e.toString());}
				
				if (server_ip != null)// Client Transmitter
				{
					if (cleanup_mate) recycle(mate);//mate Client Receiver
					cleanup(this);
				}
				else if (int_src != null)// Server Transmitter
				{
					if (cleanup_mate) cleanup(mate);//mate Server Receiver
					recycle(this);
				}
				else if (int_dst != null && (mate == null || mate.server_ip == null))//  Server Receiver
				{
					if (cleanup_mate) recycle(mate);//mate  Server Transmitter
					cleanup(this);
				}
				else //Client Receiver
				{
					if (cleanup_mate) cleanup(mate);
					recycle(this);
				}
			}
			
			@Override public void completed(Integer result, Object o) {
				if (result == -1) close();
				else if (int_src == null) receiving();
				else transmitting();
			}
			
			@Override public void failed(Throwable e, Object o) {
				LOG.severe("void failed " + e.toString());
				close();
			}

//region Receiving
			
			public INT.BytesDst int_dst;
			
			
			void receive(AsynchronousSocketChannel src, INT.BytesDst dst) {
				int_dst     = dst;
				ext_channel = src;
				
				int_dst.connected(this);//notify
				if (mate == null && int_dst.mate() != null) int_dst.mate().subscribe(this, this);//listen localhost output
				
				ext_channel.read(buffer, null, this);//start receiving
			}
			
			void receiving() {
				if (ext_channel == null) return;
				try//operating
				{
					buffer.flip();
					int_dst.write(buffer);
					buffer.clear();
					
					ext_channel.read(buffer, null, this);
				} catch (IOException e) { LOG.severe("void receiving() "  +e.toString());}
			}

//endregion

//region Transmitting
			
			public INT.BytesSrc int_src;
			
			void connected() {
				INT.BytesDst dst = int_src.mate();
				if (dst != null)
				{
					
					(mate = flows.get()).mate = this;
					mate.receive(ext_channel, dst);
				}
				int_src.connected(this);
				int_src.subscribe(this, this);
			}
			
			@Override public void accept(AdHoc.EXT.BytesSrc src) {
				
				if (busy()) return;
				if (this.int_src == null) //Substitute listener on server receiver
				{
					
					(mate = flows.get()).mate = this;
					
					mate.ext_channel = ext_channel;
					mate.busy();
					(mate.int_src = (INT.BytesSrc) src).subscribe(mate, mate);//switch listener
					idle();
					mate.transmitting();
					
				}
				else transmitting();
			}
			protected final AtomicBoolean busy = new AtomicBoolean(false);
			
			protected boolean busy() {return busy.getAndSet(true);}
			
			protected void idle()    {busy.set(false);}
			
			void transmitting() {
				
				if (ext_channel == null) return;
				
				boolean free = true;
				try
				{
					buffer.clear();
					
					while (0 < int_src.read(buffer) && buffer.hasRemaining()) ;//till has space or packs to read
					
					if (0 < buffer.position())
					{
						buffer.flip();
						ext_channel.write(buffer, null, this);//async
						free = false;
					}
				} catch (IOException e) {LOG.severe("void transmitting()"+ e.toString());} finally {if (free) idle();}
			}

//endregion
		}
		
		public static class Server extends TCP {
			
			protected final Pool<INT.BytesDst> localhost_receivers;//new connection data handlers
			
			public Server(int buffer_size, Supplier<INT.BytesDst> receiver_generator, InetSocketAddress... ips) throws IOException {
				this(buffer_size, new Pool.MultiThreaded<>(receiver_generator), ips);
			}
			
			final AsynchronousChannelGroup executor = AsynchronousChannelGroup.withThreadPool(Executors.newWorkStealingPool());
			public Server(int buffer_size, Pool<INT.BytesDst> receivers, InetSocketAddress... ips) throws IOException {
				super(buffer_size);
				this.localhost_receivers = receivers;
				
				bind(ips);
			}
			
			public ArrayList<AsynchronousServerSocketChannel> tcp_listeners = new ArrayList<>();
			
			public void bind(InetSocketAddress... ips) throws IOException {
				for (InetSocketAddress ip : ips)
				{
					final AsynchronousServerSocketChannel server = AsynchronousServerSocketChannel.open(executor)
							                                               .setOption(StandardSocketOptions.SO_REUSEADDR, true)
							                                               .bind(ip);
					
					tcp_listeners.add(server);
					
					server.accept(null,
					              new CompletionHandler<AsynchronousSocketChannel, Void>() {
						              @Override public void completed(AsynchronousSocketChannel client, Void v) {
							
							              flows.get().receive(client, localhost_receivers.get());
							              server.accept(null, this);//rerun
						              }
						
						              @Override public void failed(Throwable e, Void v) {LOG.severe("server.accept " + e.toString());}
					              }
					             );
				}
			}
			@Override protected void cleanup(TCP.Flow receiver) {
				
				receiver.int_dst.closed();
				INT.BytesSrc src = receiver.int_dst.mate();
				if (src != null)
				{
					src.closed();
					src.subscribe(null, null);
				}
				
				localhost_receivers.accept(receiver.int_dst);
				receiver.int_dst = null;
				
				recycle(receiver);
			}
			
			
			@Override public void shutdown() {
				for (Closeable closeable : tcp_listeners)
					try
					{
						closeable.close();
					} catch (IOException e) { LOG.severe("public void shutdown() " + e);}
			}
		}
		
		public static class Client extends TCP {
			
			public final Flow transmitter = flows.get();
			
			public final Runnable                 OnConnectingTimout;
			public final Duration                     timeout;
			protected    Consumer<AdHoc.EXT.BytesSrc> bytes_listener;
			
			public Client(int buffer_size, Runnable onConnectingTimout, Duration timeout) {
				super(buffer_size);
				this.timeout       = timeout;
				OnConnectingTimout = onConnectingTimout;
				
				bytes_listener = src -> {
					final INT.BytesSrc output = (INT.BytesSrc) src;
					final Object       token  = output.token(null);
					
					if (!(token instanceof InetSocketAddress)) return;
					
					output.subscribe(null, transmitter);//in connection process
					transmitter.int_src = output;
					try
					{
						transmitter.ext_channel = AsynchronousSocketChannel.open();
					} catch (IOException e)
					{
						throw new RuntimeException(e);
					}
					
					transmitter.ext_channel.connect(transmitter.server_ip = (InetSocketAddress) token, transmitter, on_connect_to_server);
					
					Executors.newSingleThreadScheduledExecutor().schedule(() -> {
						if (!transmitter.ext_channel.isOpen()) OnConnectingTimout.run();
					}, timeout.getSeconds(), TimeUnit.SECONDS);
					
				};
			}
			
			public void bind(INT.BytesSrc src, InetSocketAddress dst) throws IOException {
				src.close();
				src.subscribe(bytes_listener, dst);
			}
			
			
			private static final CompletionHandler<Void, TCP.Flow> on_connect_to_server = new CompletionHandler<Void, Flow>() {
				@Override public void completed(Void v, Flow transmitter) {transmitter.connected();}
				
				@Override public void failed(Throwable exc, Flow flow) {flow.close();}
			};
			
			@Override protected void cleanup(TCP.Flow flow) {
				
				transmitter.int_src.closed();
				if (transmitter.int_src.mate() != null) transmitter.int_src.mate().closed();
				
				transmitter.int_src.subscribe(bytes_listener, transmitter.server_ip);
				
				transmitter.server_ip = null;
				transmitter.int_src   = null;
				
				recycle(transmitter);
			}
			
			@Override public void shutdown() {
				transmitter.close();
			}
		}
		
		public interface Pool<F> extends Supplier<F>, Consumer<F> {
			
			class SingleThreadImpl<T> implements Pool<T> {
				private SoftReference<ArrayList<T>> list = new SoftReference<>(new ArrayList<>(3));
				final   Supplier<T>                 supplier;
				
				protected SingleThreadImpl(Supplier<T> supplier) {this.supplier = supplier;}
				
				public T get() {
					ArrayList<T> list = this.list.get();
					return list == null || list.isEmpty() ? supplier.get() : list.remove(list.size() - 1);
				}
				
				public void accept(T item) {
					ArrayList<T> list = this.list.get();
					if (list == null) this.list = new SoftReference<>(list = new ArrayList<>(3));
					
					list.add(item);
				}
			}
			
			class MultiThreaded<T> implements Pool<T> {
				protected final ThreadLocal<Pool<T>> threadLocal = new ThreadLocal<>();// todo ThreadLocal.withInitial(ArrayList::new);
				private final   Supplier<T>          supplier;
				
				public MultiThreaded(Supplier<T> supplier) {this.supplier = supplier;}
				
				@Override public void accept(T t) {
					Pool<T> pool = threadLocal.get();
					if (pool == null) threadLocal.set(new SingleThreadImpl<>(supplier));
				}
				
				@Override public T get() {
					Pool<T> pool = threadLocal.get();
					if (pool == null) threadLocal.set(pool = new SingleThreadImpl<>(supplier));
					return pool.get();
				}
			}
		}
	}
	
	class Wire implements Consumer<AdHoc.EXT.BytesSrc> {
		public        AdHoc.EXT.BytesDst dst;
		private final ByteBuffer         buffer;
		
		public Wire(AdHoc.EXT.BytesSrc.Producer registrar, AdHoc.EXT.BytesDst dst, int buffer_size) {
			this.dst = dst;
			buffer   = ByteBuffer.wrap(new byte[buffer_size]);
			registrar.subscribe(this, null);
		}
		public void connect(AdHoc.EXT.BytesSrc src, AdHoc.EXT.BytesDst dst) {
			try
			{
				buffer.clear();
				while (0 < src.read(buffer))
				{
					buffer.flip();
					dst.write(buffer);
					buffer.clear();
				}
			} catch (IOException e) {TCP.LOG.severe("public void connect " + e.toString());}
		}
		
		@Override public void accept(AdHoc.EXT.BytesSrc src) {
			try
			{
				buffer.clear();
				while (0 < src.read(buffer))
				{
					buffer.flip();
					dst.write(buffer);
					buffer.clear();
				}
			} catch (IOException e) {TCP.LOG.severe("public void accept " + e.toString());}
		}
	}
	
	class UDP {
		//use TCP implementation over Wireguard https://www.wireguard.com/
	}
}