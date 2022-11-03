// AdHoc protocol - data interchange format and source code generator
// Copyright 2020 Chikirev Sirguy, Unirail Group. All rights reserved.
// cheblin@gmail.org
// https://github.com/cheblin/AdHoc-protocol
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

import java.lang.ref.SoftReference;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.math.BigInteger;


public abstract class AdHoc {
	private static final BigInteger ULONG_MASK = BigInteger.ONE.shiftLeft(Long.SIZE).subtract(BigInteger.ONE);
	
	public static String ulong(long src) {
		return src < 0L ? BigInteger.valueOf(src).and(ULONG_MASK).toString() : Long.toString(src);
	}
	
	private static int trailingZeros(int i) {
		
		int n = 7;
		i <<= 24;
		int y = i << 4;
		
		if (y != 0)
		{
			n -= 4;
			i = y;
		}
		
		y = i << 2;
		
		return y == 0 ? n - (i << 1 >>> 31) : n - 2 - (y << 1 >>> 31);
	}
	
	//region CRC
	private static final int  CRC_LEN_BYTES = 2;//CRC len in bytes
	private static final char tab[]         = {0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935};
	
	// !!!! Https://github.com/redis/redis/blob/95b1979c321eb6353f75df892ab8be68cf8f9a77/src/crc16.c
	//Output for "123456789"     : 31C3 (12739)
	private static char crc16(int src, char crc) {
		src &= 0xFF;
		crc = (char) (tab[(crc >> 12 ^ src >> 4) & 0x0F] ^ crc << 4);
		return (char) (tab[(crc >> 12 ^ src & 0x0F) & 0x0F] ^ crc << 4);
	}

//endregion
	
	
	private static final int OK = Integer.MAX_VALUE,
			STR                 = OK - 100,
			DONE                = STR + 1,
			VAL4                = DONE + 1,
			VAL8                = VAL4 + 1,
			LEN                 = VAL8 + 1, BASE_LEN = LEN + 1,
			BITS                = BASE_LEN + 1,
			VARINTS             = BITS + 1,
			VARINT              = VARINTS + 1;
	
	protected int bit;
	
	boolean pack_by_pack_mode = false;
	
	public    Object obj;
	protected String str;
	
	protected String     internal_string;
	protected int        bits;
	protected ByteBuffer buffer;
	protected int        mode;
	
	protected int  u4;
	protected long u8;
	public    int  bytes_left;
	
	
	public interface EXT {
		
		interface BytesSrc extends ReadableByteChannel {
			
			interface Producer {
				void subscribe(Consumer<BytesSrc> subscriber, Object token);
				
				Object token(Object token);
				
				Object token();
			}
		}
		
		interface BytesDst extends WritableByteChannel {}
	}
	
	public interface INT {
		interface BytesDst {
			BytesDst put_bytes(Receiver src);
			
			interface Consumer {
				BytesDst receiving(Receiver src, int id);
				
				void received(Receiver src, BytesDst dst);
			}
		}
		
		interface BytesSrc {
			BytesSrc get_bytes(Transmitter dst);
			
			interface Producer {
				BytesSrc sending(Transmitter dst);
				
				void sent(Transmitter dst, BytesSrc src);
			}
		}
	}
	
	public static class Receiver extends AdHoc implements EXT.BytesDst, Context.Provider {
		
		public AdHoc.INT.BytesDst.Consumer int_dst;
		
		private final int id_bytes;
		public Receiver(AdHoc.INT.BytesDst.Consumer int_dst, int id_bytes) {
			
			this.int_dst = int_dst;
			bytes_left   = this.id_bytes = id_bytes;
		}
		
		
		public static class Framing implements EXT.BytesDst {
			@Override public boolean isOpen() {return dst.isOpen();}
			@Override public void close()     {dst.close();}
			public Receiver dst;
			public Framing(Receiver dst) {(this.dst = dst).pack_by_pack_mode = true;}
			
			private void reset() {
				
				bits  = 0;
				shift = 0;
				crc0  = 0;
				crc1  = 0;
				crc   = 0;
				put   = 0;
				BYTE  = 0;
				
				if (!FF)//not on next frame start position... switch to search next frame start position mode
					state = State.SEEK_FF;
				
				dst.write(null);//fully cleanup
			}
			
			@Override public int write(ByteBuffer src) {
				if (src == null)
				{
					reset();
					return -1;
				}
				int remaining = src.remaining();
				if (remaining < 1) return 0;
				final int limit = src.limit();
				put = 0;


init:
				switch (state)
				{
					case State.SEEK_FF://bytes distortion was detected, skip bytes until FF sync mark
						while (src.hasRemaining())
							if (src.get() == (byte) 0xFF)
							{
								state = State.NORMAL;
								if (FF) error_handler.error(Error.FFFF_ERROR);
								FF = true;
								if (src.hasRemaining()) break init;
								
								return remaining;
							}
							else FF = false;
						return remaining;
					
					case State.Ox7F:
						
						if (FF = (BYTE = src.get() & 0xFF) == 0xFF)//FF here is an error
						{
							reset();
							break init;
						}
						
						bits |= ((BYTE & 1) << 7 | 0x7F) << shift;
						put(src, 0);
						write(src, 1, State.NORMAL);
						src.position(1).limit(limit);
					
					case State.Ox7F_:
						
						while (BYTE == 0x7F)
						{
							if (!src.hasRemaining())
							{
								write(src, put, State.Ox7F_);
								return remaining;
							}
							
							if (FF = (BYTE = src.get() & 0xFF) == 0xFF)//FF here is an error
							{
								reset();
								break init;
							}
							
							bits |= (BYTE << 6 | 0x3F) << shift;
							if ((shift += 7) < 8) continue;
							shift -= 8;
							
							put(src, put++);
						}
						
						
						bits |= BYTE >> 1 << shift;
						if ((shift += 7) < 8) break;
						
						shift -= 8;
						
						if (src.position() == put)
						{
							write(src, put, State.NORMAL);
							src.position(put).limit(limit);
							put = 0;
						}
						put(src, put++);
						
						state = State.NORMAL;
				}
				
				while (src.hasRemaining())
				{
					if ((BYTE = src.get() & 0xFF) == 0x7F)
					{
						if (!src.hasRemaining())
						{
							write(src, put, State.Ox7F);
							return remaining;
						}
						
						if (FF = (BYTE = src.get() & 0xFF) == 0xFF)//FF here is an error
						{
							reset();
							continue;
						}
						
						bits |= ((BYTE & 1) << 7 | 0x7F) << shift;
						
						put(src, put++);
						
						while (BYTE == 0x7F)
						{
							if (!src.hasRemaining())
							{
								write(src, put, State.Ox7F_);
								return remaining;
							}
							
							if (FF = (BYTE = src.get() & 0xFF) == 0xFF)//FF here is an error
							{
								reset();
								continue;
							}
							
							bits |= ((BYTE & 1) << 6 | 0x3F) << shift;
							if ((shift += 7) < 8) continue;
							
							shift -= 8;
							
							put(src, put++);
						}
						
						bits |= BYTE >> 1 << shift;
						if ((shift += 7) < 8) continue;
						
						shift -= 8;
					}
					else if (BYTE == 0xFF)  //starting new  frame mark byte
					{
						if (FF)
						{
							error_handler.error(Error.FFFF_ERROR);
							continue;
						}
						
						FF = true;
						final int fix = src.position();//store position
						write(src, put, State.NORMAL);
						src.limit(limit).position(fix);//restore position
						
						continue;
					}
					else bits |= BYTE << shift;
					
					FF = false;
					put(src, put++);
				}
				write(src, put, State.NORMAL);
				
				return remaining;
			}
			
			
			private void write(ByteBuffer src, int limit, int state_if_ok) {
				state = state_if_ok;
				if (limit == 0) return;//no decoded bytes
				
				src.position(0).limit(limit);//positioning on the decoded bytes section
				
				dst.write(src);
				
				if (dst.mode == OK)//exit from dst.write(src) is not because there is not enough data
				{
					if (dst.slot != null && dst.slot.dst != null)//there is a `fully received packet`, waiting for CRC check and dispatching, if check is OK
					{
						//fully received packet here
						int bytes_left = src.remaining();
						if (bytes_left == CRC_LEN_BYTES)
						{
							dst.u4 = src.getChar();//received CRC
							CHECK_CRC_THEN_DISPATCH();
							return;
						}
						
						if (bytes_left < CRC_LEN_BYTES)//not enough bytes for crc
						{
							RECEIVING_CRC = true;//switch receiving crc mode
							
							//prepare variables
							dst.u4         = 0;//received CRC
							dst.bytes_left = CRC_LEN_BYTES - 1;
							
							for (; 0 < bytes_left; bytes_left--, dst.bytes_left--)//collect already available crc bytes
							     dst.u4 |= (src.get() & 0xFF) << bytes_left * 8;
							return;
						}
						
						// packet received but CRC_LEN_BYTES < src.remaining() (bytes left more than CRC_LEN_BYTES)  - this is not normal
					}
					
					//consumed bytes does not produce packet. this is error
					error_handler.error(Error.BYTES_DISTORTION);//error notification
					reset();
				}
				else if (FF)//not enough bytes to complete the current packet but already next pack frame detected. error
				{
					error_handler.error(Error.BYTES_DISTORTION);
					reset();
				}
			}
			private void put(ByteBuffer dst, int put) {
								
				crc  = crc1; //shift crc
				crc1 = crc0;
				
				if (RECEIVING_CRC)
				{
					this.dst.u4 |= (bits & 0xFF) << (this.dst.bytes_left * 8);
					if ((this.dst.bytes_left -= 1) == -1) CHECK_CRC_THEN_DISPATCH();
				}
				else
				{
					crc0 = crc16(bits, crc1);
					dst.put(put, (byte) bits);
				}
				
				bits >>= 8;
				
			}
			
			boolean RECEIVING_CRC = false;
			
			void CHECK_CRC_THEN_DISPATCH() {
				RECEIVING_CRC = false;
				if (crc == dst.u4) dst.int_dst.received(dst, dst.slot.dst);//dispatching
				else error_handler.error(Error.CRC_ERROR);//bad CRC
				reset();
			}
			
			
			public Error.Handler error_handler = Error.Handler.DEFAULT;
			
			public @interface Error {
				int
						FFFF_ERROR       = 0,
						CRC_ERROR        = 1,
						BYTES_DISTORTION = 3;
				
				interface Handler {
					Handler DEFAULT = error -> {
						switch (error)
						{
							case FFFF_ERROR:
								System.err.println("====================FFFF_ERROR");
								return;
							case CRC_ERROR:
								System.err.println("===================CRC_ERROR");
								return;
							case BYTES_DISTORTION:
								System.err.println("===================BYTES_DISTORTION");
								return;
							
						}
					};
					
					void error(int error);
				}
			}
			
			
			private int  bits  = 0;
			private int  put   = 0;//place where put decoded
			private int  shift = 0;
			private char crc   = 0;
			private char crc0  = 0;
			private char crc1  = 0;
			private int  BYTE  = 0;//fix fetched byte
			
			private boolean FF = false;
			
			private @State int state = State.SEEK_FF;
			
			private @interface State {
				int
						NORMAL  = 0,
						Ox7F    = 2,
						Ox7F_   = 3,
						SEEK_FF = 4;
			}
		}


//region Slot
		
		private static class Slot {
			
			public int                state;
			public AdHoc.INT.BytesDst dst;
			
			public int base_index;
			public int base_index_max;
			public int base_nulls;
			
			public int fields_nulls;
			
			public int index     = 1;
			public int index_max = 1;
			public int items_nulls;
			
			public       Slot next;
			public final Slot prev;
			
			public Slot(Slot prev) {
				this.prev = prev;
				if (prev != null) prev.next = this;
			}
			public ContextExt context;
		}
		
		private Slot                slot;
		private SoftReference<Slot> slot_ref = new SoftReference<>(new Slot(null));
		
		private void free_slot() {
			if (slot.context != null)
			{
				context      = slot.context.prev;
				slot.context = null;
			}
			slot = slot.prev;
		}

//endregion


//region Context
		
		private static class ContextExt extends Context {
			
			AdHoc.INT.BytesDst key;
			AdHoc.INT.BytesDst value;
			
			String key_string;
			long   key_long;
			public       ContextExt next;
			public final ContextExt prev;
			
			public ContextExt(ContextExt prev) {
				this.prev = prev;
				if (prev != null) prev.next = this;
			}
		}
		
		private ContextExt                context;
		private SoftReference<ContextExt> context_ref = new SoftReference<>(new ContextExt(null));
		
		
		public Context context() {
			
			if (slot.context != null) return slot.context;
			
			if (context == null && (context = context_ref.get()) == null) context_ref = new SoftReference<>(context = new ContextExt(null));
			else if (context.next == null) context = context.next = new ContextExt(context);
			else context = context.next;
			
			return slot.context = context;
		}

//endregion
		
		public AdHoc.INT.BytesDst output() {
			AdHoc.INT.BytesDst dst = slot.next.dst;
			slot.next.dst = null;
			return dst;
		}
		
		public AdHoc.INT.BytesDst key() {
			AdHoc.INT.BytesDst key = slot.context.key;
			slot.context.key = null;
			return key;
		}
		
		public AdHoc.INT.BytesDst key(AdHoc.INT.BytesDst key) {return slot.context.key = key;}
		
		public AdHoc.INT.BytesDst value() {
			AdHoc.INT.BytesDst value = slot.context.value;
			slot.context.value = null;
			return value;
		}
		
		public AdHoc.INT.BytesDst value(AdHoc.INT.BytesDst value) {return slot.context.value = value;}
		
		public void key(String key)                               {slot.context.key_string = key;}
		
		public String key_string() {
			String key = slot.context.key_string;
			slot.context.key_string = null;
			return key;
		}
		public long key(long key)   {return slot.context.key_long = key;}
		
		public long key_long()      {return slot.context.key_long;}
		
		public void key(double key) {slot.context.key_long = Double.doubleToLongBits(key);}
		
		public double key_double()  {return Double.longBitsToDouble(slot.context.key_long);}
		
		public void key(float key)  {slot.context.key_long = Float.floatToIntBits(key);}
		
		public float key_float()    {return Float.intBitsToFloat((int) slot.context.key_long);}
		
		public boolean get_info(int the_case) {
			if (0 < buffer.remaining())
			{
				context();
				slot.context.key_long = (long) getU() << 32;
				return true;
			}
			retry_at(the_case);
			return false;
		}
		
		public boolean hasNullKey() {return (key_long() >> 39 & 1) == 1;}
		
		public boolean hasNullKey(int key_val_case, int end_case) {
			if (hasNullKey()) return true;
			state(index_max() == 0 ? end_case : key_val_case);
			
			return false;
		}
		
		public boolean hasNullKey(int null_values_case, int key_val_case, int next_field_case) {
			boolean has = hasNullKey();
			if (has && nullKeyHasValue()) return true;//not jump. step to send value of key == null
			
			//if key == null does not exists or it's value == null
			//no need to receive value,  so can calculate next jump
			state(0 < index_max() ? null_values_case : //jump to send keys which value == null
			      0 < index_max((int) key_long()) ? key_val_case :// jump to send KV
			      next_field_case //jump out
			     );
			
			return has;
		}
		
		public boolean nullKeyHasValue()              {return (slot.context.key_long >> 38 & 1) == 1;}
		
		public boolean get_items_count(int next_case) {return get_len((int) (slot.context.key_long >> 32 & 7), next_case);}
		
		public boolean null_values_count(int next_case) {
			slot.context.key_long |= index_max();//preserve total items count
			return get_len((int) (slot.context.key_long >> 35 & 7), next_case);
		}
		
		public int items_count() {return (int) key_long() + index_max() + (hasNullKey() ? 1 : 0);}
		
		public boolean no_null_values(int key_val_case, int end_case) {
			if (0 < index_max()) return false; //no keys which value == null
			
			state(0 < index_max((int) key_long()) ? key_val_case : end_case);// KV
			return true;
		}
		
		public boolean no_key_val(int end_case) {
			
			if (0 < index_max((int) key_long())) return false;
			state(end_case);
			return true;
		}
		
		
		public int state()           {return slot.state;}
		
		public void state(int value) {slot.state = value;}
		
		
		public int index()           {return slot.index;}
		
		public int index(int value)  {return slot.index = value;}
		
		public int index_max()       {return slot.index_max;}
		
		public int index_max(int len) {
			slot.index = 0;
			return slot.index_max = len;
		}
		
		public boolean index_max_zero(int on_zero_case) {
			if (0 < slot.index_max) return false;
			state(on_zero_case);
			return true;
		}
		
		public int base_index()          {return slot.base_index;}
		
		public int base_index(int value) {return slot.base_index = value;}
		
		public int base_index_max()      {return slot.base_index_max;}
		
		public int base_index_max(int base_len) {
			slot.base_index = 0;
			return slot.base_index_max = base_len;
		}
		
		public boolean next_index(int ok_case) {
			if (++slot.index < slot.index_max)
			{
				state(ok_case);
				return true;
			}
			return false;
		}
		
		public boolean next_index()      {return ++slot.index < slot.index_max;}
		
		public boolean next_base_index() {return ++slot.base_index < slot.base_index_max;}
		
		public boolean null_at_index()   {return (nulls() & 1 << (index() & 7)) == 0;}
		
		public int nulls()               {return slot.items_nulls;}
		
		public void nulls(int nulls, int index) {
			
			slot.index       = index + trailingZeros(nulls);
			slot.items_nulls = nulls;
		}
		
		
		public boolean null_at_base_index() {return (base_nulls() & 1 << (base_index() & 7)) == 0;}
		
		public int base_nulls()             {return slot.base_nulls;}
		
		public void base_nulls(int nulls, int base_index) {
			
			slot.base_index = base_index + trailingZeros(nulls);
			slot.base_nulls = nulls;
			
		}
		
		public boolean find_exist(int index) {
			int nulls = buffer.get() & 0xFF;
			if (nulls == 0) return false;
			slot.index       = index + trailingZeros(nulls);
			slot.items_nulls = nulls;
			return true;
		}
		
		public boolean find_base_exist(int base_index) {
			int nulls = buffer.get() & 0xFF;
			if (nulls == 0) return false;
			slot.base_index = base_index + trailingZeros(nulls);
			slot.base_nulls = nulls;
			return true;
		}
		
		public boolean get_fields_nulls(int this_case) {
			if (buffer.hasRemaining())
			{
				slot.fields_nulls = buffer.get() & 0xFF;
				return true;
			}
			
			slot.state = this_case;
			mode       = DONE;
			return false;
		}
		
		public boolean is_null(int field, int next_field_case) {
			if ((slot.fields_nulls & field) == 0)
			{
				state(next_field_case);
				return true;
			}
			return false;
		}
		
		public boolean get_len(int bytes, int next_case) {
			if (bytes == 0)
			{
				index_max(0);
				return true;
			}
			
			if (buffer.remaining() < bytes)
			{
				retry_get4(bytes, next_case);
				mode = LEN;
				return false;
			}
			
			index_max(get4(bytes));
			return true;
		}
		
		public boolean get_base_len(int bytes, int next_case) {
			if (buffer.remaining() < bytes)
			{
				retry_get4(bytes, next_case);
				mode = BASE_LEN;
				return false;
			}
			
			base_index_max(get4(bytes));
			return true;
		}
		
		
		public boolean idle() {return slot == null;}
		
		
		boolean not_get4() {
			if (buffer.remaining() < bytes_left)
			{
				int r = buffer.remaining();
				u4 = u4 << r * 8 | get4(r);
				bytes_left -= r;
				return true;
			}
			
			u4 = u4 << bytes_left * 8 | get4(bytes_left);
			return false;
		}
		// if src == null - clear and reset
		public int write(ByteBuffer src) {
			
			if (src == null)
			{
				buffer = null;
				if (slot == null) return 0;
				mode            = OK;
				bytes_left      = id_bytes;
				u4              = 0;
				u8              = 0;
				internal_string = null;
				slot.dst        = null;
				slot.state      = 0;
				
				while (slot != null)
				{
					slot.dst = null;
					free_slot();
				}
				
				return 0;
			}
			
			final int remaining = src.remaining();
			
			buffer = src;
write:
			for (; ; )
			{
				if (slot == null || slot.dst == null)
				{
					if (not_get4())
					{
						if (slot != null) free_slot();//remove hardlinks
						break;
					}
					
					final int id = u4;
					bytes_left = id_bytes;
					u4         = 0;
					
					if ((slot = slot_ref.get()) == null) slot_ref = new SoftReference<>(slot = new Slot(null));
					
					if ((slot.dst = int_dst.receiving(this, id)) == null)
					{
						slot = null;
						break;
					}
					u8         = 0;
					slot.state = 0;
				}
				else switch (mode)
				{
					case VAL8:
						if (buffer.remaining() < bytes_left)
						{
							int r = buffer.remaining();
							u8 = u8 << r * 8 | get8(r);
							bytes_left -= r;
							break write;
						}
						
						u8 = u8 << bytes_left * 8 | get8(bytes_left);
						
						break;
					case VAL4:
						if (not_get4()) break write;
						break;
					case LEN:
						if (not_get4()) break write;
						
						index_max(u4);
						break;
					case VARINT:
						if (buffer.hasRemaining() && retry_get_varint(state())) break;
						break write;
					case BASE_LEN:
						if (not_get4()) break write;
						
						base_index_max(u4);
						break;
					case STR:
						if (!string()) break write;
						break;
					case DONE:
						break;
				}
				
				mode = OK;
				
				for (AdHoc.INT.BytesDst dst; ; )
					if ((dst = slot.dst.put_bytes(this)) == null)
					{
						if (mode < OK) break write;  //provided, received data ended
						if (slot.prev == null) break; //it was the root, all received. now dispatching
						
						//slot.dst = null; //back from depth. do not clean up, can be used
						
						free_slot();
					}
					else //deepening into the hierarchy
					{
						slot       = slot.next == null ? slot.next = new Slot(slot) : slot.next;
						slot.dst   = dst;
						slot.state = 0;
					}
				
				bytes_left = id_bytes;// !!!!!!!!!!!!!
				u4         = 0;
				slot.state = 0;
				
				if (pack_by_pack_mode) return remaining - src.remaining();//do not clean up, do not dispatch, return length of processed bytes
				
				int_dst.received(this, slot.dst);//dispatching
				slot.dst = null; //ready to read next packet data
				
			}//write: loop
			
			buffer = null;
			
			return remaining;
		}
		
		
		public void retry_at(int the_case) {
			slot.state = the_case;
			mode       = DONE;
		}
		
		
		public byte get() {return buffer.get();}
		
		public int getU() {return buffer.get() & 0xFF;}
		
		public boolean no_items_data(int retry_at_case, int no_items_case) {
			for (int nulls; buffer.hasRemaining(); )
			{
				if ((nulls = buffer.get() & 0xFF) != 0)
				{
					slot.index += trailingZeros(slot.items_nulls = nulls);
					return false;
				}
				if (slot.index_max <= (slot.index += 8))
				{
					state(no_items_case);
					return false;
				}
			}
			retry_at(retry_at_case);
			return true;
		}
		
		public boolean no_index(int on_fail_case, int on_fail_fix_index) {
			if (buffer.hasRemaining()) return false;
			retry_at(on_fail_case);
			index(on_fail_fix_index);
			return true;
		}
		
		public boolean no_base_index(int on_fail_case, int fix_base_index_on_fail) {
			if (buffer.hasRemaining()) return false;
			retry_at(on_fail_case);
			base_index(fix_base_index_on_fail);
			return true;
		}
		
		public int remaining()                 {return buffer.remaining();}
		
		public int position()                  {return buffer.position();}
		
		public boolean try_get8(int next_case) {return try_get8(bytes_left, next_case);}
		
		public boolean try_get8(int bytes, int next_case) {
			if (buffer.remaining() < bytes) return retry_get8(bytes, next_case);
			u8 = get8(bytes);
			return true;
		}
		
		public boolean retry_get8(int bytes, int get8_case) {
			bytes_left = bytes - buffer.remaining();
			u8         = get8(buffer.remaining());
			slot.state = get8_case;
			mode       = VAL8;
			return false;
		}
		
		public long get8() {return u8;}
		
		public long get8(int byTes) {
			long u8 = 0;
			
			switch (byTes)
			{
				case 8:
					u8 |= (buffer.get() & 0xFFL) << 56;
				case 7:
					u8 |= (buffer.get() & 0xFFL) << 48;
				case 6:
					u8 |= (buffer.get() & 0xFFL) << 40;
				case 5:
					u8 |= (buffer.get() & 0xFFL) << 32;
				case 4:
					u8 |= (buffer.get() & 0xFFL) << 24;
				case 3:
					u8 |= (buffer.get() & 0xFFL) << 16;
				case 2:
					u8 |= (buffer.get() & 0xFFL) << 8;
				case 1:
					u8 |= buffer.get() & 0xFFL;
			}
			return u8;
		}
		
		public boolean try_get4(int next_case) {return try_get4(bytes_left, next_case);}
		
		public boolean try_get4(int bytes, int next_case) {
			if (buffer.remaining() < bytes) return retry_get4(bytes, next_case);
			u4 = get4(bytes);
			return true;
		}
		
		public boolean retry_get4(int bytes, int get4_case) {
			bytes_left = bytes - buffer.remaining();
			u4         = get4(buffer.remaining());
			slot.state = get4_case;
			mode       = VAL4;
			return false;
		}
		
		public double get_double() {return buffer.getDouble();}
		
		public float get_float()   {return buffer.getFloat();}
		
		public double as_double()  {return Double.longBitsToDouble(u8);}
		
		public float as_float()    {return Float.intBitsToFloat(u4);}
		
		public int get4()          {return u4;}
		
		public int get4(int bytes) {
			int u4 = 0;
			switch (bytes)
			{
				case 4:
					u4 |= (buffer.get() & 0xFF) << 24;
				case 3:
					u4 |= (buffer.get() & 0xFF) << 16;
				case 2:
					u4 |= (buffer.get() & 0xFF) << 8;
				case 1:
					u4 |= buffer.get() & 0xFF;
			}
			return u4;
		}

//region bits
		
		public void init_bits() {//initialization receive bit
			bits = 0;
			bit  = 8;
		}
		
		public byte get_bits() {return (byte) u4;}
		
		
		public int get_bits(int len_bits) {
			int ret;
			if (bit + len_bits < 9)
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
		
		public boolean try_get_bits(int len_bits, int this_case) {
			if (bit + len_bits < 9)
			{
				u4 = bits >> bit & 0xFF >> 8 - len_bits;
				bit += len_bits;
			}
			else if (buffer.hasRemaining())
			{
				u4  = (bits >> bit | (bits = buffer.get() & 0xFF) << 8 - bit) & 0xFF >> 8 - len_bits;
				bit = bit + len_bits - 8;
			}
			else
			{
				retry_at(this_case);
				return false;
			}
			return true;
		}

//endregion
		
		public short zig_zag2(long src) {return (short) (-(src & 1) ^ src >>> 1);}
		
		public int zig_zag4(long src)   {return (int) (-(src & 1) ^ src >>> 1);}
		
		public long zig_zag8(long src)  {return -(src & 1) ^ src >>> 1;}
		
		public boolean try_get_varint(int next_case) {
			u8         = 0;
			bytes_left = 0;
			
			return retry_get_varint(next_case);
		}
		
		private boolean retry_get_varint(int next_case) {
			
			while (buffer.hasRemaining())
			{
				byte b = buffer.get();
				if (b < 0)
				{
					u8 |= (b & 0x7FL) << bytes_left;
					bytes_left += 7;
					continue;
				}
				
				u8 |= (long) b << bytes_left;
				return true;
			}
			state(next_case);
			mode = VARINT;
			return false;
		}
		
		
		//region temporary store received params
		private SoftReference<byte[]> buff_ref = new SoftReference<>(null); //temporary buffer for the received string
		private byte[]                buff     = null;
		public void init_buff() {
			if ((buff = buff_ref.get()) == null) buff = new byte[512];
		}
		
		public void clean_buff() {buff = null;}
		
		public int get(int pos, int bytes) {
			int u4 = 0;
			switch (bytes)
			{
				case 4:
					u4 |= (buff[pos + 3] & 0xFF) << 24;
				case 3:
					u4 |= (buff[pos + 2] & 0xFF) << 16;
				case 2:
					u4 |= (buff[pos + 1] & 0xFF) << 8;
				case 1:
					u4 |= buff[pos] & 0xFF;
			}
			return u4;
		}
		
		public void put(int pos, int bytes) {
			switch (bytes)
			{
				case 4:
					buff[pos + 3] = (byte) (u4 >> 24 & 0xFF);
				case 3:
					buff[pos + 2] = (byte) (u4 >> 16 & 0xFF);
				case 2:
					buff[pos + 1] = (byte) (u4 >> 8 & 0xFF);
				case 1:
					buff[pos] = (byte) (u4 & 0xFF);
			}
		}

//endregion
		
		//getting the result of an offline fill
		public String get_string() {
			String ret = internal_string;
			internal_string = null;
			return ret;
		}
		public boolean get_string(int get_string_case) {
			
			if ((buff = buff_ref.get()) == null) buff = new byte[512];
			internal_string = null;
			bytes_left      = 0;
			
			if (string()) return true;
			
			slot.state = get_string_case;
			mode       = STR; //lack of received bytes, switch to reading lines offline
			return false;
		}
		
		public boolean string() {
			for (byte b; buffer.hasRemaining(); bytes_left++)
				if ((b = buffer.get()) == (byte) 0xFF)
				{
					internal_string = new String(buff, 0, bytes_left, StandardCharsets.UTF_8);
					if (buff_ref.get() != buff) buff_ref = new SoftReference<>(buff);
					buff       = null;
					bytes_left = 0;
					return true;
				}
				else (bytes_left == buff.length - 1 ? buff = Arrays.copyOf(buff, bytes_left + bytes_left / 2) : buff)[bytes_left] = b;
			return false;
		}
		public boolean isOpen() {return slot != null;}
		
		public void close()     {write(null);}
		
		@Override public String toString() {
			Slot s = slot;
			while (s.prev != null) s = s.prev;
			StringBuilder str    = new StringBuilder();
			String        offset = "";
			for (; s != slot; s = s.next, offset += "\t")
			     str.append(offset).append(s.dst.getClass().getCanonicalName()).append("\t").append(state()).append("\n");
			
			str.append(offset).append(s.dst.getClass().getCanonicalName()).append("\t").append(state()).append("\n");
			
			return str.toString();
		}
	}
	
	public static class Transmitter extends AdHoc implements EXT.BytesSrc, Context.Provider {
		public AdHoc.INT.BytesSrc.Producer int_src;
		public LongSupplier                int_values_src;
		
		public Transmitter(AdHoc.INT.BytesSrc.Producer int_src, LongSupplier int_values_src) {
			this.int_src        = int_src;
			this.int_values_src = int_values_src;
		}
		
		public static class Framing implements EXT.BytesSrc {
			
			public Transmitter src;
			public Framing(Transmitter src) {
				src.pack_by_pack_mode = true;//switch to pack-by-pack mode
				this.src              = src;
			}
			
			@Override public int read(ByteBuffer dst) {
				if (dst == null)
				{
					src.read(null);
					bits  = 0;
					shift = 0;
					crc   = 0;
					return -1;
				}
				
				final int fix_position = dst.position();
				
				while (dst.hasRemaining())
				{
					final boolean write_starting_frame_byte_FF = src.slot == null || src.slot.src == null;
					
					final int enc_position = dst.position();//where start to put encoded bytes
					int       raw_position = enc_position + dst.remaining() / 8 + CRC_LEN_BYTES + 1 + 2;// + 1 for 0xFF byte - frame start mark. start position for temporarily storing raw bytes from the source
					
					dst.position(raw_position);
					
					int len = src.read(dst);
					
					final int raw_max = dst.position();
					dst.position(enc_position);
					
					if (len < 1) return fix_position < enc_position ? enc_position - fix_position : len;
					
					if (write_starting_frame_byte_FF) dst.put((byte) 0xFF);//write starting frame byte
					
					for (; raw_position < raw_max; raw_position++) encode(dst.get(raw_position) & 0xFF, dst);
					
					if (src.slot == null || src.slot.src == null)//the packet sending completed
					{
						final int fix = crc;// crc will continue counting on call encode(), so fix it
						encode(fix >> 8 & 0xFF, dst);
						encode(fix & 0xFF, dst);
						if (0 < shift) dst.put((byte) bits);
						
						bits  = 0;
						shift = 0;
						crc   = 0;
					}
				}
				
				return fix_position < dst.position() ? dst.position() - fix_position : 0;
			}
			
			private void encode(int src, ByteBuffer dst) {
				
				crc = crc16(src, crc);
				final int v = (bits |= src << shift) & 0xFF;
				
				if ((v & 0x7F) == 0x7F)
				{
					dst.put((byte) 0x7F);
					bits >>= 7;
					
					if (shift < 7) shift++;
					else //                          a full byte in enc_bits
					{
						if ((bits & 0x7F) == 0x7F)
						{
							dst.put((byte) 0x7F);
							bits >>= 7;
							
							shift = 1;
							return;
						}
						
						dst.put((byte) bits);
						shift = 0;
						
						bits = 0;
					}
					return;
				}
				
				dst.put((byte) v);
				bits >>= 8;
			}
			
			private int  bits  = 0;
			private int  shift = 0;
			private char crc   = 0;
			@Override public boolean isOpen() {return src.isOpen();}
			@Override public void close()     {read(null);}
		}


//region Slot
		
		private static final class Slot {
			
			int                state;
			AdHoc.INT.BytesSrc src;
			int                base_index;
			int                base_index2;
			int                base_index_max;
			int                fields_nulls;
			
			int index;
			int index2;
			int index_max;
			
			Slot next;
			final Slot prev;
			
			public Slot(Slot prev) {
				this.prev = prev;
				if (prev != null) prev.next = this;
			}
			
			
			ContextExt context;
		}
		
		protected SoftReference<Slot> slot_ref = new SoftReference<>(new Slot(null));
		protected Slot                slot;
		
		private void free_slot() {
			if (slot.context != null)
			{
				context      = slot.context.prev;
				slot.context = null;
			}
			
			slot = slot.prev;
		}
//endregion

//region Context
		
		private static class ContextExt extends Context {
			
			public       ContextExt next;
			public final ContextExt prev;
			
			public ContextExt(ContextExt prev) {
				this.prev = prev;
				if (prev != null) prev.next = this;
			}
		}
		
		
		private ContextExt                context;
		private SoftReference<ContextExt> context_ref = new SoftReference<>(new ContextExt(null));
		
		public Context context() {
			
			if (slot.context != null) return slot.context;
			
			if (context == null && (context = context_ref.get()) == null) context_ref = new SoftReference<>(context = new ContextExt(null));
			else if (context.next == null) context = context.next = new ContextExt(context);
			else context = context.next;
			
			return slot.context = context;
		}

//endregion
		
		public int state()            {return slot.state;}
		
		public void state(int value)  {slot.state = value;}
		
		
		public int position()         {return buffer.position();}
		
		public int remaining()        {return buffer.remaining();}
		
		public int index()            {return slot.index;}
		
		public int index(int value)   {return slot.index = value;}
		
		public int index2()           {return slot.index2;}
		
		public void index2(int value) {slot.index2 = value;}
		
		public int index_max()        {return slot.index_max;}
		
		public int index_max(int max) {
			slot.index = 0;
			return slot.index_max = max;
		}
		public boolean index_less_max(int jump_case) {
			if (slot.index_max <= slot.index) return false;
			state(jump_case);
			return true;
		}
		
		
		public boolean index_max_zero(int on_zero_case) {
			if (0 < slot.index_max) return false;
			state(on_zero_case);
			return true;
		}
		
		public int base_index()          {return slot.base_index;}
		
		public int base_index(int value) {return slot.base_index = value;}
		
		public int base_index_max()      {return slot.base_index_max;}
		
		public int base_index_max(int base_len) {
			slot.base_index = 0;
			return slot.base_index_max = base_len;
		}
		
		
		public void base_index2(int value) {slot.base_index2 = value;}
		
		public boolean next_index2()       {return ++slot.index < slot.index2;}
		
		public boolean next_index()        {return ++slot.index < slot.index_max;}
		
		public boolean next_index(int yes_case) {
			if (++slot.index < slot.index_max)
			{
				state(yes_case);
				return true;
			}
			return false;
		}
		
		public boolean next_index(int yes_case, int no_case) {
			
			if (++slot.index < slot.index_max)
			{
				state(yes_case);
				return true;
			}
			state(no_case);
			return false;
		}
		
		
		public int index_next(int next_state) {
			++slot.index;
			state(slot.index_max == slot.index ? next_state + 1 : next_state);
			return slot.index - 1;
		}
		
		
		public boolean base_index_less_max(int jump_case) {
			if (slot.base_index_max <= slot.base_index) return false;
			state(jump_case);
			return true;
		}
		
		public boolean next_base_index2() {return ++slot.base_index < slot.base_index2;}
		
		public boolean next_base_index()  {return ++slot.base_index < slot.base_index_max;}
		
		
		public boolean init_fields_nulls(int field0_bit, int current_case) {
			if (!allocate(1, current_case)) return false;
			slot.fields_nulls = field0_bit;
			return true;
		}
		
		public void set_fields_nulls(int field) {slot.fields_nulls |= field;}
		
		public void flush_fields_nulls()        {put((byte) slot.fields_nulls);}
		
		public boolean is_null(int field, int next_field_case) {
			if ((slot.fields_nulls & field) == 0)
			{
				state(next_field_case);
				return true;
			}
			return false;
		}
		
		// if dst == null - clean / reset state
		//
		// if 0 < return - bytes read
		// if return == 0 - not enough space available
		// if return == -1 -  no more packets left
		public int read(ByteBuffer dst) {
			
			if (dst == null)//reset
			{
				if (slot == null) return -1;
				buffer = null;
				
				while (slot != null)
				{
					slot.src = null;
					free_slot();
				}
				
				mode = OK;
				
				u4         = 0;
				bytes_left = 0; //requires correct bitwise sending
				
				return -1;
			}
			
			buffer = dst;
			final int position = buffer.position();
read:
			for (; ; )
			{
				if (slot == null || slot.src == null)
				{
					if ((slot = slot_ref.get()) == null) slot_ref = new SoftReference<>(slot = new Slot(null));
					
					if ((slot.src = int_src.sending(this)) == null)
					{
						final int ret = buffer.position() - position;
						buffer = null;
						free_slot();//remove hard links
						
						return 0 < ret ? ret : -1;
					}
					
					slot.state = 0; //write id request
					
					u4         = 0;
					bytes_left = 0;
					slot.index = 0;
				}
				else switch (mode) //the packet transmission was interrupted, recall where we stopped
				{
					case STR:
						if (!encode(internal_string)) break read;
						internal_string = null;
						break;
					case VAL4:
						if (buffer.remaining() < bytes_left) break read;
						put_val(u4, bytes_left);
						break;
					case VAL8:
						if (buffer.remaining() < bytes_left) break read;
						put_val(u8, bytes_left);
						break;
					case VARINTS:
						if (buffer.remaining() < 25) break read;//space for one full transaction
						bits_byte = buffer.position();//preserve space for bits info
						buffer.position(bits_byte + 1);
						put_val(u8, bytes_left);
						break;
					case VARINT:
						if (buffer.hasRemaining() && put_varint(u8, state())) break;
						break read;
					case BITS:
						if (buffer.remaining() < 4) break read;
						bits_byte = buffer.position();//preserve space for bits info
						buffer.position(bits_byte + 1);
						break;
				}
				mode = OK; //restore the state
				
				for (AdHoc.INT.BytesSrc src; ; )
					if ((src = slot.src.get_bytes(this)) == null) //not going deeper in the hierarchy
					{
						if (mode < OK) break read; //there is not enough space in the provided buffer for further work
						
						if (slot.prev == null) break; //it was the root level all packet data sent
						
						//slot.src = null               // do not do this. sometime can be used
						free_slot();
					}
					else  //go into the hierarchy deeper
					{
						slot       = slot.next == null ? slot.next = new Slot(slot) : slot.next;
						slot.src   = src;
						slot.state = 1; //skip write id
					}
				
				int_src.sent(this, slot.src);
				slot.src = null; //sing of next packet data request
				if (!pack_by_pack_mode) continue;
				
				free_slot();//remove hard links
				break;
			}
			
			int ret = buffer.position() - position;
			buffer = null;
			
			return ret; // number of bytes read
		}// read loop
		
		
		public void put(Boolean src) {put_bits(src == null ? 0 : src ? 1 : 2, 2);}
		
		public void put(boolean src) {put_bits(src ? 1 : 0, 1);}
		
		
		public boolean allocate(int bytes, int current_case) {
			if (bytes <= buffer.remaining()) return true;
			slot.state = current_case;
			mode       = DONE;
			return false;
		}

//region bits
		
		private int bits_byte = -1;
		
		public boolean allocate(int current_case) { //space request (20 bytes) for at least one transaction is called once on the first varint, as continue of `init_bits`
			if (17 < buffer.remaining()) return true;
			
			state(current_case);
			buffer.position(bits_byte);//trim byte at bits_byte index
			
			mode = BITS;
			return false;
		}
		
		public boolean init_bits(int current_case) {return init_bits(20, current_case);}//varint init_bits
		
		public boolean init_bits(int allocate_bytes, int current_case) {
			if (buffer.remaining() < allocate_bytes)
			{
				slot.state = current_case;
				mode       = DONE;
				return false;
			}
			
			bits = 0;
			bit  = 0;
			
			bits_byte = buffer.position();//place fixation
			buffer.position(bits_byte + 1);
			return true;
		}
		
		
		//check, if in bits enougt data, then flush first `bits` byte into uotput buffer at bits_byte index
		//and switch to new place - bits_byte
		public boolean put_bits(int src, int len_bits) {
			bits |= src << bit;
			if ((bit += len_bits) < 9) return false; //yes 9! not 8!  to avoid allocating the next byte after the current one is full. it is might be redundant
			
			buffer.put(bits_byte, (byte) bits);//sending
			
			bits >>= 8;
			bit -= 8;
			
			bits_byte = buffer.position();
			if (buffer.hasRemaining()) buffer.position(bits_byte + 1);
			return true;
		}
		
		public void end_bits() {
			if (0 < bit) buffer.put(bits_byte, (byte) bits);
			else buffer.position(bits_byte);//trim byte at bits_byte index. allocated, but not used
		}
		
		public void continue_bits_at(int continue_at_case) {
			state(continue_at_case);
			buffer.position(bits_byte);//trim byte at bits_byte index
			mode = BITS;
		}


//endregion
		
		//region single varint
		public boolean put_varint(long src, int next_case) {
			while (buffer.hasRemaining())
			{
				if ((src & ~0x7F) == 0)
				{
					buffer.put((byte) src);
					return true;
				}
				buffer.put((byte) (~0x7F | src & 0x7F));
				src >>>= 7;
			}
			
			u8 = src;
			state(next_case);
			mode = VARINT;
			return false;
		}
//endregion

//region varint collection
		
		private static int bytes1(long src) {return src < 1 << 8 ? 1 : 2;}
		
		public boolean put_varint21(long src, int continue_at_case) {
			int bytes = bytes1(src);
			return put_varint(bytes - 1, 1, src & 0xFFFFL, bytes, continue_at_case);
		}
		
		public boolean put_varint211(long src, int continue_at_case) {
			int bytes = bytes1(src);
			
			return put_varint(bytes - 1 << 1 | 1, 2, src & 0xFFFFL, bytes, continue_at_case);
		}
		
		public long zig_zag(short src)      {return (src << 1 ^ (int) src >> 15) & 0xFFFFL;}
		
		private static int bytes2(long src) {return src < 1 << 8 ? 1 : src < 1 << 16 ? 2 : 3;}
		
		public boolean put_varint32(long src, int continue_at_case) {
			if (src == 0) return put_varint(2, continue_at_case);
			
			int bytes = bytes2(src);
			return put_varint(bytes, 2, src & 0xFFFF_FFL, bytes, continue_at_case);
		}
		
		public boolean put_varint321(long src, int continue_at_case) {
			if (src == 0) return put_varint(3, continue_at_case);
			
			int bytes = bytes2(src);
			return put_varint(bytes << 1 | 1, 3, src & 0xFFFF_FFL, bytes, continue_at_case);
		}
		
		
		public long zig_zag(int src)        {return (src << 1 ^ src >> 31) & 0xFFFF_FFFFL;}
		
		private static int bytes3(long src) {return src < 1L << 16 ? src < 1L << 8 ? 1 : 2 : src < 1L << 24 ? 3 : 4;}
		
		public boolean put_varint42(long src, int continue_at_case) {
			int bytes = bytes3(src);
			return put_varint(bytes - 1, 2, src & 0xFFFF_FFFFL, bytes, continue_at_case);
		}
		
		public boolean put_varint421(long src, int continue_at_case) {
			int bytes = bytes3(src);
			return put_varint(bytes - 1 << 1 | 1, 3, src & 0xFFFF_FFFFL, bytes, continue_at_case);
		}
		
		public long zig_zag(long src) {return src << 1 ^ src >> 63;}
		
		private static int bytes4(long src) {
			return src < 1 << 24 ? src < 1 << 16 ? src < 1 << 8 ? 1 : 2 : 3 :
			       src < 1L << 32 ? 4 :
			       src < 1L << 40 ? 5 :
			       src < 1L << 48 ? 6 : 7;
		}
		
		public boolean put_varint73(long src, int continue_at_case) {
			if (src == 0) return put_varint(3, continue_at_case);
			
			int bytes = bytes4(src);
			
			return put_varint(bytes, 3, src, bytes, continue_at_case);
		}
		public boolean put_varint731(long src, int continue_at_case) {
			if (src == 0) return put_varint(4, continue_at_case);
			
			int bytes = bytes4(src);
			
			return put_varint(bytes << 1 | 1, 4, src, bytes, continue_at_case);
		}
		
		private static int bytes5(long src) {
			return src < 0 ? 8 : src < 1L << 32 ? src < 1 << 16 ? src < 1 << 8 ? 1 : 2 :
			                                      src < 1 << 24 ? 3 : 4 :
			                     src < 1L << 48 ? src < 1L << 40 ? 5 : 6 :
			                     src < 1L << 56 ? 7 : 8;
		}
		
		
		public boolean put_varint83(long src, int continue_at_case) {
			int bytes = bytes5(src);
			return put_varint(bytes - 1, 3, src, bytes, continue_at_case);
		}
		public boolean put_varint831(long src, int continue_at_case) {
			
			int bytes = bytes5(src);
			return put_varint(bytes - 1 << 1 | 1, 4, src, bytes, continue_at_case);
		}
		
		public boolean put_varint84(long src, int continue_at_case) {
			if (src == 0) return put_varint(4, continue_at_case);
			
			int bytes = bytes5(src);
			
			return put_varint(bytes, 4, src, bytes, continue_at_case);
		}
		
		public boolean put_varint841(long src, int continue_at_case) {
			if (src == 0) return put_varint(5, continue_at_case);
			
			int bytes = bytes5(src);
			
			return put_varint(bytes << 1 | 1, 5, src, bytes, continue_at_case);
		}
		
		
		public boolean put_varint(int bits, int continue_at_case) {
			if (!put_bits(0, bits) || 20 < remaining()) return true;
			continue_bits_at(continue_at_case);
			return false;
		}
		
		private boolean put_varint(int bytes_info, int bits, long varint, int bytes, int continue_at_case) {
			//                                                   break here is OK
			if (put_bits(bytes_info, bits) && remaining() < 25)//wost case 83: 3 bits x 3times x 8 bytes
			{
				u8         = varint; //fix value
				bytes_left = bytes;//fix none zero LSB length
				
				state(continue_at_case);
				buffer.position(bits_byte);
				mode = VARINTS;
				return false;
			}
			
			put_val(varint, bytes);
			return true;
		}
//endregion
		
		public boolean put_val(long src, int bytes, int next_case) {
			if (buffer.remaining() < bytes)
			{
				put(src, bytes, next_case);
				return false;
			}
			
			put_val(src, bytes);
			return true;
		}
		private void put_val(long src, int bytes) {
			
			switch (bytes)
			{
				case 8:
					buffer.put((byte) (src >>> 56 & 0xFF));
				case 7:
					buffer.put((byte) (src >> 48 & 0xFF));
				case 6:
					buffer.put((byte) (src >> 40 & 0xFF));
				case 5:
					buffer.put((byte) (src >> 32 & 0xFF));
				case 4:
					buffer.put((byte) (src >> 24 & 0xFF));
				case 3:
					buffer.put((byte) (src >> 16 & 0xFF));
				case 2:
					buffer.put((byte) (src >> 8 & 0xFF));
				case 1:
					buffer.put((byte) (src & 0xFF));
			}
		}
		
		
		public boolean put_len(int len, int bytes, int next_case) {
			slot.index_max = len;
			slot.index     = 0;
			return put_val((int) len, bytes, next_case);
		}
		
		
		public boolean no_more_items(int key_value_case, int end_case) {
			if (++slot.index < slot.index_max) return false;
			if (0 < index2())
			{
				index_max(index2());
				state(key_value_case);
			}
			else state(end_case);
			
			return true;
		}
		
		public boolean no_more_items(int next_field_case) {
			if (0 < index_max(index2())) return false;
			
			state(next_field_case);
			return true;
		}
		
		//The method is split. cause of items == 0 no more queries!
		public boolean zero_items(int items, int next_field_case) {
			if (items == 0)
			{
				put((byte) 0);
				state(next_field_case);
				return true;
			}
			
			index_max(items);
			return false;
		}
		
		
		public boolean put_set_info(boolean null_key_present, int next_field_case) {
			int items         = index_max();
			int null_key_bits = 0;
			
			if (null_key_present)
			{
				null_key_bits = 1 << 7;
				if (--items == 0)
				{
					put((byte) null_key_bits);
					state(next_field_case);
					return true;
				}
			}
			
			index_max(items);//key-value items
			int bytes = bytes4value(items);
			
			put((byte) (null_key_bits | bytes));
			put_val(items, bytes, 0);
			return false;
		}
		
		public boolean put_map_info(boolean null_key_present, boolean null_key_has_value, int keys_null_value_count, int next_case, int key_val_case, int next_field_case) {
			int items = index_max();
			
			int null_key_bits = null_key_has_value ? 1 << 6 : 0;
			
			if (null_key_present)
			{
				null_key_bits |= 1 << 7;
				if (--items == 0)
				{
					put((byte) null_key_bits);
					state(next_field_case);
					return true;
				}
			}
			if (0 < keys_null_value_count)
			{
				index_max(keys_null_value_count); //keys with null value
				int keys_null_value_count_bytes = bytes4value(keys_null_value_count);
				
				items -= keys_null_value_count;
				index2(items);//key-value items preserve
				int key_val_count_bytes = bytes4value(items);
				
				put((byte) (null_key_bits | keys_null_value_count_bytes << 3 | key_val_count_bytes));
				if (0 < items) put_val(items, key_val_count_bytes, 0);
				put_val(keys_null_value_count, keys_null_value_count_bytes, 0);
				
				state(next_case);
				return false;
			}
			
			state(key_val_case);
			index_max(items);//key-value items
			int bytes = bytes4value(items);
			
			put((byte) (null_key_bits | bytes));
			put_val(items, bytes, 0);
			return true;
		}
		
		
		public boolean put_base_len(int base_len, int bytes, int next_case) {
			slot.base_index_max = base_len;
			slot.base_index     = 0;
			return put_val((int) base_len, bytes, next_case);
		}
		
		
		public boolean put_val(int src, int bytes, int next_case) {
			if (buffer.remaining() < bytes)
			{
				put(src, bytes, next_case);
				return false;
			}
			
			put_val(src, bytes);
			return true;
		}
		
		public void put_val(int src, int bytes) {
			switch (bytes)
			{
				case 4:
					buffer.put((byte) (src >> 24 & 0xFF));
				case 3:
					buffer.put((byte) (src >> 16 & 0xFF));
				case 2:
					buffer.put((byte) (src >> 8 & 0xFF));
				case 1:
					buffer.put((byte) (src & 0xFF));
			}
		}
		
		public boolean put(String str, int next_case) {
			bytes_left = 0;
			
			if (encode(str)) return true;
			
			slot.state           = next_case;
			this.internal_string = str;
			mode                 = STR;
			return false;
		}
		
		public boolean encode(String str) {
			for (int len = str.length(); bytes_left < len; )
			{
				if (buffer.remaining() < 5) return false;//place for the longest character + one byte for 0xFF (string terminator)
				
				final char ch = str.charAt(bytes_left++);
				
				if (ch < 0x80) buffer.put((byte) ch);// Have at most seven bits
				else if (ch < 0x800)
				{
					buffer.put((byte) (0xc0 | ch >> 6));// 2 bytes, 11 bits
					buffer.put((byte) (0x80 | ch & 0x3f));
				}
				else if ('\uD800' <= ch && ch <= '\uDFFF')
				{
					int ch2 = str.charAt(bytes_left);
					
					if ('\uD800' <= ch2 && ch2 < '\uDBFF' + 1 && bytes_left + 1 < str.length())
					{
						final int ch3 = str.charAt(bytes_left + 1);
						if ('\uDC00' <= ch3 && ch3 < '\uDFFF' + 1)
							ch2 = (ch2 << 10) + ch3 + 0x010000 - ('\uD800' << 10) - '\uDC00';
					}
					
					if (ch2 == ch) buffer.put((byte) '?');
					else
					{
						buffer.put((byte) (0xf0 | ch2 >> 18));
						buffer.put((byte) (0x80 | ch2 >> 12 & 0x3f));
						buffer.put((byte) (0x80 | ch2 >> 6 & 0x3f));
						buffer.put((byte) (0x80 | ch2 & 0x3f));
						bytes_left++;  // 2 chars
					}
				}
				else
				{
					buffer.put((byte) (0xe0 | ch >> 12));// 3 bytes, 16 bits
					buffer.put((byte) (0x80 | ch >> 6 & 0x3f));
					buffer.put((byte) (0x80 | ch & 0x3f));
				}
			}
			if (buffer.remaining() == 0) return false;
			buffer.put((byte) 0xFF); // string end sign
			bytes_left = 0;
			return true;
		}
		
		private void put(int src, int bytes, int next_case) {
			slot.state = next_case;
			bytes_left = bytes;
			u4         = src;
			mode       = VAL4;
		}
		
		private void put(long src, int bytes, int next_case) {
			slot.state = next_case;
			bytes_left = bytes;
			u8         = src;
			mode       = VAL8;
		}
		
		public void retry_at(int the_case) {
			slot.state = the_case;
			mode       = DONE;
		}
		
		
		public int bytes4value(int value) {return value < 0xFFFF ? value < 0xFF ? value == 0 ? 0 : 1 : 2 : value < 0xFFFFFF ? 3 : 4;}
		
		public boolean put(byte src, int next_case) {
			if (buffer.hasRemaining())
			{
				put(src);
				return true;
			}
			
			put(src, 1, next_case);
			return false;
		}
		
		public void put(byte src) {buffer.put(src);}
		
		public boolean put(short src, int next_case) {
			if (buffer.remaining() < 2)
			{
				put(src, 2, next_case);
				return false;
			}
			
			put(src);
			return true;
		}
		
		public void put(short src) {buffer.putShort(src);}
		
		public boolean put(char src, int next_case) {
			if (buffer.remaining() < 2)
			{
				put(src, 2, next_case);
				return false;
			}
			
			put(src);
			return true;
		}
		
		public void put(char src) {buffer.putChar(src);}
		
		public boolean put(int src, int next_case) {
			if (buffer.remaining() < 4)
			{
				put(src, 4, next_case);
				return false;
			}
			
			put(src);
			return true;
		}
		
		public void put(int src) {buffer.putInt(src);}
		
		public boolean put(long src, int next_case) {
			if (buffer.remaining() < 8)
			{
				put(src, 8, next_case);
				return false;
			}
			
			put(src);
			return true;
		}
		
		public void put(long src)                     {buffer.putLong(src);}
		
		public void put(float src)                    {buffer.putFloat(src);}
		
		public boolean put(float src, int next_case)  {return put(Float.floatToIntBits(src), next_case);}
		
		public void put(double src)                   {buffer.putDouble(src);}
		
		public boolean put(double src, int next_case) {return put(Double.doubleToLongBits(src), next_case);}
		//has data
		public boolean isOpen() {return slot != null;}
		
		//cleanup on close
		public void close() {read(null);}
		
		@Override public String toString() {
			Slot s = slot;
			while (s.prev != null) s = s.prev;
			StringBuilder str    = new StringBuilder();
			String        offset = "";
			for (; s != slot; s = s.next, offset += "\t")
			     str.append(offset).append(s.src.getClass().getCanonicalName()).append("\t").append(state()).append("\n");
			
			str.append(offset).append(s.src.getClass().getCanonicalName()).append("\t").append(state()).append("\n");
			
			return str.toString();
		}
	}
}