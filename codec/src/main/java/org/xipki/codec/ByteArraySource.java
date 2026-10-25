// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Reads bytes from a part of a byte array. Used by the ASN.1 and CBOR decoders.
 *
 * @author Lijun Liao (xipki)
 */
public final class ByteArraySource {

  private final byte[] bytes;

  private final int startPosition;

  private final int maxPosition; // exclusive

  private int position;

  public ByteArraySource(byte[] bytes) {
    this.bytes = Args.notNull(bytes, "bytes");
    this.position = 0;
    this.startPosition = 0;
    this.maxPosition = bytes.length;
  }

  /**
   * Creates a new {@link ByteArraySource} instance.
   * @param bytes the bytes.
   * @param offset offset of the bytes to read.
   * @param len number of the bytes to read.
   * @throws IOException if offset and len exceed the bytes.
   */
  public ByteArraySource(byte[] bytes, int offset, int len) throws IOException {
    Args.notNull(bytes, "bytes");
    Args.min(offset, "offset", 0);
    Args.min(len, "len", 0);
    if (len > bytes.length - offset) {
      throw new IOException("bytes too short");
    }
    this.bytes = bytes;
    this.position = offset;
    this.startPosition = offset;
    this.maxPosition = offset + len;
  }

  public int position() {
    return position;
  }

  public boolean hasMoreBytes() {
    return position < maxPosition;
  }

  public int remainingBytesSize() {
    return maxPosition - position;
  }

  public byte[] remainingBytes() {
    return Arrays.copyOfRange(bytes, position, maxPosition);
  }

  public void writeConsumedBytes(OutputStream os) throws IOException {
    os.write(bytes, startPosition, position - startPosition);
  }

  public int peek1Byte() throws CodecException {
    ensureAvailable(1);
    return 0xFF & bytes[position];
  }

  public byte[] peekBytes(int num) throws CodecException {
    ensureAvailable(num);
    return Arrays.copyOfRange(bytes, position, position + num);
  }

  public int read1Byte() throws CodecException {
    ensureAvailable(1);
    return 0xFF & bytes[position++];
  }

  public byte[] readExactly(int len) throws CodecException {
    ensureAvailable(len);
    byte[] ret = Arrays.copyOfRange(bytes, position, position + len);
    position += len;
    return ret;
  }

  public String readUtf8String(int len) throws CodecException {
    ensureAvailable(len);
    String str = new String(bytes, position, len, StandardCharsets.UTF_8);
    position += len;
    return str;
  }

  /**
   * Reads an unsigned big-endian integer.
   * @param numBytes number of bytes, at most 8.
   * @return the integer. For 8 bytes, values above {@link Long#MAX_VALUE} are negative.
   * @throws CodecException if the bytes are too short.
   */
  public long readUInt(int numBytes) throws CodecException {
    ensureAvailable(numBytes);
    long v = 0;
    for (int i = 0; i < numBytes; i++) {
      v = (v << 8) | (bytes[position++] & 0xFFL);
    }
    return v;
  }

  private void ensureAvailable(int len) throws CodecException {
    // len > maxPosition - position instead of position + len > maxPosition: the latter may
    // overflow.
    if (len < 0 || len > maxPosition - position) {
      throw new CodecException("bytes too short");
    }
  }

}
