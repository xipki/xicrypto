// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.Arrays;

/**
 * Writes bytes into a part of a fixed byte array. Used by the ASN.1 and CBOR encoders.
 *
 * @author Lijun Liao (xipki)
 */
public final class ByteArraySink {

  private final byte[] buffer;

  private final int maxPosition; // exclusive

  private int position;

  public ByteArraySink(byte[] buffer) {
    this.buffer = Args.notNull(buffer, "buffer");
    this.position = 0;
    this.maxPosition = buffer.length;
  }

  /**
   * Creates a new {@link ByteArraySink} instance.
   * @param buffer the buffer to which the data will be written.
   * @param offset offset of the buffer.
   * @param maxLen maximal length of data to be written.
   */
  public ByteArraySink(byte[] buffer, int offset, int maxLen) {
    this.buffer = Args.notNull(buffer, "buffer");

    if (offset < 0 || offset > buffer.length - 1) {
      throw new IllegalArgumentException("invalid offset " + offset);
    }

    if (maxLen < 1 || maxLen > buffer.length - offset) {
      throw new IllegalArgumentException("invalid maxLen " + maxLen);
    }

    this.position = offset;
    this.maxPosition = offset + maxLen;
  }

  public void write(byte b) throws CodecException {
    if (position >= maxPosition) {
      throw new CodecException.CodecIOException(
          "EOF reached: position=" + position + ", maxPosition=" + maxPosition);
    }
    buffer[position++] = b;
  }

  public void write(byte[] bytes, int off, int len) throws CodecException {
    // len > maxPosition - position instead of position + len > maxPosition: the latter may
    // overflow.
    if (len > maxPosition - position) {
      throw new CodecException.CodecIOException(
          "EOF reached: position=" + position + ", len=" + len + ", maxPosition=" + maxPosition);
    }
    System.arraycopy(bytes, off, buffer, position, len);
    position += len;
  }

  public int position() {
    return position;
  }

  public byte[] getWrittenBytes(boolean alwaysCopyBuffer) {
    if (position < buffer.length) {
      return Arrays.copyOf(buffer, position);
    }

    return alwaysCopyBuffer ? buffer.clone() : buffer;
  }

}
