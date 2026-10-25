// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.ByteArraySink;
import org.xipki.codec.exception.CodecException;

/**
 * Buffer Cbor Encoder.
 *
 * @author Lijun Liao (xipki)
 */
public class BufferCborEncoder extends CborEncoder {

  private final ByteArraySink sink;

  public BufferCborEncoder(byte[] buffer) {
    this.sink = new ByteArraySink(buffer);
  }

  /**
   * Creates a new {@link BufferCborEncoder} instance.
   * @param buffer the buffer to which the data will be written.
   * @param offset offset of the buffer.
   * @param maxLen maximal length of data to be written.
   */
  public BufferCborEncoder(byte[] buffer, int offset, int maxLen) {
    this.sink = new ByteArraySink(buffer, offset, maxLen);
  }

  @Override
  protected void write(byte b) throws CodecException {
    sink.write(b);
  }

  @Override
  protected void write(int b) throws CodecException {
    sink.write((byte) b);
  }

  @Override
  protected void write(byte[] bytes, int off, int len) throws CodecException {
    sink.write(bytes, off, len);
  }

  public int position() {
    return sink.position();
  }

}
