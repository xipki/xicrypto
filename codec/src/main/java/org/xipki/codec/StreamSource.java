// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

/**
 * Reads bytes from an input stream, with peeking. Used by the ASN.1 and CBOR decoders.
 *
 * @author Lijun Liao (xipki)
 */
public final class StreamSource {

  private static final int PUSHBACK_SIZE = 100;

  private final PushbackInputStream is;

  private int position;

  /**
   * Creates a new {@link StreamSource} instance.
   *
   * @param is the input stream. If it is not a {@link PushbackInputStream}, it will be wrapped
   *           in one that can peek up to 100 bytes.
   */
  public StreamSource(InputStream is) {
    Args.notNull(is, "is");
    this.is = (is instanceof PushbackInputStream)
        ? (PushbackInputStream) is : new PushbackInputStream(is, PUSHBACK_SIZE);
    this.position = 0;
  }

  public int position() {
    return position;
  }

  public int read1Byte() throws CodecException {
    int r;
    try {
      r = is.read();
    } catch (IOException e) {
      throw new CodecException(e);
    }

    if (r == -1) {
      throw new CodecException("bytes too short");
    }
    position++;
    return r;
  }

  public byte[] readExactly(int len) throws CodecException {
    Args.notNegative(len, "len");
    byte[] ret;
    try {
      // readNBytes() reads in chunks and allocates only the memory for the bytes read.
      ret = is.readNBytes(len);
    } catch (IOException e) {
      throw new CodecException(e);
    }

    if (ret.length != len) {
      throw new CodecException("bytes too short");
    }

    position += len;
    return ret;
  }

  /**
   * Reads an unsigned big-endian integer.
   * @param numBytes number of bytes, at most 8.
   * @return the integer. For 8 bytes, values above {@link Long#MAX_VALUE} are negative.
   * @throws CodecException if the bytes are too short.
   */
  public long readUInt(int numBytes) throws CodecException {
    long v = 0;
    for (byte b : readExactly(numBytes)) {
      v = (v << 8) | (b & 0xFFL);
    }
    return v;
  }

  public int peek1Byte() throws CodecException {
    int r = read1Byte();
    unread(new byte[] {(byte) r});
    return r;
  }

  public byte[] peekBytes(int num) throws CodecException {
    byte[] bytes = readExactly(num);
    unread(bytes);
    return bytes;
  }

  private void unread(byte[] value) throws CodecException {
    try {
      is.unread(value);
    } catch (IOException e) {
      throw new CodecException(e);
    }
    position -= value.length;
  }

}
