// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

/**
 * Asn1 Stream Parser.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1StreamParser {

  /**
   * My Int.
   */
  public static class MyInt {

    private int value;

    void set(int value) {
      this.value = value;
    }

    public int get() {
      return value;
    }

  } // class MyInt

  public static final int TAG_CONSTRUCTED_SEQUENCE = Asn1Tags.CONSTRUCTED | Asn1Tags.SEQUENCE;

  public static final int TAG_CONSTRUCTED_SET = Asn1Tags.CONSTRUCTED | Asn1Tags.SET;

  public static byte[] readBlock(BufferedInputStream instream, String name) throws IOException {
    return readBlock(Integer.MAX_VALUE, instream, name);
  }

  public static byte[] readBlock(int expectedTag, BufferedInputStream instream, String name)
      throws IOException {
    int tag = readByte(instream, name);
    if (expectedTag != Integer.MAX_VALUE) {
      assertTag(expectedTag, tag, name);
    }

    byte[] lenBytes = new byte[5];
    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream, lenBytes);

    byte[] value = readExactly(instream, length, name);
    byte[] bytes = new byte[1 + lenBytesSize.get() + length];
    bytes[0] = (byte) tag;
    System.arraycopy(lenBytes, 0, bytes, 1, lenBytesSize.get());
    System.arraycopy(value, 0, bytes, 1 + lenBytesSize.get(), length);
    return bytes;
  }

  public static byte[] readValue(int expectedTag, BufferedInputStream instream, String name)
      throws IOException {
    int tag = readByte(instream, name);
    assertTag(expectedTag, tag, name);

    MyInt lenBytesSize = new MyInt();
    int length = readLength(lenBytesSize, instream);
    return readExactly(instream, length, name);
  } // method readValue

  /**
   * Reads exactly len bytes. The memory is allocated for the bytes actually read, so that a
   * large declared length in a short (malicious) input does not cause the OutOfMemoryError.
   */
  private static byte[] readExactly(InputStream instream, int len, String name)
      throws IOException {
    byte[] bytes = instream.readNBytes(len);
    if (bytes.length != len) {
      throw new EOFException("not enough data to read " + name);
    }
    return bytes;
  }

  private static int readByte(InputStream instream, String name) throws IOException {
    int b = instream.read();
    if (b == -1) {
      throw new EOFException("not enough data to read " + name);
    }
    return b;
  }

  public static int markAndReadTag(InputStream instream) throws IOException {
    instream.mark(10);
    return instream.read();
  }

  public static int peekTag(InputStream instream) throws IOException {
    instream.mark(1);
    int tag = instream.read();
    instream.reset();
    return tag;
  }

  public static int readLength(MyInt lenBytesSize, InputStream instream) throws IOException {
    return readLength(lenBytesSize, instream, null);
  }

  /**
   * Reads the definite length.
   * @param lenBytesSize will be set to the number of the length octets.
   * @param instream the input stream.
   * @param lenBytes if not null, the length octets will be written to it.
   * @return the length.
   * @throws IOException if the length is indefinite, too long, or the input is truncated.
   */
  private static int readLength(MyInt lenBytesSize, InputStream instream, byte[] lenBytes)
      throws IOException {
    int b = readByte(instream, "length");
    if (lenBytes != null) {
      lenBytes[0] = (byte) b;
    }

    if ((b & 0x80) == 0) {
      lenBytesSize.set(1);
      return b;
    }

    int numBytes = b & 0x7F;
    if (numBytes == 0) {
      throw new IOException("indefinite length is not supported");
    } else if (numBytes > 4) {
      throw new IOException("length too long");
    }
    lenBytesSize.set(1 + numBytes);

    int length = 0;
    for (int i = 0; i < numBytes; i++) {
      int b1 = readByte(instream, "length");
      if (lenBytes != null) {
        lenBytes[1 + i] = (byte) b1;
      }
      length = (length << 8) | b1;
    }

    if (length < 0) {
      throw new IOException("length too long");
    }
    return length;
  } // method readLength

  public static void assertTag(int expectedTag, int tag, String name) {
    if (expectedTag != tag) {
      throw new IllegalArgumentException(String.format(
          "invalid %s: tag is %d, but not expected %d", name, tag, expectedTag));
    }
  }

  public static Instant readTime(AbstractAsn1Time obj) {
    return obj.getTime();
  }

  public static Instant readTime(MyInt bytesLen, BufferedInputStream instream, String name)
      throws IOException {
    int tag = peekTag(instream);
    byte[] bytes = readBlock(instream, name);
    bytesLen.set(bytes.length);
    try {
      if (tag == Asn1Tags.UTC_TIME || tag == Asn1Tags.GENERALIZED_TIME) {
        return AbstractAsn1Time.fromEncoded(bytes).getTime();
      } else {
        throw new IllegalArgumentException("invalid tag for " + name + ": " + tag);
      }
    } catch (CodecException ex) {
      throw new IllegalArgumentException("error parsing time", ex);
    }
  } // method readTime

  public static void skip(InputStream instream, long count) throws IOException {
    long remaining = count;
    while (remaining > 0) {
      long skipped = instream.skip(remaining);
      if (skipped > 0) {
        remaining -= skipped;
      } else {
        // skip() returns 0 at the end of stream (and may return 0 otherwise), read one byte
        // to distinguish them, otherwise we would loop forever with a truncated input.
        readByte(instream, "skipped bytes");
        remaining--;
      }
    }
  }

  public static void skipField(InputStream instream) throws IOException {
    markAndReadTag(instream);
    int len = readLength(new MyInt(), instream);
    skip(instream, len);
  }

  public static void skipTagLen(InputStream instream) throws IOException {
    markAndReadTag(instream);
    readLength(new MyInt(), instream);
  }

}
