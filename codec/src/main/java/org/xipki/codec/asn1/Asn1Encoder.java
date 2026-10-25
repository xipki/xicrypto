// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.ByteArraySink;
import org.xipki.codec.exception.CodecException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * ASN.1 Encoder.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Asn1Encoder {

  private final Asn1Encoding encoding;

  Asn1Encoding getEncoding() {
    return encoding;
  }

  protected Asn1Encoder(Asn1Encoding encoding) {
    this.encoding = Args.notNull(encoding, "encoding");
  }

  protected abstract void write(byte b) throws CodecException;

  private void writeByte(int b) throws CodecException {
    if (b < 0 || b > 255) {
      throw new CodecException("b not in [0, 255]");
    }
    write((byte) b);
  }

  protected void write(byte[] bytes) throws CodecException {
    write(bytes, 0, bytes.length);
  }

  protected abstract void write(byte[] bytes, int off, int len) throws CodecException;

  public void encode(Asn1Primitive primitive) throws CodecException {
    PrimitiveType type = primitive.type();

    // write tag
    write(Asn1Util.tagNo2bytes(
        primitive.getTagClass(), primitive.isConstructed(), primitive.getTagNo()));

    // write length
    int encodedLen = primitive.getEncodedLength(encoding);
    write(toDerLen(encodedLen));

    // write value
    encodeValue(type, primitive);
  }

  void encodeValue(PrimitiveType type, Asn1Primitive primitive) throws CodecException {
    // write value
    switch (type) {
      case NULL:
        // nothing to write
        break;
      case BOOLEAN: {
        Asn1Boolean v = (Asn1Boolean) primitive;
        if (encoding == Asn1Encoding.DER) {
          write(v.isTrue() ? (byte) 0xFF : 0);
        } else {
          writeByte(v.getIntValue());
        }
        break;
      }
      case OCTET_STRING: {
        Asn1OctetString v = (Asn1OctetString) primitive;
        write(v.getOctets());
        break;
      }
      case BIT_STRING: {
        Asn1BitString v = (Asn1BitString) primitive;
        writeByte(v.getUnusedBits());
        write(v.getOctets());
        break;
      }
      case ENUMERATED: {
        Asn1Enumerated v = (Asn1Enumerated) primitive;
        write(v.getOctets());
        break;
      }
      case INTEGER: {
        Asn1Integer v = (Asn1Integer) primitive;
        write(v.getOctets());
        break;
      }
      case IA5_STRING: {
        Asn1IA5String v = (Asn1IA5String) primitive;
        write(v.getString().getBytes(StandardCharsets.US_ASCII));
        break;
      }
      case PRINTABLE_STRING: {
        Asn1PrintableString v = (Asn1PrintableString) primitive;
        write(v.getString().getBytes(StandardCharsets.US_ASCII));
        break;
      }
      case VISIBLE_STRING: {
        Asn1VisibleString v = (Asn1VisibleString) primitive;
        write(v.getString().getBytes(StandardCharsets.US_ASCII));
        break;
      }
      case UTF8_STRING: {
        Asn1Utf8String v = (Asn1Utf8String) primitive;
        write(v.getOctets());
        break;
      }
      case BMP_STRING: {
        Asn1BmpString v = (Asn1BmpString) primitive;
        write(v.contentToByteArray());
        break;
      }
      case UTC_TIME: {
        Asn1UtcTime v = (Asn1UtcTime) primitive;
        write(v.getText().getBytes(StandardCharsets.US_ASCII));
        break;
      }
      case GENERALIZED_TIME: {
        Asn1GeneralizedTime v = (Asn1GeneralizedTime) primitive;
        write(v.getText().getBytes(StandardCharsets.US_ASCII));
        break;
      }
      case OID: {
        Asn1Oid v = (Asn1Oid) primitive;
        write(v.getOctets());
        break;
      }
      case RELATIVE_OID: {
        Asn1RelativeOid v = (Asn1RelativeOid) primitive;
        write(v.getOctets());
        break;
      }
      case SET: {
        Asn1Set v = (Asn1Set) primitive;
        int size = v.size();
        if (size == 0) {
          // do nothing
        } else if (size == 1) {
          encode(v.getObjectAt(0));
        } else {
          byte[][] bytesSet = new byte[v.size()][];
          for (int i = 0; i < bytesSet.length; i++) {
            bytesSet[i] = v.getObjectAt(i).getEncoded(encoding);
          }

          // sort the entries
          bubbleSortAscending(bytesSet);

          for (byte[] bytes : bytesSet) {
            write(bytes);
          }
        }
        break;
      }
      case SEQUENCE: {
        Asn1Sequence v = (Asn1Sequence) primitive;
        for (int i = 0; i < v.size(); i++) {
          Asn1Primitive p = v.getObjectAt(i);
          encode(p);
        }
        break;
      }
      case TAGGED_OBJECT: {
        Asn1TaggedObject v = (Asn1TaggedObject) primitive;
        TagContent tc = v.getContent();
        tc.encodeTo(this);
        break;
      }
      case ANY: {
        Asn1Any v = (Asn1Any) primitive;
        write(v.getValue());
        break;
      }
      default:
        throw new IllegalStateException("shall not reach here, unknown Primitive " +
            primitive.getClass().getName());
    }
  }

  static byte[] toDerLen(int len) {
    if (len < 128) {
      return new byte[] {(byte) len};
    } else if (len < 0x0100) {
      return new byte[] {(byte) 0x81, (byte) len};
    } else if (len < 0x010000) {
      return new byte[] {(byte) 0x82, (byte) (len >> 8), (byte) len};
    } else if (len < 0x01000000) {
      return new byte[] {(byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
    } else {
      return new byte[] {(byte) 0x84, (byte) (len >> 24), (byte) (len >> 16),
          (byte) (len >> 8), (byte) len};
    }
  }

  private static boolean lessThanOrEqual(byte[] a, byte[] b) {
    // clear the CONSTRUCTED bit
    int ta = a[0] & 0xFF & ~0x20;
    int tb = b[0] & 0xFF & ~0x20;
    if (ta > tb) {
      return false;
    } else if (ta < tb) {
      return true;
    }

    int len = Math.min(a.length, b.length);
    for (int i = 1; i < len; i++) {
      ta = 0xFF & a[i];
      tb = 0xFF & b[i];

      if (ta > tb) {
        return false;
      } else if (ta < tb) {
        return true;
      }
    }

    return true;
  }

  static void bubbleSortAscending(byte[][] setEntries) {
    int maxIndex = setEntries.length - 1;
    for (int i = 0; i < maxIndex; i++) {
      for (int j = 0; j < maxIndex - i; j++) {
        if (!lessThanOrEqual(setEntries[j], setEntries[j + 1])) {
          byte[] tmp = setEntries[j];
          setEntries[j] = setEntries[j + 1];
          setEntries[j + 1] = tmp;
        }
      }
    }
  }

  /**
   * Buffer ASN.1 Encoder.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ByteArrayEncoder extends Asn1Encoder {

    private final ByteArraySink sink;

    public ByteArrayEncoder(Asn1Encoding encoding, byte[] buffer) {
      super(encoding);
      this.sink = new ByteArraySink(buffer);
    }

    /**
     * Creates a new {@link ByteArrayEncoder} instance.
     * @param buffer the buffer to which the data will be written.
     * @param offset offset of the buffer.
     * @param maxLen maximal length of data to be written.
     */
    public ByteArrayEncoder(Asn1Encoding encoding, byte[] buffer, int offset, int maxLen) {
      super(encoding);
      this.sink = new ByteArraySink(buffer, offset, maxLen);
    }

    @Override
    protected void write(byte b) throws CodecException {
      sink.write(b);
    }

    @Override
    protected void write(byte[] bytes, int off, int len) throws CodecException {
      sink.write(bytes, off, len);
    }

    public int position() {
      return sink.position();
    }

    public byte[] getWrittenBytes(boolean alwaysCopyBuffer) {
      return sink.getWrittenBytes(alwaysCopyBuffer);
    }

  }

  /**
   * Byte Array ASN.1 Encoder.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ByteArrayStreamEncoder extends Asn1Encoder implements AutoCloseable {

    private final ByteArrayOutputStream m_os;

    /**
     * Creates a new {@link ByteArrayStreamEncoder} instance with default initial
     * size 32.
     */
    public ByteArrayStreamEncoder(Asn1Encoding encoding) {
      this(encoding, 32);
    }

    /**
     * Creates a new {@link ByteArrayStreamEncoder} instance.
     * @param size the initial size.
     */
    public ByteArrayStreamEncoder(Asn1Encoding encoding, int size) {
      super(encoding);
      this.m_os = new ByteArrayOutputStream(Args.min(size, "size", 1));
    }

    public byte[] toByteArray() {
      return m_os.toByteArray();
    }

    @Override
    protected void write(byte b) {
      m_os.write(b);
    }

    @Override
    protected void write(byte[] bytes, int off, int len) {
      m_os.write(bytes, off, len);
    }

    @Override
    public void close() throws IOException {
      m_os.close();
    }

  }

  /**
   * Stream ASN.1 Encoder.
   *
   * @author Lijun Liao (xipki)
   */
  public static class StreamEncoder extends Asn1Encoder implements AutoCloseable {

    private final OutputStream m_os;

    /**
     * Creates a new {@link StreamEncoder} instance.
     * @param os the output stream to which the data will be written.
     *
     */
    public StreamEncoder(Asn1Encoding encoding, OutputStream os) {
      super(encoding);
      this.m_os = Args.notNull(os, "os");
    }

    @Override
    protected void write(byte b) throws CodecException {
      try {
        m_os.write(b);
      } catch (IOException e) {
        throw new CodecException.CodecIOException(e);
      }
    }

    @Override
    protected void write(byte[] bytes, int off, int len) throws CodecException {
      try {
        m_os.write(bytes, off, len);
      } catch (IOException e) {
        throw new CodecException.CodecIOException(e);
      }
    }

    @Override
    public void close() throws Exception {
      m_os.close();
    }

  }
}
