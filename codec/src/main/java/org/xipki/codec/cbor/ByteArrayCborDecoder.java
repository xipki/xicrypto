// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.codec.cbor;

import org.xipki.codec.util.Args;
import org.xipki.codec.ByteArraySource;
import org.xipki.codec.exception.CodecException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import static org.xipki.codec.cbor.CborConstants.TYPE_TEXT_STRING;

/**
 * Byte Array Cbor Decoder.
 *
 * @author J.W. Janssen <j.w.janssen@lxtreme.nl>
 * @author Lijun Liao (xipki)
 */
public class ByteArrayCborDecoder extends CborDecoder {

  private final ByteArraySource src;

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public ByteArrayCborDecoder(InputStream is) throws IOException {
    this(Args.notNull(is, "is").readAllBytes());
  }

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   * @param bytes the encoded cbor message.
   */
  public ByteArrayCborDecoder(byte[] bytes) {
    this.src = new ByteArraySource(bytes);
  }

  /**
   * Creates a new {@link ByteArrayCborDecoder} instance.
   * @param bytes the encoded cbor message.
   * @param offset offset of bytes for the cbor message.
   * @param len length of the bytes for the cbor message.
   */
  public ByteArrayCborDecoder(byte[] bytes, int offset, int len) throws IOException {
    this.src = new ByteArraySource(bytes, offset, len);
  }

  public byte[] remainingBytes() {
    return src.remainingBytes();
  }

  public void writeConsumedBytes(OutputStream os) throws IOException {
    src.writeConsumedBytes(os);
  }

  @Override
  protected int remainingBytesSize() {
    return src.remainingBytesSize();
  }

  boolean hasMoreBytes() {
    return src.hasMoreBytes();
  }

  @Override
  public String readTextString() throws CodecException {
    if (skipNull()) {
      return null;
    }

    long len = readMajorTypeWithSize(TYPE_TEXT_STRING);
    if (len < 0) {
      fail("Infinite-length text strings not supported!");
    }
    if (len > Integer.MAX_VALUE) {
      fail("String length too long!");
    }

    return src.readUtf8String((int) len);
  }

  @Override
  protected int readUInt8() throws CodecException {
    return src.read1Byte();
  }

  @Override
  protected int readUInt16() throws CodecException {
    return (int) src.readUInt(2);
  }

  @Override
  protected long readUInt32() throws CodecException {
    return src.readUInt(4);
  }

  @Override
  protected long readUInt64() throws CodecException {
    return src.readUInt(8);
  }

  @Override
  protected byte[] readExactly(int len) throws CodecException {
    return src.readExactly(len);
  }

  @Override
  public int read1Byte() throws CodecException {
    return src.read1Byte();
  }

  @Override
  public int streamOffset() {
    return src.position();
  }

  @Override
  public CborType peekType() throws CodecException {
    return CborType.valueOf(src.peek1Byte());
  }

  @Override
  public CborType[] peekTypes(int num) throws CodecException {
    byte[] bytes = src.peekBytes(num);
    CborType[] ret = new CborType[num];
    for (int i = 0; i < num; i++) {
      ret[i] = CborType.valueOf(0xFF & bytes[i]);
    }
    return ret;
  }

  private static void fail(String msg, Object... args) throws CodecException {
    throw new CodecException(String.format(msg, args));
  }

}
