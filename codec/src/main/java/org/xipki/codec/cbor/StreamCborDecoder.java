// #THIRDPARTY
/*
 * JACOB - CBOR implementation in Java.
 *
 * (C) Copyright - 2013 - J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package org.xipki.codec.cbor;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.StreamSource;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.xipki.codec.cbor.CborConstants.TYPE_TEXT_STRING;

/**
 * Stream Cbor Decoder.
 *
 * @author J.W. Janssen <j.w.janssen@lxtreme.nl>
 * @author Lijun Liao (xipki)
 */
public class StreamCborDecoder extends CborDecoder {

  private final StreamSource src;

  /**
   * Creates a new {@link StreamCborDecoder} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public StreamCborDecoder(InputStream is) {
    this.src = new StreamSource(is);
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

    return new String(src.readExactly((int) len), StandardCharsets.UTF_8);
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
