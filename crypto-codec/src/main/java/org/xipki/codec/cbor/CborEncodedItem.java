// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.Hex;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * One CBOR data item kept in its original encoding, as read by
 * {@link CborDecoder#readEncodedItem()}. Encoding it writes the original bytes unchanged,
 * so that, for example, signed data can be verified over exactly the received bytes.
 *
 * @author Lijun Liao (xipki)
 */
public final class CborEncodedItem extends CborEncodable {

  private final byte[] encoded;

  /**
   * Creates a new {@link CborEncodedItem}. The bytes are not copied and not checked.
   * @param encoded the encoding of exactly one CBOR data item.
   */
  CborEncodedItem(byte[] encoded) {
    this.encoded = Args.notNull(encoded, "encoded");
  }

  /**
   * Creates a new {@link CborEncodedItem}, checking that the bytes contain exactly one
   * well-formed CBOR data item.
   * @param encoded the encoding of exactly one CBOR data item.
   * @return the item.
   * @throws CodecException if the bytes are not exactly one well-formed CBOR data item.
   */
  public static CborEncodedItem getInstance(byte[] encoded) throws CodecException {
    Args.notNull(encoded, "encoded");
    ByteArrayCborDecoder decoder = new ByteArrayCborDecoder(encoded);
    CborEncodedItem item = decoder.readEncodedItem();
    if (decoder.hasMoreBytes()) {
      throw new CodecException("trailing bytes after the CBOR data item");
    }
    return item;
  }

  /**
   * Creates a new {@link CborEncodedItem} from generic CBOR data, encoded deterministically,
   * see {@link CborMap#deepSorted(Object)}. A {@link CborEncodedItem} is returned unchanged.
   * @param data generic CBOR data, see {@link CborDecoder#readNext()}.
   * @return the item.
   * @throws IllegalArgumentException if the data cannot be encoded, or a map has duplicate keys.
   */
  public static CborEncodedItem ofData(Object data) {
    if (data instanceof CborEncodedItem) {
      return (CborEncodedItem) data;
    }

    try {
      ByteArrayCborEncoder encoder = new ByteArrayCborEncoder();
      encoder.writeAnyObject(CborMap.deepSorted(data));
      return getInstance(encoder.toByteArray());
    } catch (CodecException e) {
      throw new IllegalArgumentException("invalid data: " + e.getMessage(), e);
    }
  }

  /**
   * Decodes the item as generic CBOR data, see {@link CborDecoder#readNext()}.
   * @return the generic CBOR data; maps and lists are unmodifiable.
   * @throws CodecException if the item cannot be decoded as generic data, e.g. if it contains
   *         indefinite lengths or duplicate map keys.
   */
  public Object data() throws CodecException {
    return decoder().readNext();
  }

  /**
   * Returns the diagnostic notation of the item, see {@link CborMap#toDiagnostic(Object)}, or
   * the hex encoding in the form {@code <<h'...'>>} if it cannot be decoded as generic data.
   * @return the diagnostic notation.
   */
  public String toDiagnostic() {
    try {
      return CborMap.toDiagnostic(data());
    } catch (CodecException e) {
      return "<<h'" + Hex.encode(encoded) + "'>>";
    }
  }

  /**
   * Returns the type of the item, i.e. of its initial byte.
   * @return the type of the item.
   */
  public CborType type() {
    return CborType.valueOf(0xFF & encoded[0]);
  }

  /**
   * Returns the length of the encoding.
   * @return the length of the encoding.
   */
  public int length() {
    return encoded.length;
  }

  /**
   * Returns a new decoder positioned at the start of the item.
   * @return a new decoder positioned at the start of the item.
   */
  public ByteArrayCborDecoder decoder() {
    return new ByteArrayCborDecoder(encoded);
  }

  /**
   * Returns a copy of the original encoding.
   * @return a copy of the original encoding.
   */
  @Override
  public byte[] getEncoded() {
    return encoded.clone();
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.write(encoded, 0, encoded.length);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "h'" + Hex.encode(encoded) + "'");
    return buf;
  }

  @Override
  public String toString() {
    return "CBOR h'" + Hex.encode(encoded) + "'";
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded);
  }

  @Override
  public boolean equals(Object obj) {
    return this == obj
        || (obj instanceof CborEncodedItem
            && Arrays.equals(encoded, ((CborEncodedItem) obj).encoded));
  }

}
