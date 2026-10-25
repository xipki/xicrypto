// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * ENUMERATED
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Enumerated extends Asn1Primitive {

  private final int value;

  private final byte[] octets;

  public static Asn1Enumerated fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Enumerated) Asn1Util.readAsn1Object(Asn1Tags.ENUMERATED, encoded);
  }

  public Asn1Enumerated(int value) {
    this.value = Args.notNegative(value, "value");
    this.octets = Asn1Util.toTwosComplement(value);
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.ENUMERATED;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.ENUMERATED;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public int getValue() {
    return value;
  }

  public byte[] getOctets() {
    return octets;
  }

  @Override
  public int hashCode() {
    return value;
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Enumerated)) {
      return false;
    }

    Asn1Enumerated b = (Asn1Enumerated) obj;
    return value == b.value;
  }

  @Override
  public String toString() {
    return Integer.toString(value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, Integer.toString(value));
  }

}
