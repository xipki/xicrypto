// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * OCTET STRING
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1OctetString extends Asn1Primitive {

  private final byte[] octets;

  public static Asn1OctetString fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1OctetString) Asn1Util.readAsn1Object(Asn1Tags.OCTET_STRING, encoded);
  }

  public Asn1OctetString(byte[] octets) {
    this.octets = Args.notNull(octets, "octets");
  }

  public static Asn1OctetString wrap(Asn1Encodable object) {
    return new Asn1OctetString(Args.notNull(object, "object").getEncoded(Asn1Encoding.DER));
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.OCTET_STRING;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.OCTET_STRING;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }

  public int getOctetsLength() {
    return octets.length;
  }

  public boolean hasValue(byte[] value) {
    return Arrays.equals(octets, value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(octets);
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1OctetString)) {
      return false;
    }

    Asn1OctetString b = (Asn1OctetString) obj;
    return Arrays.equals(octets, b.octets);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.toString(octets, buf, indentLevel);
  }

}
