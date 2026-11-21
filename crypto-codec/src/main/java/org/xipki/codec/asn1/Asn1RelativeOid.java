// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Relative OID
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1RelativeOid extends Asn1Primitive {

  private final byte[] octets;

  private final String id;

  public static Asn1RelativeOid fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1RelativeOid) Asn1Util.readAsn1Object(Asn1Tags.RELATIVE_OID, encoded);
  }

  public Asn1RelativeOid(String oid) {
    this.id = Asn1Oid.checkStringLength(Args.notBlank(oid, "oid"));
    this.octets = Asn1Oid.checkEncodedLength(encodeRawRelativeOid(oid));
  }

  public Asn1RelativeOid(byte[] octets) {
    this.octets = Asn1Oid.checkEncodedLength(Args.notEmpty(octets, "octets"));
    this.id = decodeRawRelativeOid(octets, 0);
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.RELATIVE_OID;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.RELATIVE_OID;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }

  public String getId() {
    return id;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(octets);
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1RelativeOid)) {
      return false;
    }

    return Arrays.equals(octets, ((Asn1RelativeOid) obj).octets);
  }

  @Override
  public String toString() {
    return id;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, id);
  }

  static byte[] encodeRawRelativeOid(String oid) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(10);
    String[] nodes = oid.split("\\.");

    for (String node : nodes) {
      int v = Integer.parseInt(node);
      Asn1Oid.encodeOidNode(out, v);
    }

    return out.toByteArray();
  }

  static String decodeRawRelativeOid(byte[] encoded, int offset) {
    final int len = encoded.length;
    StringBuilder sb = new StringBuilder(len + 5);

    while (offset < len) {
      if (sb.length() > 0) {
        sb.append(".");
      }
      offset = Asn1Oid.readNode(sb, encoded, offset, false);
    }

    if (offset != len) {
      throw new IllegalArgumentException("encoded too long");
    }

    return sb.toString();
  }

}
