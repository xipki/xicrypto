// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * Represent a object which is not supported natively.
 * @author Lijun Liao (xipki)
 */
public class Asn1Any extends Asn1Primitive {

  private final boolean constructed;

  private final int tagNo;

  private final byte[] value;

  public Asn1Any(boolean constructed, int tagNo, byte[] value) {
    this.constructed = constructed;
    this.tagNo = tagNo;
    this.value = value;
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.ANY;
  }

  @Override
  public boolean isConstructed() {
    return constructed;
  }

  @Override
  public int getTagNo() {
    return tagNo;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return value.length;
  }

  public byte[] getValue() {
    return value;
  }

  @Override
  public int hashCode() {
    int r = tagNo * 31 + Arrays.hashCode(value);
    return r * 31 + (constructed ? 1 : 0);
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Any)) {
      return false;
    }

    Asn1Any b = (Asn1Any) obj;
    return constructed == b.constructed && tagNo == b.tagNo && Arrays.equals(value, b.value);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel,
        "tag=" + tagNo + (constructed ? " (constructed)" : "") + "\n");
    return ToStringUtil.toString("value", value, buf, indentLevel);
  }

}
