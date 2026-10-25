// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * BOOLEAN
 * @author Lijun Liao (xipki)
 */
public class Asn1Boolean extends Asn1Primitive {

  public static final Asn1Boolean TRUE = new Asn1Boolean(true);

  public static final Asn1Boolean FALSE = new Asn1Boolean(false);

  private final boolean value;
  private final int intValue;

  public static Asn1Boolean fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Boolean) Asn1Util.readAsn1Object(Asn1Tags.BOOLEAN, encoded);
  }

  public static Asn1Boolean getInstance(boolean b) {
    return b ? TRUE : FALSE;
  }

  private Asn1Boolean(boolean value) {
    this.value = value;
    this.intValue = 0xFF;
  }

  public Asn1Boolean(int value) {
    this.intValue = Args.range(value, "value", 0, 255);
    this.value = value != 0;
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.BOOLEAN;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.BOOLEAN;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return 1;
  }

  public boolean isTrue() {
    return value;
  }

  public int getIntValue() {
    return intValue;
  }

  @Override
  public int hashCode() {
    return value ? 31 : 0;
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Boolean)) {
      return false;
    }

    Asn1Boolean b = (Asn1Boolean) obj;
    return value == b.value;
  }

  @Override
  public String toString() {
    return Boolean.toString(value);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, Boolean.toString(value));
  }

}
