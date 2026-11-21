// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * NULL
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Null extends Asn1Primitive {

  public static final Asn1Null INSTANCE = new Asn1Null();

  public static Asn1Null fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Null) Asn1Util.readAsn1Object(Asn1Tags.NULL, encoded);
  }

  public static boolean isEncodedNull(byte[] encoded) {
    if (encoded.length != 2) {
      return false;
    }
    return encoded[0] == 5 && encoded[1] == 0;
  }

  private Asn1Null() {
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.NULL;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.NULL;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return 0;
  }

  @Override
  public int hashCode() {
    return 1;
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    return obj instanceof Asn1Null;
  }

  @Override
  public String toString() {
    return "NULL";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, "NULL");
  }

}
