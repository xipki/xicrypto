// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.util.ToStringUtil;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractAsn1String extends Asn1Primitive {

  private final PrimitiveType type;

  private final int tag;

  protected final String value;

  protected AbstractAsn1String(PrimitiveType type, String value) {
    this.type = Args.notNull(type, "type");
    this.value = Args.notNull(value, "value");

    if (type == PrimitiveType.IA5_STRING) {
      tag = Asn1Tags.IA5_STRING;
    } else if (type == PrimitiveType.PRINTABLE_STRING) {
      tag = Asn1Tags.PRINTABLE_STRING;
    } else if (type == PrimitiveType.UTF8_STRING) {
      tag = Asn1Tags.UTF8_STRING;
    } else if (type == PrimitiveType.BMP_STRING) {
      tag = Asn1Tags.BMP_STRING;
    } else if (type == PrimitiveType.VISIBLE_STRING) {
      tag = Asn1Tags.VISIBLE_STRING;
    } else {
      throw new IllegalArgumentException("invalid type " + type);
    }
  }

  public static AbstractAsn1String newString(PrimitiveType type, String value) {
    switch (type) {
      case PRINTABLE_STRING:
        return new Asn1PrintableString(value);
      case BMP_STRING:
        return new Asn1BmpString(value);
      case UTF8_STRING:
        return new Asn1Utf8String(value);
      case IA5_STRING:
        return new Asn1IA5String(value);
      case VISIBLE_STRING:
        return new Asn1VisibleString(value);
      default:
        throw new IllegalArgumentException("unsupported type " + type);
    }
  }

  @Override
  public final PrimitiveType type() {
    return type;
  }

  @Override
  public final boolean isConstructed() {
    return false;
  }

  @Override
  public final int getTagNo() {
    return tag;
  }

  public String getString() {
    return value;
  }

  public int getStringLength() {
    return value.length();
  }

  @Override
  public int hashCode() {
    return tag * 31 + value.hashCode();
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof AbstractAsn1String)) {
      return false;
    }

    AbstractAsn1String b = (AbstractAsn1String) obj;
    return tag == b.tag && value.equals(b.value);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, value);
  }

}
