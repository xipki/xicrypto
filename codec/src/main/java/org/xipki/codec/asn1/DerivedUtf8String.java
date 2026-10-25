// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class DerivedUtf8String extends Asn1Encodable {

  protected final Asn1Utf8String value;

  protected abstract void checkValue(Asn1Utf8String value) throws CodecException;

  protected DerivedUtf8String(Asn1Utf8String value) throws CodecException {
    checkValue(value);
    this.value = Args.notNull(value, "value");
  }

  protected DerivedUtf8String(String value) throws CodecException {
    this(Asn1Util.toUtf8String(value));
  }

  public Asn1Utf8String getValue() {
    return value;
  }

  public String value() {
    return value.getString();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return value;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return value.toString(buf, indentLevel);
  }
}

