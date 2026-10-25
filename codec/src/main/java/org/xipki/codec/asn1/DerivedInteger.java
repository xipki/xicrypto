// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 *
 * @author Lijun Liao (xipki)
 */
public abstract class DerivedInteger extends Asn1Encodable {

  protected final Asn1Integer value;

  protected abstract void checkValue(Asn1Integer value) throws CodecException;

  protected DerivedInteger(Asn1Integer value) throws CodecException {
    checkValue(value);
    this.value = Args.notNull(value, "value");
  }

  protected DerivedInteger(BigInteger value) throws CodecException {
    this(Asn1Util.toInteger(value));
  }

  public Asn1Integer getValue() {
    return value;
  }

  public BigInteger value() {
    return value.getValue();
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
