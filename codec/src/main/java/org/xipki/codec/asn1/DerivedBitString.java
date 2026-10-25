// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class DerivedBitString extends Asn1Encodable {

  protected final Asn1BitString value;

  protected abstract void checkValue(Asn1BitString value) throws CodecException;

  protected DerivedBitString(Asn1BitString value) throws CodecException {
    checkValue(value);
    this.value = Args.notNull(value, "value");
  }

  protected DerivedBitString(byte[] value) throws CodecException {
    this(Asn1Util.toBitString(value));
  }

  public Asn1BitString getValue() {
    return value;
  }

  public byte[] value() {
    return value.getOctets();
  }

  public byte[] alignedValue() {
    return value.getAlignedOctets();
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
