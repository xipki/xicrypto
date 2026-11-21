// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class DerivedOctetString extends Asn1Encodable {

  protected final Asn1OctetString value;

  protected abstract void checkValue(Asn1OctetString value) throws CodecException;

  protected DerivedOctetString(Asn1OctetString value) throws CodecException {
    checkValue(value);
    this.value = Args.notNull(value, "value");
  }

  protected DerivedOctetString(byte[] value) throws CodecException {
    this(Asn1Util.toOctetString(value));
  }

  public Asn1OctetString getValue() {
    return value;
  }

  public byte[] value() {
    return value.getOctets();
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
