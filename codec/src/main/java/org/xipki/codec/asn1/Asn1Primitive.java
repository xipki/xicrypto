// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

/**
 * Represents the ASN.1 primitive types.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Asn1Primitive extends Asn1Encodable {

  public abstract PrimitiveType type();

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return this;
  }

  public TagClass getTagClass() {
    return TagClass.universal;
  }

  private void assertType(PrimitiveType type) throws CodecException {
    if (type != type()) {
      throw new CodecException("this ASN.1 object is not " + type + ", but " + type());
    }
  }

  public Asn1Null asNull() throws CodecException {
    assertType(PrimitiveType.NULL);
    return (Asn1Null) this;
  }

  public Asn1Enumerated asEnumerated() throws CodecException {
    assertType(PrimitiveType.ENUMERATED);
    return (Asn1Enumerated) this;
  }

  public Asn1Boolean asBoolean() throws CodecException {
    assertType(PrimitiveType.BOOLEAN);
    return (Asn1Boolean) this;
  }

  public Asn1Integer asInteger() throws CodecException {
    assertType(PrimitiveType.INTEGER);
    return (Asn1Integer) this;
  }

  public Asn1BitString asBitString() throws CodecException {
    assertType(PrimitiveType.BIT_STRING);
    return (Asn1BitString) this;
  }

  public Asn1OctetString asOctetString() throws CodecException {
    assertType(PrimitiveType.OCTET_STRING);
    return (Asn1OctetString) this;
  }

  public Asn1UtcTime asUtcTime() throws CodecException {
    assertType(PrimitiveType.UTC_TIME);
    return (Asn1UtcTime) this;
  }

  public Asn1GeneralizedTime asGeneralizedTime() throws CodecException {
    assertType(PrimitiveType.GENERALIZED_TIME);
    return (Asn1GeneralizedTime) this;
  }

  public Asn1BmpString asBmpString() throws CodecException {
    assertType(PrimitiveType.BMP_STRING);
    return (Asn1BmpString) this;
  }

  public Asn1IA5String asIA5String() throws CodecException {
    assertType(PrimitiveType.IA5_STRING);
    return (Asn1IA5String) this;
  }

  public Asn1VisibleString asVisibleString() throws CodecException {
    assertType(PrimitiveType.VISIBLE_STRING);
    return (Asn1VisibleString) this;
  }

  public Asn1PrintableString asPrintableString() throws CodecException {
    assertType(PrimitiveType.PRINTABLE_STRING);
    return (Asn1PrintableString) this;
  }

  public Asn1Utf8String asUtf8String() throws CodecException {
    assertType(PrimitiveType.UTF8_STRING);
    return (Asn1Utf8String) this;
  }

  public Asn1Oid asOid() throws CodecException {
    assertType(PrimitiveType.OID);
    return (Asn1Oid) this;
  }

  public Asn1RelativeOid asRelativeOid() throws CodecException {
    assertType(PrimitiveType.RELATIVE_OID);
    return (Asn1RelativeOid) this;
  }

  public Asn1Set asSet() throws CodecException {
    assertType(PrimitiveType.SET);
    return (Asn1Set) this;
  }

  public Asn1Sequence asSequence() throws CodecException {
    assertType(PrimitiveType.SEQUENCE);
    return (Asn1Sequence) this;
  }

  public Asn1TaggedObject asTagged() throws CodecException {
    assertType(PrimitiveType.TAGGED_OBJECT);
    return (Asn1TaggedObject) this;
  }

  public AbstractAsn1Time asTime() throws CodecException {
    PrimitiveType type = type();
    if (type == PrimitiveType.UTC_TIME || type == PrimitiveType.GENERALIZED_TIME) {
      return (AbstractAsn1Time) this;
    }

    throw new CodecException("this ASN.1 object is neither UTCTime nor " +
        "GeneralizedTime, but " + type);
  }

  public abstract boolean isConstructed();

  public abstract int getTagNo();

  public abstract int getEncodedLength(Asn1Encoding encoding);

  protected abstract boolean doEquals(Asn1Primitive other);

  @Override
  public final boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj instanceof Asn1Primitive) {
      return doEquals((Asn1Primitive) obj);
    } else {
      return false;
    }
  }
}
