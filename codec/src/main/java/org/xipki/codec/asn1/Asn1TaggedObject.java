// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * Tagged Object
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1TaggedObject extends Asn1Primitive {

  static class GenContent {
    final boolean explicit;
    final Asn1Primitive content;

    GenContent(boolean explicit, Asn1Primitive baseObject) {
      this.explicit = explicit;
      this.content = Args.notNull(baseObject, "baseObject");
    }

    boolean isConstructed() {
      return content.isConstructed();
    }

    int getEncodedLength(Asn1Encoding encoding) {
      int len = content.getEncodedLength(encoding);

      // implicit
      return explicit
          ? Asn1Util.numBytesOfTag(content.getTagNo()) + Asn1Util.numBytesOfLength(len) + len
          : len;
    }

    @Override
    public int hashCode() {
      return (explicit ? 31 : 0) + content.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }

      if (!(obj instanceof GenContent)) {
        return false;
      }

      GenContent b = (GenContent) obj;
      return explicit == b.explicit && content.equals(b.content);
    }

    public void toString(int tagNo, StringBuilder buf, int indentLevel) {
      ToStringUtil.appendIndent(buf, indentLevel,
          "[" + tagNo + "]" + (explicit ? " EXPLICIT" : " IMPLICIT") + "\n");
      content.toString(buf, indentLevel + 1);
    }

  }

  private final TagClass tagClass;

  private final boolean constructed;

  private final int tagNo;

  private final TagContent content;

  public static Asn1TaggedObject newImplicit(int tagNo, Asn1Encodable baseObject) {
    return new Asn1TaggedObject(false, tagNo, baseObject);
  }

  public static Asn1TaggedObject newExplicit(int tagNo, Asn1Encodable baseObject) {
    return new Asn1TaggedObject(true, tagNo, baseObject);
  }

  public Asn1TaggedObject(boolean explicit, int tagNo, Asn1Encodable baseObject) {
    this(null, explicit, tagNo, baseObject);
  }

  public Asn1TaggedObject(TagClass tagClass, boolean explicit,
                          int tagNo, Asn1Encodable baseObject) {
    this.tagClass = tagClass == null ? TagClass.contextSpecific : tagClass;
    this.tagNo = tagNo;

    // fix the explicit: base object of CHOICE MUST be EXPLICIT.
    if (!explicit && baseObject.isChoice()) {
      explicit = true;
    }

    this.content = TagContent.ofBaseObject(explicit,
        Args.notNull(baseObject, "baseObject").toAsn1Primitive());
    // we do not use indefinite-length for encoding, so constructed is fixed
    this.constructed = explicit | this.content.baseObject.isConstructed();
  }

  Asn1TaggedObject(TagClass tagClass, boolean constructed, int tagNo, TagContent content) {
    this.tagClass = Args.notNull(tagClass, "tagClass");
    this.constructed = constructed;
    this.tagNo = tagNo;
    this.content = Args.notNull(content, "content");
  }

  public static Asn1TaggedObject fromEncoded(byte[] encoded) throws CodecException {
    return Asn1Util.readAsn1Tagged(encoded);
  }

  TagContent getContent() {
    return content;
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.TAGGED_OBJECT;
  }

  @Override
  public boolean isConstructed() {
    return constructed;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return content.getEncodedLength(encoding);
  }

  @Override
  public TagClass getTagClass() {
    return tagClass;
  }

  @Override
  public int getTagNo() {
    return tagNo;
  }

  Asn1Primitive getBaseObject() {
    return content == null ? null : content.baseObject.content;
  }

  @Override
  public int hashCode() {
    return tagClass.hashCode() * 31 * 31 * 31 + tagNo * 31 * 31 +
        (constructed ? 1 : 0) * 31 + content.hashCode();
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1TaggedObject)) {
      return false;
    }

    Asn1TaggedObject b = (Asn1TaggedObject) obj;
    return tagClass == b.tagClass
        && tagNo == b.tagNo
        && constructed == b.constructed
        && content.equals(b.content);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return content.toString(tagNo, buf, indentLevel);
  }

  public Asn1Integer getExplicitIntegerBase() throws CodecException {
    return (Asn1Integer) getExplicitBase(Asn1Tags.INTEGER);
  }

  public Asn1Boolean getExplicitBooleanBase() throws CodecException {
    return (Asn1Boolean) getExplicitBase(Asn1Tags.BOOLEAN);
  }

  public Asn1Null getExplicitNullBase() throws CodecException {
    return (Asn1Null) getExplicitBase(Asn1Tags.NULL);
  }

  public Asn1Enumerated getExplicitEnumeratedBase() throws CodecException {
    return (Asn1Enumerated) getExplicitBase(Asn1Tags.ENUMERATED);
  }

  public Asn1OctetString getExplicitOctetStringBase() throws CodecException {
    return (Asn1OctetString) getExplicitBase(Asn1Tags.OCTET_STRING);
  }

  public Asn1BitString getExplicitBitStringBase() throws CodecException {
    return (Asn1BitString) getExplicitBase(Asn1Tags.BIT_STRING);
  }

  public Asn1IA5String getExplicitIA5StringBase() throws CodecException {
    return (Asn1IA5String) getExplicitBase(Asn1Tags.IA5_STRING);
  }

  public Asn1Utf8String getExplicitUTF8StringBase() throws CodecException {
    return (Asn1Utf8String) getExplicitBase(Asn1Tags.UTF8_STRING);
  }

  public Asn1PrintableString getExplicitPrintableStringBase() throws CodecException {
    return (Asn1PrintableString) getExplicitBase(Asn1Tags.PRINTABLE_STRING);
  }

  public Asn1BmpString getExplicitBmpStringBase() throws CodecException {
    return (Asn1BmpString) getExplicitBase(Asn1Tags.BMP_STRING);
  }

  public Asn1VisibleString getExplicitVisibleStringBase() throws CodecException {
    return (Asn1VisibleString) getExplicitBase(Asn1Tags.VISIBLE_STRING);
  }

  public Asn1Oid getExplicitOidBase() throws CodecException {
    return (Asn1Oid) getExplicitBase(Asn1Tags.OBJECT_IDENTIFIER);
  }

  public Asn1RelativeOid getExplicitRelativeOidBase() throws CodecException {
    return (Asn1RelativeOid) getExplicitBase(Asn1Tags.RELATIVE_OID);
  }

  public Asn1GeneralizedTime getExplicitGeneralizedTimeBase() throws CodecException {
    return (Asn1GeneralizedTime) getExplicitBase(Asn1Tags.GENERALIZED_TIME);
  }

  public Asn1UtcTime getExplicitUtcTimeBase() throws CodecException {
    return (Asn1UtcTime) getExplicitBase(Asn1Tags.UTC_TIME);
  }

  public Asn1Sequence getExplicitSequenceBase() throws CodecException {
    return (Asn1Sequence) getExplicitBase(Asn1Tags.SEQUENCE);
  }

  public Asn1Set getExplicitSetBase() throws CodecException {
    return (Asn1Set) getExplicitBase(Asn1Tags.SET);
  }

  public Asn1TaggedObject getExplicitTaggedBase() throws CodecException {

    return content.getExplicitTaggedBase();
  }

  public Asn1Primitive getExplicitBase() throws CodecException {
    return content.getExplicitBase();
  }

  private Asn1Primitive getExplicitBase(int expectedTagNo) throws CodecException {
    return Asn1Decoder.rejectInvalidTextString(
        content.getExplicitBase(expectedTagNo), expectedTagNo);
  }

  public Asn1Integer getImplicitIntegerBase() throws CodecException {
    return (Asn1Integer) getImplicitBase(Asn1Tags.INTEGER);
  }

  public Asn1Boolean getImplicitBooleanBase() throws CodecException {
    return (Asn1Boolean) getImplicitBase(Asn1Tags.BOOLEAN);
  }

  public Asn1Null getImplicitNullBase() throws CodecException {
    return (Asn1Null) getImplicitBase(Asn1Tags.NULL);
  }

  public Asn1Enumerated getImplicitEnumeratedBase() throws CodecException {
    return (Asn1Enumerated) getImplicitBase(Asn1Tags.ENUMERATED);
  }

  public Asn1OctetString getImplicitOctetStringBase() throws CodecException {
    return (Asn1OctetString) getImplicitBase(Asn1Tags.OCTET_STRING);
  }

  public Asn1BitString getImplicitBitStringBase() throws CodecException {
    return (Asn1BitString) getImplicitBase(Asn1Tags.BIT_STRING);
  }

  public Asn1IA5String getImplicitIA5StringBase() throws CodecException {
    return (Asn1IA5String) getImplicitBase(Asn1Tags.IA5_STRING);
  }

  public Asn1Utf8String getImplicitUTF8StringBase() throws CodecException {
    return (Asn1Utf8String) getImplicitBase(Asn1Tags.UTF8_STRING);
  }

  public Asn1PrintableString getImplicitPrintableStringBase() throws CodecException {
    return (Asn1PrintableString) getImplicitBase(Asn1Tags.PRINTABLE_STRING);
  }

  public Asn1BmpString getImplicitBmpStringBase() throws CodecException {
    return (Asn1BmpString) getImplicitBase(Asn1Tags.BMP_STRING);
  }

  public Asn1VisibleString getImplicitVisibleStringBase() throws CodecException {
    return (Asn1VisibleString) getImplicitBase(Asn1Tags.VISIBLE_STRING);
  }

  public Asn1Oid getImplicitOidBase() throws CodecException {
    return (Asn1Oid) getImplicitBase(Asn1Tags.OBJECT_IDENTIFIER);
  }

  public Asn1RelativeOid getImplicitRelativeOidBase() throws CodecException {
    return (Asn1RelativeOid) getImplicitBase(Asn1Tags.RELATIVE_OID);
  }

  public Asn1GeneralizedTime getImplicitGeneralizedTimeBase() throws CodecException {
    return (Asn1GeneralizedTime) getImplicitBase(Asn1Tags.GENERALIZED_TIME);
  }

  public Asn1UtcTime getImplicitUtcTimeBase() throws CodecException {
    return (Asn1UtcTime) getImplicitBase(Asn1Tags.UTC_TIME);
  }

  public Asn1Sequence getImplicitSequenceBase() throws CodecException {
    return (Asn1Sequence) getImplicitBase(Asn1Tags.SEQUENCE);
  }

  public Asn1Set getImplicitSetBase() throws CodecException {
    return (Asn1Set) getImplicitBase(Asn1Tags.SET);
  }

  public Asn1TaggedObject getImplicitTaggedObjectBase(int tagNo) {
    return new Asn1TaggedObject(TagClass.contextSpecific, constructed, tagNo, content);
  }

  public Asn1Primitive getImplicitBase(int baseObjectTagNo) throws CodecException {
    return Asn1Decoder.rejectInvalidTextString(
        content.getImplicitBase(constructed, baseObjectTagNo), baseObjectTagNo);
  }

}
