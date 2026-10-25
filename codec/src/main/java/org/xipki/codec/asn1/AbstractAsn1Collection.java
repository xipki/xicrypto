// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractAsn1Collection extends Asn1Primitive {

  private final List<Asn1Primitive> values;

  AbstractAsn1Collection(List<? extends Asn1Encodable> values) {
    Args.noNullElements(values, "values");
    this.values = new ArrayList<>(values.size());
    for (Asn1Encodable enc : values) {
      this.values.add(enc.toAsn1Primitive());
    }
  }

  AbstractAsn1Collection(Asn1Encodable... values) {
    Args.noNullElements(values, "values");
    this.values = new ArrayList<>(values.length);
    for (Asn1Encodable enc : values) {
      this.values.add(enc.toAsn1Primitive());
    }
  }

  AbstractAsn1Collection(Asn1Primitive... values) {
    Args.noNullElements(values, "values");
    this.values = new ArrayList<>(values.length);
    this.values.addAll(Arrays.asList(values));
  }

  public List<Asn1Primitive> getValues() {
    return values;
  }

  @Override
  public boolean isConstructed() {
    return true;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    int len = 0;
    for (Asn1Primitive v : values) {
      int vLen = v.getEncodedLength(encoding);
      len += Asn1Util.numBytesOfTag(v.getTagNo()) + Asn1Util.numBytesOfLength(vLen) + vLen;
    }
    return len;
  }

  @Override
  public int hashCode() {
    return getTagNo() * 31 + values.hashCode();
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof AbstractAsn1Collection)) {
      return false;
    }

    AbstractAsn1Collection b = (AbstractAsn1Collection) obj;
    return getTagNo() == b.getTagNo() && values.equals(b.values);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "[\n");
    for (Asn1Primitive m : values) {
      m.toString(buf, indentLevel + 1);
      buf.append("\n");
    }
    return ToStringUtil.appendIndent(buf, indentLevel, "]");
  }

  public int size() {
    return values.size();
  }

  public boolean isEmpty() {
    return values.isEmpty();
  }

  public boolean notHasBoolean(int index) {
    return !hasBoolean(index);
  }

  public boolean hasBoolean(int index) {
    return hasType(index, PrimitiveType.BOOLEAN);
  }

  public boolean notHasInteger(int index) {
    return !hasInteger(index);
  }

  public boolean hasInteger(int index) {
    return hasType(index, PrimitiveType.INTEGER);
  }

  public boolean notHasIA5String(int index) {
    return !hasIA5String(index);
  }

  public boolean hasIA5String(int index) {
    return hasType(index, PrimitiveType.IA5_STRING);
  }

  public boolean notHasUtf8String(int index) {
    return !hasUtf8String(index);
  }

  public boolean hasUtf8String(int index) {
    return hasType(index, PrimitiveType.UTF8_STRING);
  }

  public boolean notHasOctetString(int index) {
    return !hasOctetString(index);
  }

  public boolean hasOctetString(int index) {
    return hasType(index, PrimitiveType.OCTET_STRING);
  }

  public boolean notHasBitString(int index) {
    return !hasBitString(index);
  }

  public boolean hasBitString(int index) {
    return hasType(index, PrimitiveType.BIT_STRING);
  }

  public boolean notHasSequence(int index) {
    return !hasSequence(index);
  }

  public boolean hasSequence(int index) {
    return hasType(index, PrimitiveType.SEQUENCE);
  }

  public boolean notHasSet(int index) {
    return !hasSet(index);
  }

  public boolean hasSet(int index) {
    return hasType(index, PrimitiveType.SET);
  }

  public boolean notHasOid(int index) {
    return !hasOid(index);
  }

  public boolean hasOid(int index) {
    return hasType(index, PrimitiveType.OID);
  }

  public boolean notHasGeneralizedTime(int index) {
    return !hasGeneralizedTime(index);
  }

  public boolean hasGeneralizedTime(int index) {
    return hasType(index, PrimitiveType.GENERALIZED_TIME);
  }

  public boolean notHasType(int index, PrimitiveType type) {
    return !hasType(index, type);
  }

  public boolean hasType(int index, PrimitiveType type) {
    if (index >= values.size()) {
      return false;
    }

    Asn1Primitive p = values.get(index);
    return p.type() == type;
  }

  public boolean hasAnyType(int index, PrimitiveType... types) {
    if (types == null || types.length == 0) {
      return false;
    }

    if (index >= values.size()) {
      return false;
    }

    Asn1Primitive p = values.get(index);
    for (PrimitiveType type : types) {
      if (p.type() == type) {
        return true;
      }
    }

    return false;
  }

  public boolean isNotTaggedAt(int index, int tagNo) {
    return !isTaggedAt(index, tagNo);
  }

  public boolean isTaggedAt(int index, int tagNo) {
    if (index >= values.size()) {
      return false;
    }

    Asn1Primitive p = values.get(index);
    return p instanceof Asn1TaggedObject && p.getTagNo() == tagNo;
  }

  public boolean isNotTaggedAt(int index) {
    return !isTaggedAt(index);
  }

  public boolean isTaggedAt(int index) {
    if (index >= values.size()) {
      return false;
    }

    Asn1Primitive p = values.get(index);
    return p instanceof Asn1TaggedObject;
  }

  public Asn1Primitive getObjectAt(int index) {
    return values.get(index);
  }

  private Asn1Primitive checkPrimitive(int index, PrimitiveType expectedType)
      throws CodecException {
    Asn1Primitive p = values.get(index);
    if (p.type() != expectedType) {
      throw new CodecException("object at index " + index + " is " +
          p.type() + " but expected " + expectedType);
    }
    return p;
  }

  public Asn1Set getSetAt(int index) throws CodecException {
    return (Asn1Set) checkPrimitive(index, PrimitiveType.SET);
  }

  public Asn1Sequence getSequenceAt(int index) throws CodecException {
    return (Asn1Sequence) checkPrimitive(index, PrimitiveType.SEQUENCE);
  }

  public Asn1Integer getIntegerAt(int index) throws CodecException {
    return (Asn1Integer) checkPrimitive(index, PrimitiveType.INTEGER);
  }

  /**
   * Returns the INTEGER at the given index, which must not be negative.
   * @throws CodecException if the object is not an INTEGER, or is negative.
   */
  public Asn1Integer getNonNegativeIntegerAt(int index) throws CodecException {
    return Asn1Integer.checkNonNegative(getIntegerAt(index));
  }

  public Asn1Boolean getBooleanAt(int index) throws CodecException {
    return (Asn1Boolean) checkPrimitive(index, PrimitiveType.BOOLEAN);
  }

  public Asn1Enumerated getEnumeratedAt(int index) throws CodecException {
    return (Asn1Enumerated) checkPrimitive(index, PrimitiveType.ENUMERATED);
  }

  public AbstractAsn1Time getTimeAt(int index) throws CodecException {
    Asn1Primitive r = values.get(index);
    if (r instanceof AbstractAsn1Time) {
      return (AbstractAsn1Time) r;
    }

    throw new CodecException("object at index " + index +
        " is " + r.type() + " but expected UTCTime or GeneralizedTime");
  }

  public Asn1UtcTime getUtcTimeAt(int index) throws CodecException {
    return (Asn1UtcTime) checkPrimitive(index, PrimitiveType.UTC_TIME);
  }

  public Asn1GeneralizedTime getGeneralizedTimeAt(int index) throws CodecException {
    return (Asn1GeneralizedTime) checkPrimitive(index, PrimitiveType.GENERALIZED_TIME);
  }

  public Asn1Oid getOidAt(int index) throws CodecException {
    return (Asn1Oid) checkPrimitive(index, PrimitiveType.OID);
  }

  public Asn1RelativeOid getRelativeOidAt(int index) throws CodecException {
    return (Asn1RelativeOid) checkPrimitive(index, PrimitiveType.RELATIVE_OID);
  }

  public Asn1BitString getBitStringAt(int index) throws CodecException {
    return (Asn1BitString) checkPrimitive(index, PrimitiveType.BIT_STRING);
  }

  public Asn1OctetString getOctetStringAt(int index) throws CodecException {
    return (Asn1OctetString) checkPrimitive(index, PrimitiveType.OCTET_STRING);
  }

  public AbstractAsn1String getString(int index) throws CodecException {
    Asn1Primitive r = values.get(index);
    if (r instanceof AbstractAsn1String) {
      return (AbstractAsn1String) r;
    }

    throw new CodecException("object at index " + index + " is " +
        r.type() + " but expected STRING");
  }

  public Asn1PrintableString getPrintableStringAt(int index) throws CodecException {
    return (Asn1PrintableString) checkPrimitive(index, PrimitiveType.PRINTABLE_STRING);
  }

  public Asn1Utf8String getUtf8StringAt(int index) throws CodecException {
    return (Asn1Utf8String) checkPrimitive(index, PrimitiveType.UTF8_STRING);
  }

  public Asn1IA5String getIA5StringAt(int index) throws CodecException {
    return (Asn1IA5String) checkPrimitive(index, PrimitiveType.IA5_STRING);
  }

  public Asn1BmpString getBmpString(int index) throws CodecException {
    return (Asn1BmpString) checkPrimitive(index, PrimitiveType.BMP_STRING);
  }

  public Asn1VisibleString getVisibleStringAt(int index) throws CodecException {
    return (Asn1VisibleString) checkPrimitive(index, PrimitiveType.VISIBLE_STRING);
  }

  public Asn1TaggedObject getTaggedAt(int index) throws CodecException {
    Asn1Primitive r = values.get(index);
    if (r instanceof Asn1TaggedObject) {
      return (Asn1TaggedObject) r;
    }
    throw new CodecException("object at index " + index + " is " + r.type() +
        ", expected is a tagged object");
  }

  public Asn1TaggedObject getTaggedAt(int index, int expectedTagNo) throws CodecException {
    Asn1TaggedObject t = getTaggedAt(index);
    if (t.getTagNo() != expectedTagNo) {
      throw new CodecException("element at " + index + " has tagNo " +
          t.getTagNo() + ", but expected " + expectedTagNo);
    }
    return t;
  }

  public Asn1Primitive getObjectOfExplicitTaggedAt(int index) throws CodecException {
    Asn1TaggedObject t = getTaggedAt(index);
    return t.getExplicitBase();
  }

  public Asn1Primitive getObjectOfImplicitTaggedAt(int index, int baseObjectTagNo)
      throws CodecException {
    Asn1TaggedObject t = getTaggedAt(index);
    return t.getImplicitBase(baseObjectTagNo);
  }

  private Asn1Primitive getObjectOfTaggedAt(int index, boolean explicit, int baseObjectTagNo)
      throws CodecException {
    if (explicit) {
      return Asn1Decoder.rejectInvalidTextString(
          getObjectOfExplicitTaggedAt(index), baseObjectTagNo);
    } else {
      // the implicit base is already checked by Asn1TaggedObject.getImplicitBase().
      return getObjectOfImplicitTaggedAt(index, baseObjectTagNo);
    }
  }

  public Asn1Set getSetTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Set) getObjectOfTaggedAt(index, explicit, Asn1Tags.SET);
  }

  public Asn1Sequence getSequenceTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Sequence) getObjectOfTaggedAt(index, explicit, Asn1Tags.SEQUENCE);
  }

  public Asn1Integer getIntegerTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Integer) getObjectOfTaggedAt(index, explicit, Asn1Tags.INTEGER);
  }

  /**
   * Returns the tagged INTEGER at the given index, which must not be negative.
   * @throws CodecException if the object is not a tagged INTEGER, or is negative.
   */
  public Asn1Integer getNonNegativeIntegerTaggedAt(int index, boolean explicit)
      throws CodecException {
    return Asn1Integer.checkNonNegative(getIntegerTaggedAt(index, explicit));
  }

  public Asn1Boolean getBooleanTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Boolean) getObjectOfTaggedAt(index, explicit, Asn1Tags.BOOLEAN);
  }

  public Asn1Enumerated getEnumeratedTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Enumerated) getObjectOfTaggedAt(index, explicit, Asn1Tags.ENUMERATED);
  }

  public AbstractAsn1Time getTimeExplicitTaggedAt(int index) throws CodecException {
    Asn1Primitive r = getObjectOfExplicitTaggedAt(index);
    if (r instanceof AbstractAsn1Time) {
      return (AbstractAsn1Time) r;
    }
    throw new CodecException("object at index " + index + " is not a UTCTime or a GeneralizedTime");
  }

  public Asn1UtcTime getUtcTimeTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1UtcTime) getObjectOfTaggedAt(index, explicit, Asn1Tags.UTC_TIME);
  }

  public Asn1GeneralizedTime getGeneralizedTimeTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1GeneralizedTime) getObjectOfTaggedAt(index, explicit, Asn1Tags.GENERALIZED_TIME);
  }

  public Asn1Oid getOidTaggedAt(int index, boolean explicit) throws CodecException {
    return (Asn1Oid) getObjectOfTaggedAt(index, explicit, Asn1Tags.OBJECT_IDENTIFIER);
  }

  public Asn1RelativeOid getRelativeOidTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1RelativeOid) getObjectOfTaggedAt(index, explicit, Asn1Tags.RELATIVE_OID);
  }

  public Asn1BitString getBitStringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1BitString) getObjectOfTaggedAt(index, explicit, Asn1Tags.BIT_STRING);
  }

  public Asn1OctetString getOctetStringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1OctetString) getObjectOfTaggedAt(index, explicit, Asn1Tags.OCTET_STRING);
  }

  public Asn1PrintableString getPrintableStringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1PrintableString) getObjectOfTaggedAt(index, explicit, Asn1Tags.PRINTABLE_STRING);
  }

  public Asn1Utf8String getUtf8StringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1Utf8String) getObjectOfTaggedAt(index, explicit, Asn1Tags.UTF8_STRING);
  }

  public Asn1IA5String getIA5StringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1IA5String) getObjectOfTaggedAt(index, explicit, Asn1Tags.IA5_STRING);
  }

  public Asn1BmpString getBMPStringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1BmpString) getObjectOfTaggedAt(index, explicit, Asn1Tags.BMP_STRING);
  }

  public Asn1VisibleString getVisibleStringTaggedAt(int index, boolean explicit)
      throws CodecException {
    return (Asn1VisibleString) getObjectOfTaggedAt(index, explicit, Asn1Tags.VISIBLE_STRING);
  }

  public List<Asn1Integer> toIntegers() {
    List<Asn1Integer> r = new ArrayList<>(values.size());
    for (Asn1Primitive value : values) {
      r.add((Asn1Integer) value);
    }
    return r;
  }

  public List<Asn1Utf8String> toUtf8Strings() {
    List<Asn1Utf8String> r = new ArrayList<>(values.size());
    for (Asn1Primitive value : values) {
      r.add((Asn1Utf8String) value);
    }
    return r;
  }

  public List<Asn1OctetString> toOctetStrings() {
    List<Asn1OctetString> r = new ArrayList<>(values.size());
    for (Asn1Primitive value : values) {
      r.add((Asn1OctetString) value);
    }
    return r;
  }

}
