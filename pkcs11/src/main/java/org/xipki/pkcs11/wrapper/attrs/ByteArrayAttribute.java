// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.attrs;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.exception.CodecException;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11T;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Byte Array Attribute, as specified by PKCS#11.
 *
 * @author Lijun Liao (xipki)
 */
public class ByteArrayAttribute extends Attribute {

  public ByteArrayAttribute(long type, byte[] value) {
    super(type, value);
  }

  public ByteArrayAttribute(long type, BigInteger value) {
    super(type, value == null ? null : Functions.asUnsignedByteArray(value));
  }

  /**
   * Get the byte-array value of this attribute. Null, is also possible.
   *
   * @return The byte-array value of this attribute or null.
   */
  public byte[] getValue() {
    return (byte[]) value;
  }

  public void setValue(byte[] value) {
    this.value = value;
  }

  public BigInteger getBigIntValue() {
    return isNullValue() ? null : new BigInteger(1, (byte[]) value);
  }

  /**
   * Get a string representation of this attribute's value.
   *
   * @return A string representation of this attribute's value.
   */
  @Override
  protected String getValueString() {
    if (isNullValue()) {
      return "<NULL_PTR>";
    }

    byte[] bvalue = (byte[]) value;
    String text = "byte[" + bvalue.length + "]\n" + Functions.toString("    ", bvalue);

    long type = type();
    if (type == PKCS11T.CKA_EC_PARAMS) {
      String[] curveNames = Functions.getCurveNames(bvalue);
      String curveOid;
      try {
        curveOid = Asn1Oid.fromEncoded(bvalue).getId();
      } catch (CodecException e) {
        curveOid = "<ERROR>";
      }
      text += " (" + curveOid + ", " + Arrays.toString(curveNames) + ")";
    }

    return text;
  }

}
