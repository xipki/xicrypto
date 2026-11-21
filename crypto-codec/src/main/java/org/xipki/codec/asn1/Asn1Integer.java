// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * INTEGER
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Integer extends Asn1Primitive {

  public static final Asn1Integer ZERO = new Asn1Integer(0);

  public static final Asn1Integer ONE = new Asn1Integer(1);

  public static final Asn1Integer TWO = new Asn1Integer(2);

  public static final Asn1Integer THREE = new Asn1Integer(3);

  public static final Asn1Integer FOUR = new Asn1Integer(4);

  public static final Asn1Integer FIVE = new Asn1Integer(5);

  private final BigInteger value;

  private final byte[] octets;

  public static Asn1Integer fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Integer) Asn1Util.readAsn1Object(Asn1Tags.INTEGER, encoded);
  }

  /**
   * Decodes the INTEGER which must not be negative.
   * @param encoded the encoded INTEGER.
   * @return the decoded INTEGER.
   * @throws CodecException if the encoding is invalid, or the value is negative.
   */
  public static Asn1Integer fromEncodedNonNegative(byte[] encoded) throws CodecException {
    return checkNonNegative(fromEncoded(encoded));
  }

  /**
   * Checks that the decoded INTEGER is not negative, e.g. a serial number, a version, a length
   * or a parameter of the cryptographic algorithm.
   * @param value the INTEGER, may be null.
   * @return the given value.
   * @throws CodecException if value is negative.
   */
  public static Asn1Integer checkNonNegative(Asn1Integer value) throws CodecException {
    if (value != null && value.value.signum() == -1) {
      throw new CodecException("negative INTEGER is not allowed");
    }
    return value;
  }

  public Asn1Integer(int value) {
    this.value = BigInteger.valueOf(value);
    this.octets = this.value.toByteArray();
  }

  public Asn1Integer(long value) {
    this.value = BigInteger.valueOf(value);
    this.octets = this.value.toByteArray();
  }

  public Asn1Integer(BigInteger value) {
    this.value = Args.notNull(value, "value");
    this.octets = value.toByteArray();
  }

  public boolean hasValue(int value) {
    try {
      return this.value.intValueExact() == value;
    } catch (ArithmeticException e) {
      return false;
    }
  }

  public boolean hasValue(long value) {
    try {
      return this.value.longValueExact() == value;
    } catch (ArithmeticException e) {
      return false;
    }
  }

  public boolean hasValue(BigInteger value) {
    try {
      return this.value.equals(value);
    } catch (ArithmeticException e) {
      return false;
    }
  }

  public BigInteger getValue() {
    return value;
  }

  public int intValueExact() {
    return value.intValueExact();
  }

  public long longValueExact() {
    return value.longValueExact();
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.INTEGER;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.INTEGER;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Integer)) {
      return false;
    }

    Asn1Integer b = (Asn1Integer) obj;
    return value.equals(b.value);
  }

  @Override
  public String toString() {
    return value.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.appendIndent(buf,indentLevel, value.toString());
  }

}
