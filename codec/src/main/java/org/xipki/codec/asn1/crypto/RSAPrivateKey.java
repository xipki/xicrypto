// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * RFC 8017 (PKCS#1):
 * <pre>
 * RSAPrivateKey ::= SEQUENCE {
 *     version           Version,
 *     modulus           INTEGER,  -- n
 *     publicExponent    INTEGER,  -- e
 *     privateExponent   INTEGER,  -- d
 *     prime1            INTEGER,  -- p
 *     prime2            INTEGER,  -- q
 *     exponent1         INTEGER,  -- d mod (p-1)
 *     exponent2         INTEGER,  -- d mod (q-1)
 *     coefficient       INTEGER,  -- (inverse of q) mod p
 *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
 * }
 *
 * Version ::= INTEGER { two-prime(0), multi(1) }
 *     (CONSTRAINED BY {
 *        -- version must be multi if otherPrimeInfos present --})
 *
 * OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
 *
 *
 * OtherPrimeInfo ::= SEQUENCE {
 *     prime             INTEGER,  -- ri
 *     exponent          INTEGER,  -- di
 *     coefficient       INTEGER   -- ti
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class RSAPrivateKey extends Asn1Encodable {

  private final Asn1Integer  version;
  private final Asn1Integer  modulus;
  private final Asn1Integer  publicExponent;
  private final Asn1Integer  privateExponent;
  private final Asn1Integer  prime1;
  private final Asn1Integer  prime2;
  private final Asn1Integer  exponent1;
  private final Asn1Integer  exponent2;
  private final Asn1Integer  coefficient;
  private final Asn1Sequence otherPrimeInfos;

  public RSAPrivateKey(
      BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent,
      BigInteger prime1, BigInteger prime2,
      BigInteger exponent1, BigInteger exponent2, BigInteger coefficient) {
      this.version = Asn1Integer.ZERO;
      this.modulus = new Asn1Integer(Args.notNull(modulus, "modulus"));
      this.publicExponent = new Asn1Integer(Args.notNull(publicExponent, "publicExponent"));
      this.privateExponent = new Asn1Integer(Args.notNull(privateExponent, "privateExponent"));
      this.prime1 = new Asn1Integer(Args.notNull(prime1, "prime1"));
      this.prime2 = new Asn1Integer(Args.notNull(prime2, "prime2"));
      this.exponent1 = new Asn1Integer(Args.notNull(exponent1, "exponent1"));
      this.exponent2 = new Asn1Integer(Args.notNull(exponent2, "exponent2"));
      this.coefficient = new Asn1Integer(Args.notNull(coefficient, "coefficient"));
      this.otherPrimeInfos = null;
  }

  public RSAPrivateKey(
      Asn1Integer version, Asn1Integer modulus, Asn1Integer publicExponent,
      Asn1Integer privateExponent, Asn1Integer prime1, Asn1Integer prime2,
      Asn1Integer exponent1, Asn1Integer exponent2, Asn1Integer coefficient,
      Asn1Sequence otherPrimeInfos) {
    this.version = Args.notNull(version, "version");
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
    this.privateExponent = Args.notNull(privateExponent, "privateExponent");
    this.prime1 = Args.notNull(prime1, "prime1");
    this.prime2 = Args.notNull(prime2, "prime2");
    this.exponent1 = Args.notNull(exponent1, "exponent1");
    this.exponent2 = Args.notNull(exponent2, "exponent2");
    this.coefficient = Args.notNull(coefficient, "coefficient");
    this.otherPrimeInfos = otherPrimeInfos;
  }

  public static RSAPrivateKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static RSAPrivateKey fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 9, 10);

    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    int versionValue = version.intValueExact();
    if (versionValue < 0 || versionValue > 1) {
        throw new CodecException("wrong version for RSA private key: " + versionValue);
    }

    Asn1Integer modulus = seq.getNonNegativeIntegerAt(1);
    Asn1Integer publicExponent = seq.getNonNegativeIntegerAt(2);
    Asn1Integer privateExponent = seq.getNonNegativeIntegerAt(3);
    Asn1Integer prime1 = seq.getNonNegativeIntegerAt(4);
    Asn1Integer prime2 = seq.getNonNegativeIntegerAt(5);
    Asn1Integer exponent1 = seq.getNonNegativeIntegerAt(6);
    Asn1Integer exponent2 = seq.getNonNegativeIntegerAt(7);
    Asn1Integer coefficient = seq.getNonNegativeIntegerAt(8);

    Asn1Sequence otherPrimeInfos = (size > 9) ? seq.getSequenceAt(9) : null;
    if (otherPrimeInfos != null && versionValue != 1) {
      throw new CodecException("version for RSA private key is not multi(1): " + versionValue);
    }

    return new RSAPrivateKey(version, modulus, publicExponent, privateExponent, prime1, prime2,
        exponent1, exponent2, coefficient, otherPrimeInfos);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public Asn1Integer getModulus() {
    return modulus;
  }

  public Asn1Integer getPublicExponent() {
    return publicExponent;
  }

  public Asn1Integer getPrivateExponent() {
    return privateExponent;
  }

  public Asn1Integer getPrime1() {
    return prime1;
  }

  public Asn1Integer getPrime2() {
    return prime2;
  }

  public Asn1Integer getExponent1() {
    return exponent1;
  }

  public Asn1Integer getExponent2() {
    return exponent2;
  }

  public Asn1Integer getCoefficient() {
    return coefficient;
  }

  public int version() {
    return version.intValueExact();
  }

  public BigInteger modulus() {
    return modulus.getValue();
  }

  public BigInteger publicExponent() {
    return publicExponent.getValue();
  }

  public BigInteger privateExponent() {
    return privateExponent.getValue();
  }

  public BigInteger prime1() {
    return prime1.getValue();
  }

  public BigInteger prime2() {
    return prime2.getValue();
  }

  public BigInteger exponent1() {
    return exponent1.getValue();
  }

  public BigInteger exponent2() {
    return exponent2.getValue();
  }

  public BigInteger coefficient() {
    return coefficient.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, modulus, publicExponent, privateExponent,
        prime1, prime2, exponent1, exponent2, coefficient, otherPrimeInfos);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    ToStringUtil.appendBigInt(buf, indentLevel, "modulus", modulus.getValue());
    publicExponent.toStringNoLineSep(buf, indentLevel, "publicExponent", true);
    // the private key material is not printed.
    ToStringUtil.appendSecret(buf, indentLevel, "privateExponent",
        BigIntegers.asUnsignedByteArray(privateExponent.getValue()).length);
    ToStringUtil.appendSecret(buf, indentLevel, "prime1",
        BigIntegers.asUnsignedByteArray(prime1.getValue()).length);
    ToStringUtil.appendSecret(buf, indentLevel, "prime2",
        BigIntegers.asUnsignedByteArray(prime2.getValue()).length);
    ToStringUtil.appendSecret(buf, indentLevel, "exponent1",
        BigIntegers.asUnsignedByteArray(exponent1.getValue()).length);
    ToStringUtil.appendSecret(buf, indentLevel, "exponent2",
        BigIntegers.asUnsignedByteArray(exponent2.getValue()).length);
    ToStringUtil.appendSecret(buf, indentLevel, "coefficient",
        BigIntegers.asUnsignedByteArray(coefficient.getValue()).length);

    if (otherPrimeInfos != null) {
      ToStringUtil.appendSecret(buf, indentLevel, "otherPrimeInfos",
          otherPrimeInfos.getEncoded().length);
    }

    return deleteLastNewLine(buf);
  }
}
