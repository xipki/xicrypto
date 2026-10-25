// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * <pre>
 * RSAPublicKey ::= SEQUENCE {
 *      modulus INTEGER, -- n
 *      publicExponent INTEGER, -- e
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class RSAPublicKey extends Asn1Encodable {

  private final Asn1Integer modulus;
  private final Asn1Integer publicExponent;

  public RSAPublicKey(BigInteger modulus, BigInteger publicExponent) {
    this.modulus = new Asn1Integer(Args.notNull(modulus, "modulus"));
    this.publicExponent = new Asn1Integer(Args.notNull(publicExponent, "publicExponent"));
  }

  public RSAPublicKey(Asn1Integer modulus, Asn1Integer publicExponent) {
    this.modulus = Args.notNull(modulus, "modulus");
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
  }

  public static RSAPublicKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static RSAPublicKey fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Integer modulus = seq.getNonNegativeIntegerAt(0);
    Asn1Integer publicExponent = seq.getNonNegativeIntegerAt(1);
    return new RSAPublicKey(modulus, publicExponent);
  }

  public Asn1Integer getModulus() {
    return modulus;
  }

  public BigInteger modulus() {
    return modulus.getValue();
  }

  public Asn1Integer getPublicExponent() {
    return publicExponent;
  }

  public BigInteger publicExponent() {
    return publicExponent.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(modulus, publicExponent);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendBigInt(buf, indentLevel, "modulus", modulus.getValue());
    publicExponent.toStringNoLineSep(buf, indentLevel, "publicExponent", true);

    return deleteLastNewLine(buf);
  }

}
