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
 * RFC 3371 (PKCS#3)
 * <pre>
 * ElGamalParameter ::= SEQUENCE {
 *     prime INTEGER,
 *     base  INTEGER
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class ElGamalParameter extends Asn1Encodable {

  private final Asn1Integer p;

  private final Asn1Integer g;

  public ElGamalParameter(BigInteger p, BigInteger g) {
    this.p = new Asn1Integer(Args.notNull(p, "p"));
    this.g = new Asn1Integer(Args.notNull(g, "g"));
  }

  public ElGamalParameter(Asn1Integer p, Asn1Integer g) {
    this.p = Args.notNull(p, "p");
    this.g = Args.notNull(g, "g");
  }

  public static ElGamalParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Integer p = seq.getNonNegativeIntegerAt(0);
    Asn1Integer g = seq.getNonNegativeIntegerAt(1);
    return new ElGamalParameter(p, g);
  }

  public Asn1Integer getP() {
    return p;
  }

  public Asn1Integer getG() {
    return g;
  }

  public BigInteger p() {
    return p.getValue();
  }

  public BigInteger g() {
    return g.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(p, g);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendBigInt(buf, indentLevel, "p", p.getValue());
    ToStringUtil.appendBigInt(buf, indentLevel, "g", g.getValue());

    return deleteLastNewLine(buf);
  }
}
