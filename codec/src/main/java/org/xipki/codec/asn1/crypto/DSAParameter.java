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
 * DSA-Params ::= SEQUENCE {
 *   p  INTEGER,
 *   q  INTEGER,
 *   g  INTEGER
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class DSAParameter extends Asn1Encodable {

  private final Asn1Integer p, q, g;

  public DSAParameter(BigInteger p, BigInteger q, BigInteger g) {
    this.p = new Asn1Integer(Args.notNull(p, "p"));
    this.q = new Asn1Integer(Args.notNull(q, "q"));
    this.g = new Asn1Integer(Args.notNull(g, "g"));
  }

  public DSAParameter(Asn1Integer p, Asn1Integer q, Asn1Integer g) {
    this.p = Args.notNull(p, "p");
    this.q = Args.notNull(q, "q");
    this.g = Args.notNull(g, "g");
  }

  public static DSAParameter fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static DSAParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    Asn1Integer p = seq.getNonNegativeIntegerAt(0);
    Asn1Integer q = seq.getNonNegativeIntegerAt(1);
    Asn1Integer g = seq.getNonNegativeIntegerAt(2);
    return new DSAParameter(p, q, g);
  }

  public Asn1Integer getP() {
    return p;
  }

  public Asn1Integer getQ() {
    return q;
  }

  public Asn1Integer getG() {
    return g;
  }

  public BigInteger p() {
    return p.getValue();
  }

  public BigInteger q() {
    return q.getValue();
  }

  public BigInteger g() {
    return g.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(p, q, g);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendBigInt(buf, indentLevel, "p", p.getValue());
    ToStringUtil.appendBigInt(buf, indentLevel, "q", q.getValue());
    ToStringUtil.appendBigInt(buf, indentLevel, "g", g.getValue());

    return deleteLastNewLine(buf);
  }

}
