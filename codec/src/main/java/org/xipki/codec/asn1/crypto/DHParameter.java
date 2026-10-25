// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * PKCS#3:
 * <pre>
 * DHParameter ::= SEQUENCE {
 *     prime               INTEGER,
 *     base                INTEGER,
 *     privateValueLength  INTEGER OPTIONAL
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class DHParameter extends Asn1Encodable {

  private final Asn1Integer p, g, l;

  public DHParameter(BigInteger p, BigInteger g, int l) {
    this.p = new Asn1Integer(Args.notNull(p, "p"));
    this.g = new Asn1Integer(Args.notNull(g, "g"));
    this.l = (l == 0) ? null : new Asn1Integer(l);
  }

  public DHParameter(Asn1Integer p, Asn1Integer g, Asn1Integer l) {
    this.p = Args.notNull(p, "p");
    this.g = Args.notNull(g, "g");
    this.l = l;
  }

  public static DHParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 3);
    Asn1Integer p = seq.getNonNegativeIntegerAt(0);
    Asn1Integer g = seq.getNonNegativeIntegerAt(1);
    Asn1Integer l = (size == 2) ? null : seq.getNonNegativeIntegerAt(2);
    return new DHParameter(p, g, l);
  }

  public Asn1Integer getP() {
    return p;
  }

  public Asn1Integer getG() {
    return g;
  }

  public Asn1Integer getL() {
    return l;
  }

  public BigInteger p() {
    return p.getValue();
  }

  public BigInteger g() {
    return g.getValue();
  }

  public BigInteger l() {
    return Asn1Util.fromAsn1(l);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(p, g, l);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendBigInt(buf, indentLevel, "p", p.getValue());
    ToStringUtil.appendBigInt(buf, indentLevel, "g", g.getValue());

    if (l != null) {
      l.toStringNoLineSep(buf, indentLevel, "l", true);
    }

    return deleteLastNewLine(buf);
  }

}
