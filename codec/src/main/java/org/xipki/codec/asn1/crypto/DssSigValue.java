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
 * RFC 3279
 * <pre>
 * Dss-Sig-Value ::= SEQUENCE {
 *     r   INTEGER,
 *     s   INTEGER
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class DssSigValue extends Asn1Encodable {

  private final Asn1Integer r;

  private final Asn1Integer s;

  public DssSigValue(Asn1Integer r, Asn1Integer s) {
    this.r = Args.notNull(r, "r");
    this.s = Args.notNull(s, "s");
  }

  public DssSigValue(BigInteger r, BigInteger s) {
    this(Asn1Util.toInteger(r), Asn1Util.toInteger(s));
  }

  public static DssSigValue fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static DssSigValue fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return new DssSigValue(seq.getNonNegativeIntegerAt(0), seq.getNonNegativeIntegerAt(1));
  }

  public Asn1Integer getR() {
    return r;
  }

  public BigInteger r() {
    return r.getValue();
  }

  public Asn1Integer getS() {
    return s;
  }

  public BigInteger s() {
    return s.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(r, s);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendBigInt(buf, indentLevel, "r", r.getValue());
    ToStringUtil.appendBigInt(buf, indentLevel, "s", s.getValue());

    return deleteLastNewLine(buf);
  }

}
