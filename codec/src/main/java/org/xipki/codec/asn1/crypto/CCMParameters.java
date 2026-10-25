// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <a href="https://tools.ietf.org/html/rfc5084">RFC 5084</a>: CCMParameters object.
 * <p>
 * <pre>
 CCMParameters ::= SEQUENCE {
   aes-nonce        OCTET STRING, -- recommended size is 12 octets
   aes-ICVlen       AES-CCM-ICVlen DEFAULT 12 }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class CCMParameters extends Asn1Encodable {

  private final Asn1OctetString nonce;
  private final Asn1Integer icvLen;

  public static CCMParameters fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1OctetString nonce = seq.getOctetStringAt(0);
    Asn1Integer icvLen = (size == 1) ? new Asn1Integer(12) : seq.getNonNegativeIntegerAt(1);
    return new CCMParameters(nonce, icvLen);
  }

  public CCMParameters(Asn1OctetString nonce, Asn1Integer icvLen) {
    this.nonce = Args.notNull(nonce, "nonce");
    this.icvLen = Args.notNull(icvLen, "icvLen");
    Args.positive(icvLen.intValueExact(), "icvLen");
  }

  public CCMParameters(byte[] nonce, int icvLen) {
    this.nonce = new Asn1OctetString(Args.notNull(nonce, "nonce"));
    this.icvLen = new Asn1Integer(Args.positive(icvLen, "icvLen"));
  }

  public Asn1OctetString getNonce() {
    return nonce;
  }

  public Asn1Integer getIcvLen() {
    return icvLen;
  }

  public byte[] nonce() {
    return nonce.getOctets();
  }

  public int icvLen() {
    return icvLen.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(nonce, icvLen.hasValue(12) ? null : icvLen);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    nonce.toStringWithLineSep(buf, indentLevel, "nonce", true);
    icvLen.toStringNoLineSep(buf, indentLevel, "icvLen", true);

    return deleteLastNewLine(buf);
  }

}
