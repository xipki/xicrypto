// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 8018:
 * <pre>
 *    PBEParameter ::= SEQUENCE {
 *       salt            OCTET STRING (SIZE(8)),
 *       iterationCount  INTEGER }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class PBEParameter extends Asn1Encodable {

  private final Asn1Integer iterations;
  private final Asn1OctetString salt;

  public PBEParameter(byte[] salt, int iterations) {
    Args.notNull(salt, "salt");
    Args.equals(salt.length, "salt length", 8);
    this.salt = new Asn1OctetString(salt);
    this.iterations = new Asn1Integer(iterations);
  }

  public PBEParameter(Asn1Integer iterations, Asn1OctetString salt) {
    this.salt = Args.notNull(salt, "salt");
    Args.equals(salt.getEncodedLength(Asn1Encoding.DER), "salt length", 8);
    this.iterations = Args.notNull(iterations, "iterations");
  }

  public static PBEParameter fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1OctetString  salt = seq.getOctetStringAt(0);
    Asn1Integer iterations = seq.getNonNegativeIntegerAt(1);
    return new PBEParameter(iterations, salt);
  }

  public Asn1Integer getIterations() {
    return iterations;
  }

  public Asn1OctetString getSalt() {
    return salt;
  }

  public int iterationCount() {
    return iterations.intValueExact();
  }

  public byte[] salt() {
    return salt.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(salt, iterations);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    salt.toStringWithLineSep(buf, indentLevel, "salt", true);
    iterations.toStringNoLineSep(buf, indentLevel, "iterations", true);

    return deleteLastNewLine(buf);
  }

}
