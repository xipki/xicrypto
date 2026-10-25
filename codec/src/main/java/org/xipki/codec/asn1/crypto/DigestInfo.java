// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * The DigestInfo object.
 * <pre>
 * DigestInfo ::= SEQUENCE{
 *     digestAlgorithm   AlgorithmIdentifier,
 *     digest            OCTET STRING }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class DigestInfo extends Asn1Encodable {

  private final AlgorithmIdentifier algId;

  private final Asn1OctetString digest;

  public DigestInfo(AlgorithmIdentifier algId, byte[] digest) {
    this.algId = Args.notNull(algId, "algId");
    this.digest = new Asn1OctetString(Args.notNull(digest, "digest"));
  }

  public DigestInfo(AlgorithmIdentifier algId, Asn1OctetString digest) {
    this.algId = Args.notNull(algId, "algId");
    this.digest = Args.notNull(digest, "digest");
  }

  public static DigestInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier algId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString digest = seq.getOctetStringAt(1);
    return new DigestInfo(algId, digest);
  }

  public AlgorithmIdentifier getAlgorithmId() {
    return algId;
  }

  public Asn1OctetString getDigest() {
    return digest;
  }

  public byte[] digest() {
    return digest.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(algId, digest);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    algId.toStringWithLineSep(buf, indentLevel, "algId", true);
    digest.toStringWithLineSep(buf, indentLevel, "digest", true);

    return deleteLastNewLine(buf);
  }

}
