// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.AbstractAsn1Collection;
import org.xipki.codec.asn1.AbstractSeq1;
import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.PublicKey;
import java.util.List;

/**
 * <pre>
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class SubjectPublicKeyInfo extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<SubjectPublicKeyInfo> {

    public Seq1(SubjectPublicKeyInfo... entries) {
      super(entries);
    }

    public Seq1(List<SubjectPublicKeyInfo> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected SubjectPublicKeyInfo newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return SubjectPublicKeyInfo.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final AlgorithmIdentifier algorithm;
  private final Asn1BitString subjectPublicKey;

  public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, Asn1BitString subjectPublicKey) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.subjectPublicKey = Args.notNull(subjectPublicKey, "subjectPublicKey");
  }

  public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, Asn1Encodable subjectPublicKey) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    Args.notNull(subjectPublicKey, "subjectPublicKey");
    this.subjectPublicKey = new Asn1BitString(subjectPublicKey.getEncoded(Asn1Encoding.DER));
  }

  public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, byte[] subjectPublicKey) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.subjectPublicKey = new Asn1BitString(Args.notNull(subjectPublicKey, "subjectPublicKey"));
  }

  public static SubjectPublicKeyInfo fromPublicKey(PublicKey publicKey) throws CodecException {
    return fromEncoded(publicKey.getEncoded());
  }

  public static SubjectPublicKeyInfo fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SubjectPublicKeyInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);

    AlgorithmIdentifier algId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1BitString keyData = seq.getBitStringAt(1);
    return new SubjectPublicKeyInfo(algId, keyData);
  }

  public static AlgorithmIdentifier algorithmFromPublicKey(PublicKey publicKey)
      throws CodecException {
    return algorithmFromAsn1(Asn1Sequence.fromEncoded(publicKey.getEncoded()));
  }

  public static AlgorithmIdentifier algorithmFromEncoded(byte[] encoded) throws CodecException {
    return algorithmFromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AlgorithmIdentifier algorithmFromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    return AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
  }

  public AlgorithmIdentifier getAlgorithm() {
    return algorithm;
  }

  public Asn1BitString getSubjectPublicKey() {
    return subjectPublicKey;
  }

  public byte[] subjectPublicKey() {
    return subjectPublicKey.getAlignedOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(algorithm, subjectPublicKey);
  }

  @Override
  public int hashCode() {
    return algorithm.hashCode() * 31 + subjectPublicKey.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof SubjectPublicKeyInfo)) {
      return false;
    }

    SubjectPublicKeyInfo b = (SubjectPublicKeyInfo) obj;
    return algorithm.equals(b.algorithm) && subjectPublicKey.equals(b.subjectPublicKey);
  }

  @Override
  protected String getTitle() {
    return "SubjectPublicKeyInfo";
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    algorithm.toStringWithLineSep(buf, indentLevel, "algorithm", true);
    return subjectPublicKey.toStringWithLineSep(buf, indentLevel, "subjectPublicKey");
  }

}
