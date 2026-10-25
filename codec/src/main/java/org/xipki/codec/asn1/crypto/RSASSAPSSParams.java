// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.List;

/**
 * RFC 8017 (PKCS #1 v2.2):
 * <pre>
 * DEFINITIONS EXPLICIT TAGS ::=
 *
 * RSASSA-PSS-params ::= SEQUENCE {
 *   hashAlgorithm     [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
 *   maskGenAlgorithm  [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
 *   saltLength        [2] INTEGER  DEFAULT 20,
 *   trailerField      [3] TrailerField  DEFAULT trailerFieldBC
 * }
 *
 * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *    { OID id-sha1 PARAMETERS NULL   }|
 *    { OID id-sha256 PARAMETERS NULL }|
 *    { OID id-sha384 PARAMETERS NULL }|
 *    { OID id-sha512 PARAMETERS NULL },
 *    ...  -- Allows for future expansion --
 * }
 *
 * PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *   { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
 *    ...  -- Allows for future expansion --
 * }
 *
 * TrailerField ::= INTEGER { trailerFieldBC(1) }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class RSASSAPSSParams extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlgorithm;
  private final AlgorithmIdentifier maskGenAlgorithm;
  private final Asn1Integer saltLength;
  private final Asn1Integer trailerField;

  public final static AlgorithmIdentifier DEFAULT_HASH_ALGORITHM =
      new AlgorithmIdentifier(CryptoOIDs.idSHA1, Asn1Null.INSTANCE);

  public final static AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION;
  public final static Asn1Integer DEFAULT_SALT_LENGTH = new Asn1Integer(20);
  public final static Asn1Integer DEFAULT_TRAILER_FIELD = Asn1Integer.ONE;

  static {
    DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(CryptoOIDs.id_mgf1,
        DEFAULT_HASH_ALGORITHM.toAsn1Primitive());
  }

  /**
   * The default version
   */
  public RSASSAPSSParams() {
    hashAlgorithm = DEFAULT_HASH_ALGORITHM;
    maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
    saltLength = DEFAULT_SALT_LENGTH;
    trailerField = DEFAULT_TRAILER_FIELD;
  }

  public RSASSAPSSParams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm,
                         Asn1Integer saltLength, Asn1Integer trailerField) {
      this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
      this.maskGenAlgorithm = Args.notNull(maskGenAlgorithm, "maskGenAlgorithm");
      this.saltLength = Args.notNull(saltLength, "saltLength");
      this.trailerField = Args.notNull(trailerField, "trailerField");
  }

  public static RSASSAPSSParams fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 4);
    int index = 0;
    AlgorithmIdentifier hashAlgorithm = seq.isNotTaggedAt(index, 0) ? DEFAULT_HASH_ALGORITHM
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    AlgorithmIdentifier maskGenAlgorithm = seq.isNotTaggedAt(index, 1) ? DEFAULT_MASK_GEN_FUNCTION
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));
    Asn1Integer saltLength = seq.isNotTaggedAt(index, 2) ? DEFAULT_SALT_LENGTH
        : seq.getNonNegativeIntegerTaggedAt(index++, true);
    Asn1Integer trailerField = seq.isNotTaggedAt(index, 3) ? DEFAULT_TRAILER_FIELD
            : seq.getNonNegativeIntegerTaggedAt(index++, true);
    Asn1Util.checkSequenceEnd(index, size);
    return new RSASSAPSSParams(hashAlgorithm, maskGenAlgorithm, saltLength, trailerField);
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public AlgorithmIdentifier getMaskGenAlgorithm() {
    return maskGenAlgorithm;
  }

  public Asn1Integer getSaltLength() {
    return saltLength;
  }

  public Asn1Integer getTrailerField() {
    return trailerField;
  }

  public int saltLength() {
    return saltLength.intValueExact();
  }

  public int trailerField() {
    return trailerField.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    List<Asn1Encodable> v = new ArrayList<>(4);
    if (!hashAlgorithm.equals(DEFAULT_HASH_ALGORITHM)) {
        v.add(Asn1TaggedObject.newExplicit(0, hashAlgorithm));
    }

    if (!maskGenAlgorithm.equals(DEFAULT_MASK_GEN_FUNCTION)) {
        v.add(Asn1TaggedObject.newExplicit(1, maskGenAlgorithm));
    }

    if (!saltLength.equals(DEFAULT_SALT_LENGTH)) {
        v.add(Asn1TaggedObject.newExplicit(2, saltLength));
    }

    if (!trailerField.equals(DEFAULT_TRAILER_FIELD)) {
        v.add(Asn1TaggedObject.newExplicit(3, trailerField));
    }

    return new Asn1Sequence(v);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    maskGenAlgorithm.toStringWithLineSep(buf, indentLevel, "maskGenAlgorithm", true);
    saltLength.toStringNoLineSep(buf, indentLevel, "saltLength", true);
    trailerField.toStringNoLineSep(buf, indentLevel, "trailerField", true);

    return deleteLastNewLine(buf);
  }

}
