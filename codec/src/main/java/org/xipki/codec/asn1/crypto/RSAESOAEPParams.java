// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
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
 *  DEFINITIONS EXPLICIT TAGS ::=
 *
 *  RSAES-OAEP-params ::= SEQUENCE {
 *     hashAlgorithm      [0] OAEP-PSSDigestAlgorithms DEFAULT sha1,
 *     maskGenAlgorithm   [1] PKCS1MGFAlgorithms       DEFAULT mgf1SHA1,
 *     pSourceAlgorithm   [2] PKCS1PSourceAlgorithms   DEFAULT pSpecifiedEmpty
 *   }
 *
 *   OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *     { OID id-sha1 PARAMETERS NULL   }|
 *     { OID id-sha256 PARAMETERS NULL }|
 *     { OID id-sha384 PARAMETERS NULL }|
 *     { OID id-sha512 PARAMETERS NULL },
 *     ...  -- Allows for future expansion --
 *   }
 *   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *     { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
 *    ...  -- Allows for future expansion --
 *   }
 *   PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *     { OID id-pSpecified PARAMETERS OCTET STRING },
 *     ...  -- Allows for future expansion --
 *  }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class RSAESOAEPParams extends Asn1Encodable {

  private final AlgorithmIdentifier hashAlgorithm;
  private final AlgorithmIdentifier maskGenAlgorithm;
  private final AlgorithmIdentifier pSourceAlgorithm;

  public final static AlgorithmIdentifier DEFAULT_HASH_ALGORITHM =
      AlgorithmIdentifier.ofNullParams(CryptoOIDs.idSHA1);

  public final static AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION =
      RSASSAPSSParams.DEFAULT_MASK_GEN_FUNCTION;

  public final static AlgorithmIdentifier DEFAULT_P_SOURCE_ALGORITHM =
      new AlgorithmIdentifier(CryptoOIDs.id_pSpecified,
          new Asn1OctetString(new byte[0]));

  /**
   * The default version
   */
  public RSAESOAEPParams() {
    this.hashAlgorithm = DEFAULT_HASH_ALGORITHM;
    this.maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
    this.pSourceAlgorithm = DEFAULT_P_SOURCE_ALGORITHM;
  }

  public RSAESOAEPParams(AlgorithmIdentifier hashAlgorithm, AlgorithmIdentifier maskGenAlgorithm,
                         AlgorithmIdentifier pSourceAlgorithm) {
      this.hashAlgorithm = Args.notNull(hashAlgorithm, "hashAlgorithm");
      this.maskGenAlgorithm = Args.notNull(maskGenAlgorithm, "maskGenAlgorithm");
      this.pSourceAlgorithm = Args.notNull(pSourceAlgorithm, "pSourceAlgorithm");
  }

  public static RSAESOAEPParams fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 0, 3);
    int index = 0;

    AlgorithmIdentifier hashAlgorithm = seq.isNotTaggedAt(index, 0)
        ? DEFAULT_HASH_ALGORITHM
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    AlgorithmIdentifier maskGenAlgorithm = seq.isNotTaggedAt(index, 1)
        ? DEFAULT_MASK_GEN_FUNCTION
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    AlgorithmIdentifier pSourceAlgorithm = seq.isNotTaggedAt(index, 2)
        ? DEFAULT_P_SOURCE_ALGORITHM
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceTaggedAt(index++, true));

    Asn1Util.checkSequenceEnd(index,size);
    return new RSAESOAEPParams(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);
  }

  public AlgorithmIdentifier getHashAlgorithm() {
    return hashAlgorithm;
  }

  public AlgorithmIdentifier getMaskGenAlgorithm() {
    return maskGenAlgorithm;
  }

  public AlgorithmIdentifier getPSourceAlgorithm() {
    return pSourceAlgorithm;
  }

  public RSAESOAEPParams withDefaultPSource() {
    return DEFAULT_P_SOURCE_ALGORITHM.equals(pSourceAlgorithm) ? this
        : new RSAESOAEPParams(hashAlgorithm, maskGenAlgorithm, DEFAULT_P_SOURCE_ALGORITHM);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    List<Asn1Encodable> v = new ArrayList<>(4);
    if (hashAlgorithm != null && !hashAlgorithm.equals(DEFAULT_HASH_ALGORITHM)) {
        v.add(Asn1TaggedObject.newExplicit(0, hashAlgorithm));
    }

    if (maskGenAlgorithm != null && !maskGenAlgorithm.equals(DEFAULT_MASK_GEN_FUNCTION)) {
        v.add(Asn1TaggedObject.newExplicit(1, maskGenAlgorithm));
    }

    if (pSourceAlgorithm != null && !pSourceAlgorithm.equals(DEFAULT_P_SOURCE_ALGORITHM)) {
        v.add(Asn1TaggedObject.newExplicit(2, pSourceAlgorithm));
    }

    return new Asn1Sequence(v);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (hashAlgorithm != null) {
      hashAlgorithm.toStringWithLineSep(buf, indentLevel, "hashAlgorithm", true);
    }

    if (maskGenAlgorithm != null) {
      maskGenAlgorithm.toStringWithLineSep(buf, indentLevel, "maskGenAlgorithm", true);
    }

    if (pSourceAlgorithm != null) {
      pSourceAlgorithm.toStringWithLineSep(buf, indentLevel, "pSourceAlgorithm", true);
    }

    return deleteLastNewLine(buf);
  }

}
