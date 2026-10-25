// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.PrimitiveType;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 * PBKDF2-params ::= SEQUENCE {
 *     salt CHOICE {
 *         specified   OCTET STRING,
 *         otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
 *     },
 *     iterationCount  INTEGER (1..MAX),
 *     keyLength       INTEGER (1..MAX) OPTIONAL,
 *     prf             AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
 *  }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class PBKDF2Params extends Asn1Encodable {

  private static final AlgorithmIdentifier algid_hmacWithSHA1 =
      AlgorithmIdentifier.ofNullParams(CryptoOIDs.id_hmacWithSHA1);

  private final Asn1OctetString specifiedSalt;
  private final Asn1Integer iterationCount;
  private final Asn1Integer keyLength;
  private final AlgorithmIdentifier prf;

  /**
   * Create a PBKDF2Params with the specified salt, iteration count,
   * and algid-hmacWithSHA1 for the prf.
   *
   * @param salt           input salt.
   * @param iterationCount input iteration count.
   */
  public PBKDF2Params(byte[] salt, int iterationCount) {
      this(salt, iterationCount, 0);
  }

  /**
   * Create a PBKDF2Params with the specified salt, iteration count,
   * keyLength, and algid-hmacWithSHA1 for the prf.
   *
   * @param salt           input salt.
   * @param iterationCount input iteration count.
   * @param keyLength      intended key length to be produced.
   */
  public PBKDF2Params(byte[] salt, int iterationCount, int keyLength) {
    this(salt, iterationCount, keyLength, null);
  }

  /**
   * Create a PBKDF2Params with the specified salt, iteration count, and a defined prf.
   *
   * @param salt           input salt.
   * @param iterationCount input iteration count.
   * @param prf            the pseudo-random function to use.
   */
  public PBKDF2Params(byte[] salt, int iterationCount, AlgorithmIdentifier prf) {
    this(salt, iterationCount, 0, prf);
  }

  /**
   * Create a PBKDF2Params with the specified salt, iteration count, keyLength, and a defined prf.
   *
   * @param salt           input salt.
   * @param iterationCount input iteration count.
   * @param keyLength      intended key length to be produced.
   * @param prf            the pseudo-random function to use.
   */
  public PBKDF2Params(byte[] salt, int iterationCount,
                      int keyLength, AlgorithmIdentifier prf) {
    this.specifiedSalt = new Asn1OctetString(Args.notNull(salt, "salt"));
    this.iterationCount = new Asn1Integer(Args.positive(iterationCount, "iterationCount"));
    this.keyLength = (keyLength > 0) ? new Asn1Integer(keyLength) : null;
    this.prf = prf == null ? algid_hmacWithSHA1 : prf;
  }

  public PBKDF2Params(Asn1OctetString specifiedSalt, Asn1Integer iterationCount,
                      Asn1Integer keyLength, AlgorithmIdentifier prf) {
    this.specifiedSalt = Args.notNull(specifiedSalt, "specifiedSalt");
    this.iterationCount = Args.positive(iterationCount, "iterationCount");
    this.keyLength = keyLength;
    this.prf = prf == null ? algid_hmacWithSHA1 : prf;
  }

  public static PBKDF2Params fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    Asn1OctetString specifiedSalt;
    if (seq.hasType(0, PrimitiveType.OCTET_STRING)) {
      specifiedSalt = seq.getOctetStringAt(0);
    } else {
      throw new CodecException("salt.otherSource is not supported");
    }

    Asn1Integer iterationCount = seq.getNonNegativeIntegerAt(1);

    int index = 2;
    Asn1Integer keyLength = seq.notHasType(index, PrimitiveType.INTEGER) ? null
        : seq.getNonNegativeIntegerAt(index++);

    AlgorithmIdentifier prf = seq.notHasType(index, PrimitiveType.SEQUENCE) ? null
        : AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index++));

    Asn1Util.checkSequenceEnd(index, size);

    return new PBKDF2Params(specifiedSalt, iterationCount, keyLength, prf);
  }

  public Asn1OctetString getSalt() {
    return specifiedSalt;
  }

  public Asn1Integer getIterationCount() {
    return iterationCount;
  }

  /**
   * Return the intended length in octets of the derived key.
   *
   * @return length in octets for derived key, if specified.
   */
  public Asn1Integer getKeyLength() {
    return keyLength;
  }

  public AlgorithmIdentifier getPrf() {
    return prf;
  }

  public boolean isDefaultPrf() {
    return algid_hmacWithSHA1.equals(prf);
  }

  public byte[] salt() {
    return specifiedSalt == null ? null : specifiedSalt.getOctets();
  }

  public int iterationCount() {
    return iterationCount.intValueExact();
  }

  public Integer keyLength() {
    return keyLength == null ? null  : keyLength.intValueExact();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    // prf DEFAULT algid-hmacWithSHA1: DER omits the default value.
    AlgorithmIdentifier asn1Prf = prf.equals(algid_hmacWithSHA1) ? null : prf;
    return Asn1Sequence.buildIgnoreNull(specifiedSalt, iterationCount, keyLength, asn1Prf);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    specifiedSalt.toStringWithLineSep(buf, indentLevel, "salt", true);
    iterationCount.toStringNoLineSep(buf, indentLevel, "iterationCount", true);

    if (keyLength != null) {
      keyLength.toStringNoLineSep(buf, indentLevel, "keyLength", true);
    }

    prf.toStringWithLineSep(buf, indentLevel, "prf", true);

    return deleteLastNewLine(buf);
  }

}
