// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * RFC 7914 scrypt parameters.
 *
 * <pre>
 * scrypt-params ::= SEQUENCE {
 *     salt                      OCTET STRING,
 *     costParameter             INTEGER (1..MAX),
 *     blockSize                 INTEGER (1..MAX),
 *     parallelizationParameter  INTEGER (1..MAX),
 *     keyLength                 INTEGER (1..MAX) OPTIONAL
 * }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class ScryptParams extends Asn1Encodable {

  private final Asn1OctetString salt;
  private final Asn1Integer costParameter;
  private final Asn1Integer blockSize;
  private final Asn1Integer parallelizationParameter;
  private final Asn1Integer keyLength;

  public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter) {
    this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize),
        BigInteger.valueOf(parallelizationParameter), null);
  }

  public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter,
                      int keyLength) {
    this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize),
        BigInteger.valueOf(parallelizationParameter), BigInteger.valueOf(keyLength));
  }

  public ScryptParams(byte[] salt, BigInteger costParameter, BigInteger blockSize,
                      BigInteger parallelizationParameter, BigInteger keyLength) {
    this.salt = new Asn1OctetString(Args.notNull(salt, "salt"));
    this.costParameter = new Asn1Integer(Args.notNull(costParameter, "costParameter"));
    this.blockSize = new Asn1Integer(Args.notNull(blockSize, "blockSize"));
    this.parallelizationParameter = new Asn1Integer(
        Args.notNull(parallelizationParameter, "parallelizationParameter"));
    this.keyLength = keyLength == null ? null : new Asn1Integer(keyLength);
  }

  public ScryptParams(Asn1OctetString salt, Asn1Integer costParameter, Asn1Integer blockSize,
                      Asn1Integer parallelizationParameter, Asn1Integer keyLength) {
    this.salt = Args.notNull(salt, "salt");
    this.costParameter = Args.notNull(costParameter, "costParameter");
    this.blockSize = Args.notNull(blockSize, "blockSize");
    this.parallelizationParameter = Args.notNull(parallelizationParameter,
        "parallelizationParameter");
    this.keyLength = keyLength;
  }

  public static ScryptParams fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 4, 5);
    Asn1OctetString salt = seq.getOctetStringAt(0);
    Asn1Integer costParameter = seq.getNonNegativeIntegerAt(1);
    Asn1Integer blockSize = seq.getNonNegativeIntegerAt(2);
    Asn1Integer parallelizationParameter = seq.getNonNegativeIntegerAt(3);
    Asn1Integer keyLength = (size == 4) ? null : seq.getNonNegativeIntegerAt(4);
    return new ScryptParams(salt, costParameter, blockSize, parallelizationParameter, keyLength);
  }

  public Asn1OctetString getSalt() {
    return salt;
  }

  public Asn1Integer getCostParameter() {
    return costParameter;
  }

  public Asn1Integer getBlockSize() {
    return blockSize;
  }

  public Asn1Integer getParallelizationParameter() {
    return parallelizationParameter;
  }

  public Asn1Integer getKeyLength() {
    return keyLength;
  }

  public byte[] salt() {
    return salt.getOctets();
  }

  public int costParameter() {
    return costParameter.intValueExact();
  }

  public int blockSize() {
    return blockSize.intValueExact();
  }

  public int parallelizationParameter() {
    return parallelizationParameter.intValueExact();
  }

  public Integer keyLength() {
    return Asn1Util.fromAsn1Int(keyLength);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(salt, costParameter,
        blockSize, parallelizationParameter, keyLength);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    salt.toStringWithLineSep(buf, indentLevel, "salt", true);
    costParameter.toStringNoLineSep(buf, indentLevel, "costParameter", true);
    blockSize.toStringNoLineSep(buf, indentLevel, "blockSize", true);
    parallelizationParameter.toStringNoLineSep(buf, indentLevel, "parallelizationParameter", true);

    if (keyLength != null) {
      keyLength.toStringNoLineSep(buf, indentLevel, "keyLength", true);
    }

    return deleteLastNewLine(buf);
  }

}
