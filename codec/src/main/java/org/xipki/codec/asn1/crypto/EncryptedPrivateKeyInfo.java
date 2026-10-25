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
 * RFC 5208 (PKCS#8):
 * <pre>
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *     encryptionAlgorithm  AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
 *     encryptedData        EncryptedData
 * }
 *
 * EncryptedData ::= OCTET STRING
 *
 * KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
 *          ... -- For local profiles
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class EncryptedPrivateKeyInfo extends Asn1Encodable {

  private final AlgorithmIdentifier encryptionAlgorithm;
  private final Asn1OctetString encryptedData;

  public static EncryptedPrivateKeyInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier algId = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    Asn1OctetString data = seq.getOctetStringAt(1);
    return new EncryptedPrivateKeyInfo(algId, data);
  }

  public EncryptedPrivateKeyInfo(AlgorithmIdentifier algId, byte[] data) {
    this.encryptionAlgorithm = Args.notNull(algId, "algId");
    this.encryptedData = new Asn1OctetString(Args.notNull(data, "data"));
  }

  public EncryptedPrivateKeyInfo(AlgorithmIdentifier algId, Asn1OctetString data) {
    this.encryptionAlgorithm = Args.notNull(algId, "algId");
    this.encryptedData = Args.notNull(data, "data");
  }

  public AlgorithmIdentifier getEncryptionAlgorithm() {
    return encryptionAlgorithm;
  }

  public Asn1OctetString getEncryptedData() {
    return encryptedData;
  }

  public byte[] encryptedData() {
    return encryptedData.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(encryptionAlgorithm, encryptedData);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    encryptionAlgorithm.toStringWithLineSep(buf, indentLevel, "encryptionAlgorithm", true);
    encryptedData.toStringWithLineSep(buf, indentLevel, "encryptedData", true);

    return deleteLastNewLine(buf);
  }

}
