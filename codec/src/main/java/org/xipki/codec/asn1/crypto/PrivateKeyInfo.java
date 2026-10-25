// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.*;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.security.PrivateKey;

/**
 * RFC 5958:
 *
 * <pre>
 *  [IMPLICIT TAGS]
 *
 *  OneAsymmetricKey ::= SEQUENCE {
 *      version                   Version,
 *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *      privateKey                PrivateKey,
 *      attributes            [0] Attributes OPTIONAL,
 *      ...,
 *      [[2: publicKey        [1] PublicKey OPTIONAL ]],
 *      ...
 *  }
 *
 *  PrivateKeyInfo ::= OneAsymmetricKey
 *
 *  Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
 *
 *  PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 *                                     { PUBLIC-KEY,
 *                                       { PrivateKeyAlgorithms } }
 *
 *  PrivateKey ::= OCTET STRING
 *                     -- Content varies based on type of key.  The
 *                     -- algorithm identifier dictates the format of
 *                     -- the key.
 *
 *  PublicKey ::= BIT STRING
 *                     -- Content varies based on type of key.  The
 *                     -- algorithm identifier dictates the format of
 *                     -- the key.
 *
 *  Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
 *  </pre>
 * @author Lijun Liao (xipki)
 */
public class PrivateKeyInfo extends Asn1Encodable {

  private final Asn1Integer version;
  private final AlgorithmIdentifier privateKeyAlgorithm;
  private final Asn1OctetString privateKey;
  private final Asn1Set attributes;
  private final Asn1BitString publicKey;

  private static int getVersionValue(Asn1Integer version) {
    int versionValue = version.intValueExact();
    if (versionValue < 0 || versionValue > 1) {
      throw new IllegalArgumentException("invalid version for private key info");
    }
    return versionValue;
  }

  /**
   * Construct a PrivateKeyInfo around a raw encoding.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey byte encoding of the private key, used as a raw encoding.
   */
  public PrivateKeyInfo(AlgorithmIdentifier privateKeyAlgorithm, byte[] privateKey) {
    this(privateKeyAlgorithm, privateKey, null, null);
  }

  /**
   * Construct a PrivateKeyInfo around an ASN.1 structure/primitive.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey the ASN.1 structure/primitive representing the private key.
   */
  public PrivateKeyInfo(AlgorithmIdentifier privateKeyAlgorithm, Asn1Primitive privateKey) {
    this(privateKeyAlgorithm, privateKey, null, null);
  }

  /**
   * Construct a PrivateKeyInfo around an ASN.1 structure/primitive with attributes.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey the ASN.1 structure/primitive representing the private key.
   * @param attributes attributes associated with private key.
   */
  public PrivateKeyInfo(
      AlgorithmIdentifier privateKeyAlgorithm, Asn1Primitive privateKey, Asn1Set attributes) {
    this(privateKeyAlgorithm, privateKey, attributes, null);
  }

  /**
   * Construct a PrivateKeyInfo around an ASN.1 structure/primitive with attributes.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey byte encoding of the private key, used as a raw encoding.
   * @param attributes attributes associated with private key.
   */
  public PrivateKeyInfo(
      AlgorithmIdentifier privateKeyAlgorithm, byte[] privateKey, Asn1Set attributes) {
    this(privateKeyAlgorithm, privateKey, attributes, null);
  }

  /**
   * Construct a PrivateKeyInfo around an ASN.1 structure/primitive with
   * attributes and the public key.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey the ASN.1 structure/primitive representing the private key.
   * @param attributes attributes associated with private key.
   * @param publicKey public key encoding.
   */
  public PrivateKeyInfo(
      AlgorithmIdentifier privateKeyAlgorithm, Asn1Primitive privateKey,
      Asn1Set attributes, byte[] publicKey) {
    this(privateKeyAlgorithm,
        Args.notNull(privateKey, "privateKey").getEncoded(Asn1Encoding.DER),
        attributes, publicKey);
  }

  /**
   * Construct a PrivateKeyInfo around a raw encoding with attributes and the public key.
   *
   * @param privateKeyAlgorithm algorithm identifier for the private key.
   * @param privateKey byte encoding of the private key, used as a raw encoding.
   * @param attributes attributes associated with private key.
   * @param publicKey public key encoding.
   */
  public PrivateKeyInfo(
      AlgorithmIdentifier privateKeyAlgorithm, byte[] privateKey,
      Asn1Set attributes, byte[] publicKey) {
      this.version = publicKey != null ? Asn1Integer.ONE : Asn1Integer.ZERO;
      this.privateKeyAlgorithm = Args.notNull(privateKeyAlgorithm, "privateKeyAlgorithm");
      this.privateKey = new Asn1OctetString(Args.notNull(privateKey, "privateKey"));
      this.attributes = attributes;
      this.publicKey = publicKey == null ? null : new Asn1BitString(publicKey);
  }

  public PrivateKeyInfo(Asn1Integer version, AlgorithmIdentifier privateKeyAlgorithm,
                        Asn1OctetString privateKey, Asn1Set attributes, Asn1BitString publicKey) {
    this.version = Args.notNull(version, "version");
    this.privateKeyAlgorithm = Args.notNull(privateKeyAlgorithm, "privateKeyAlgorithm");
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.attributes = attributes;
    this.publicKey = publicKey;
  }

  public static PrivateKeyInfo fromPrivateKey(PrivateKey privateKey) throws CodecException {
    return fromEncoded(privateKey.getEncoded());
  }

  public static PrivateKeyInfo fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AlgorithmIdentifier algorithmFromPrivateKey(PrivateKey privateKey)
      throws CodecException {
    return algorithmFromAsn1(Asn1Sequence.fromEncoded(privateKey.getEncoded()));
  }

  public static AlgorithmIdentifier algorithmFromEncoded(byte[] encoded) throws CodecException {
    return algorithmFromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AlgorithmIdentifier algorithmFromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", 3);
    return AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
  }

  public static PrivateKeyInfo fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeMin(seq, "seq", 3);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    int versionValue = getVersionValue(version);

    AlgorithmIdentifier privateKeyAlgorithm = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    Asn1OctetString privateKey = seq.getOctetStringAt(2);

    int index = 3;
    Asn1Set attributes = seq.isNotTaggedAt(index, 0) ? null
        : seq.getSetTaggedAt(index++, false);

    Asn1BitString publicKey = null;
    for (int i = index; i < size; i++) {
      if (seq.isTaggedAt(i, 1)) {
        publicKey = seq.getBitStringTaggedAt(i, false);
      }
    }

    if (versionValue < 1 && publicKey != null) {
      throw new CodecException("invalid optional field in private key info");
    }

    return new PrivateKeyInfo(version, privateKeyAlgorithm, privateKey, attributes, publicKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public Asn1Set getAttributes() {
    return attributes;
  }

  public AlgorithmIdentifier getPrivateKeyAlgorithm() {
    return privateKeyAlgorithm;
  }

  public Asn1OctetString getPrivateKey() {
    return new Asn1OctetString(privateKey.getOctets());
  }

  public int getPrivateKeyLength() {
      return privateKey.getOctetsLength();
  }

  public Asn1Primitive parsePrivateKey() throws CodecException {
    return Asn1Util.readAsn1Object(privateKey.getOctets());
  }

  public boolean hasPublicKey() {
    return publicKey != null;
  }

  public Asn1Primitive parsePublicKey() throws CodecException {
    return publicKey == null ? null : Asn1Util.readAsn1Object(publicKey.getAlignedOctets());
  }

  public Asn1BitString getPublicKey() {
    return publicKey;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] privateKey() {
    return privateKey.getOctets();
  }

  public byte[] publicKey() {
    return Asn1Util.fromAsn1(publicKey);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, privateKeyAlgorithm, privateKey,
        (attributes == null) ? null : Asn1TaggedObject.newImplicit(0, attributes),
        (publicKey == null)  ? null : Asn1TaggedObject.newImplicit(1, publicKey));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    privateKeyAlgorithm.toStringWithLineSep(buf, indentLevel, "privateKeyAlgorithm", true);
    // the private key is not printed.
    ToStringUtil.appendSecret(buf, indentLevel, "privateKey", privateKey.getOctetsLength());

    if (attributes != null) {
      attributes.toStringWithLineSep(buf, indentLevel, "attributes", true);
    }

    if (publicKey != null) {
      publicKey.toStringWithLineSep(buf, indentLevel, "publicKey", true);
    }

    return deleteLastNewLine(buf);
  }

}
