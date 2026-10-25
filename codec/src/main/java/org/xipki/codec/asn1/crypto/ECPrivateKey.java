// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1BitString;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;

/**
 * The elliptic curve private key object defined in RFC 5915:
 * <pre>
 *   DEFINITIONS EXPLICIT TAGS ::=
 *
 *   ECPrivateKey ::= SEQUENCE {
 *      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *      privateKey     OCTET STRING,
 *      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *      publicKey  [1] BIT STRING OPTIONAL
 *   }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class ECPrivateKey extends Asn1Encodable {

  private final Asn1Integer version;

  private final Asn1OctetString privateKey;

  private final ECParameters parameters;

  private final Asn1BitString publicKey;

  public static ECPrivateKey fromPrivateKey(java.security.interfaces.ECPrivateKey privateKey)
      throws CodecException {
    return fromEncoded(privateKey.getEncoded());
  }

  public static ECPrivateKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static ECPrivateKey fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 2, 4);
    Asn1Integer version = seq.getNonNegativeIntegerAt(0);
    Asn1OctetString privateKey = seq.getOctetStringAt(1);

    int index = 2;
    ECParameters parameters = seq.isNotTaggedAt(index, 0) ? null
        : ECParameters.fromAsn1(seq.getObjectOfExplicitTaggedAt(index++));

    Asn1BitString publicKey = seq.isNotTaggedAt(index, 1) ? null
        : seq.getBitStringTaggedAt(index++, true);

    Asn1Util.checkSequenceEnd(index, size);
    return new ECPrivateKey(version, privateKey, parameters, publicKey);
  }

  public ECPrivateKey(Asn1Integer version, Asn1OctetString privateKey,
                      ECParameters parameters, Asn1BitString publicKey) {
    this.version = Args.notNull(version, "version");
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.parameters = parameters;
    this.publicKey = publicKey;
  }

  public ECPrivateKey(int orderBitLength, BigInteger key) {
    this(orderBitLength, key, null, null);
  }

  public ECPrivateKey(int orderBitLength, BigInteger key, ECParameters parameters) {
    this(orderBitLength, key, null, parameters);
  }

  public ECPrivateKey(int orderBitLength, BigInteger key,
                      byte[] publicKey, ECParameters parameters) {
    byte[] bytes = BigIntegers.asUnsignedByteArray((orderBitLength + 7) / 8, key);
    this.version = Asn1Integer.ONE;
    this.privateKey = new Asn1OctetString(bytes);
    this.parameters = parameters;
    this.publicKey = (publicKey == null) ? null : new Asn1BitString(publicKey);
  }

  public Asn1Integer getVersion() {
    return version;
  }

  public Asn1OctetString getPrivateKey() {
    return privateKey;
  }

  public Asn1BitString getPublicKey() {
    return publicKey;
  }

  public ECParameters getParameters() {
    return parameters;
  }

  public int version() {
    return version.intValueExact();
  }

  public byte[] privateKey() {
    return privateKey.getOctets();
  }

  public BigInteger bnPrivateKey() {
    return new BigInteger(1, privateKey.getOctets());
  }

  public byte[] publicKey() {
    return publicKey == null ? null : publicKey.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(version, privateKey,
        parameters == null ? null : Asn1TaggedObject.newExplicit(0, parameters),
        publicKey == null ? null : Asn1TaggedObject.newExplicit(1, publicKey));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    version.toStringNoLineSep(buf, indentLevel, "version", true);
    // the private key is not printed.
    ToStringUtil.appendSecret(buf, indentLevel, "privateKey", privateKey.getOctetsLength());

    if (parameters != null) {
      parameters.toStringNoLineSep(buf, indentLevel, "parameters", true);
    }

    if (publicKey != null) {
      publicKey.toStringWithLineSep(buf, indentLevel, "publicKey", true);
    }

    return deleteLastNewLine(buf);
  }

}
