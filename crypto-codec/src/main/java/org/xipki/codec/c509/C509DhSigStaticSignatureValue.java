// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encodes the signature value {@code DhSigStatic} of the non-signature proof-of-possession
 * algorithms (draft-ietf-cose-cbor-encoded-cert-21, Section 4.2).
 *
 * <pre>
 * DhSigStatic = MessageDigest / DhSigStaticType
 * MessageDigest = bytes
 * DhSigStaticType = [
 *   issuer: Name,
 *   certificateSerialNumber: CertificateSerialNumber,
 *   hashValue: MessageDigest,
 * ]
 * </pre>
 *
 * The issuer {@code Name} is kept in its original encoding, see {@link CborEncodedItem}.
 *
 * @author Lijun Liao (xipki)
 */
public class C509DhSigStaticSignatureValue extends SignatureValue {

  private final byte[] hashValue;

  /**
   * Issuer in its original encoding, or {@code null}.
   */
  private final CborEncodedItem issuer;

  private final BigInteger serialNumber;

  /**
   * Creates the variant {@code MessageDigest}.
   */
  public C509DhSigStaticSignatureValue(byte[] hashValue) {
    this.hashValue = Args.notEmptyBytes(hashValue, "hashValue");
    this.issuer = null;
    this.serialNumber = null;
  }

  /**
   * Creates the variant {@code DhSigStaticType}.
   *
   * @param hashValue the hash value.
   * @param issuer the issuer {@code Name}.
   * @param serialNumber certificate serial number.
   * @throws CodecException if {@code issuer} is CBOR null.
   */
  public C509DhSigStaticSignatureValue(
      byte[] hashValue, CborEncodedItem issuer, BigInteger serialNumber) throws CodecException {
    this.hashValue = Args.notEmptyBytes(hashValue, "hashValue");
    this.issuer = Args.notNull(issuer, "issuer");
    this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    if (issuer.type().isNull()) {
      throw new CodecException("issuer must not be null");
    }
  }

  public byte[] hashValue() {
    return hashValue;
  }

  /**
   * Returns whether this value has the form {@code DhSigStaticType}, namely contains
   * the issuer and serial number.
   */
  public boolean hasIssuerAndSerialNumber() {
    return issuer != null;
  }

  /**
   * Returns the issuer in its original encoding, or {@code null}.
   */
  public CborEncodedItem issuer() {
    return issuer;
  }

  /**
   * Returns the certificate serial number, or {@code null}.
   */
  public BigInteger serialNumber() {
    return serialNumber;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    if (issuer != null) {
      encoder.writeArrayStart(3);
      encoder.writeObject(issuer);
      encoder.writeUnwrappedBiguint(serialNumber);
    }
    encoder.writeByteString(hashValue);
  }

  public static C509DhSigStaticSignatureValue parse(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return read(decoder);
    }
  }

  public static C509DhSigStaticSignatureValue read(CborDecoder decoder) throws CodecException {
    CborType type = decoder.peekType();
    if (type.isByteString()) {
      return new C509DhSigStaticSignatureValue(decoder.readByteString());
    } else {
      decoder.readArrayLength(3);
      CborEncodedItem issuer = decoder.readEncodedItem();
      BigInteger serialNumber = decoder.readUnwrappedBigInt();
      byte[] hashValue = decoder.readByteString();
      return new C509DhSigStaticSignatureValue(hashValue, issuer, serialNumber);
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "Hash value:\n");
    ToStringUtil.appendHex(buf, indentLevel + 1, hashValue);
    if (issuer != null) {
      buf.append("\n");
      ToStringUtil.appendIndent(buf, indentLevel, "Issuer (CBOR):\n");
      ToStringUtil.appendHex(buf, indentLevel + 1, issuer.getEncoded());
      buf.append("\n");
      ToStringUtil.appendIndent(buf, indentLevel, "Serial Number:\n");
      ToStringUtil.appendBigInt(buf, indentLevel + 1, serialNumber);
    }
    return buf;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509DhSigStaticSignatureValue)) {
      return false;
    }

    C509DhSigStaticSignatureValue b = (C509DhSigStaticSignatureValue) obj;
    return Arrays.equals(hashValue, b.hashValue)
        && Objects.equals(issuer, b.issuer)
        && Objects.equals(serialNumber, b.serialNumber);
  }

  @Override
  public int hashCode() {
    return Objects.hash(Arrays.hashCode(hashValue), issuer, serialNumber);
  }

}
