// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.util.ToStringUtil;

import java.util.Objects;
import java.util.Arrays;

/**
 * Uncompressed: 0x04 || x || y
 * Compressed:   0x02 / 0x03 || x
 * @author Lijun Liao (xipki)
 */
public class C509ECSubjectPublicKey extends C509SubjectPublicKey {

  public static final byte UNCOMPRESSED = 4;

  public static final byte COMPRESSED_EVEN_Y = 2;

  public static final byte COMPRESSED_ODD_Y = 3;

  private final byte[] encodedECPoint;

  public C509ECSubjectPublicKey(int algId, byte[] encodedECPoint) {
    super(algId);

    if (encodedECPoint == null || encodedECPoint.length < 20) {
      throw new IllegalArgumentException("invalid encodedECPoint");
    }

    byte encodingType = encodedECPoint[0];
    if (encodingType == UNCOMPRESSED) {
      if (encodedECPoint.length % 2 != 1) {
        // length shall be odd
        throw new IllegalArgumentException("encodedECPoint: invalid length");
      }
    } else if (!(encodingType == COMPRESSED_EVEN_Y || encodingType == COMPRESSED_ODD_Y)) {
      throw new IllegalArgumentException(
          "encodedECPoint: invalid encoding type " + (0xFF & encodingType));
    }

    int fieldLen = 0;
    switch (algId) {
      case ConstPublicKeyAlgorithm.ec_brainpoolP256r1:
      case ConstPublicKeyAlgorithm.ec_frp256v1:
      case ConstPublicKeyAlgorithm.ec_secp256r1:
      case ConstPublicKeyAlgorithm.ec_sm2p256v1:
        fieldLen = 32;
        break;
      case ConstPublicKeyAlgorithm.ec_brainpoolP384r1:
      case ConstPublicKeyAlgorithm.ec_secp384r1:
        fieldLen = 48;
        break;
      case ConstPublicKeyAlgorithm.ec_brainpoolP512r1:
        fieldLen = 64;
        break;
      case ConstPublicKeyAlgorithm.ec_secp521r1:
        fieldLen = 66;
        break;
    }

    if (fieldLen != 0) {
      int expectedLen = (encodingType == UNCOMPRESSED) ? 1 + 2 * fieldLen : 1 + fieldLen;
      if (encodedECPoint.length != expectedLen) {
        // length shall be odd
        throw new IllegalArgumentException("encodedECPoint: invalid length");
      }
    }

    this.encodedECPoint = encodedECPoint;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeInt(algorithm);
    encoder.writeByteString(encodedECPoint);
  }

  public static C509ECSubjectPublicKey read(CborDecoder decoder, int algorithm)
      throws CodecException {
    return new C509ECSubjectPublicKey(algorithm, decoder.readByteString());
  }

  public byte[] publicKeyData() {
    return encodedECPoint;
  }

  public byte pointEncoding() {
    return encodedECPoint[0];
  }

  @Override
  public SubjectPublicKeyInfo toX509SubjectPublicKey() {
    return new SubjectPublicKeyInfo(x509AlgId(), encodedECPoint);
  }

  @Override
  public void valueToString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "EC public key\n");
    ToStringUtil.appendHex(buf, indentLevel + 1, encodedECPoint);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509ECSubjectPublicKey)) {
      return false;
    }

    C509ECSubjectPublicKey b = (C509ECSubjectPublicKey) obj;

    return algorithm == b.algorithm && Arrays.equals(encodedECPoint, b.encodedECPoint);
  }
  @Override
  public int hashCode() {
    return Objects.hash(algorithm, Arrays.hashCode(encodedECPoint));
  }

}
