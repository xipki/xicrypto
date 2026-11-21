// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.RSAPublicKey;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.ToStringUtil;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Base type for CBOR-encoded subject public keys used in C509 structures.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509SubjectPublicKey extends CborEncodable {

  protected final int algorithm;

  protected final AlgorithmIdentifier x509AlgId;

  private PublicKey jceKey;

  public C509SubjectPublicKey(int algorithm) {
    this.algorithm = Args.range(algorithm, "algorithm", -32768, 32767);
    this.x509AlgId = ConstPublicKeyAlgorithm.getX509AlgorithmIdentifier(algorithm);
  }

  public int algorithm() {
    return algorithm;
  }

  protected AlgorithmIdentifier x509AlgId() {
    return x509AlgId;
  }

  public byte[] computeSubjectKeyIdentifier() {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    byte[] hv = md.digest(getEncoded());
    return Arrays.copyOf(hv, 20);
  }

  public static C509SubjectPublicKey parse(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return read(decoder);
    }
  }

  public static C509SubjectPublicKey read(CborDecoder decoder) throws CodecException {
    int algId = decoder.readInt();

    switch (algId) {
      case ConstPublicKeyAlgorithm.ec_brainpoolP256r1:
      case ConstPublicKeyAlgorithm.ec_frp256v1:
      case ConstPublicKeyAlgorithm.ec_secp256r1:
      case ConstPublicKeyAlgorithm.ec_sm2p256v1:
      case ConstPublicKeyAlgorithm.ec_brainpoolP384r1:
      case ConstPublicKeyAlgorithm.ec_secp384r1:
      case ConstPublicKeyAlgorithm.ec_brainpoolP512r1:
      case ConstPublicKeyAlgorithm.ec_secp521r1:
        byte[] bytes = decoder.readByteString();
        return new C509ECSubjectPublicKey(algId, bytes);
      case ConstPublicKeyAlgorithm.rsaEncryption:
        return C509RSASubjectPublicKey.read(decoder);
    }

    // the value of an unregistered algorithm may be any CBOR item
    if (!ConstPublicKeyAlgorithm.isRegistered(algId) && !decoder.peekType().isByteString()) {
      return C509RawSubjectPublicKey.read(decoder, algId);
    }

    return C509BytesSubjectPublicKey.read(decoder, algId);
  }

  protected abstract void valueToString(StringBuilder buf, int indentLevel);

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "algorithm: ")
        .append(ConstPublicKeyAlgorithm.describe(algorithm)).append("\n");
    valueToString(buf, indentLevel);
    return buf;
  }

  public static C509SubjectPublicKey fromSubjectPublicKeyInfo(SubjectPublicKeyInfo x509)
      throws InvalidKeySpecException {
    byte[] encodedAlgId = x509.getAlgorithm().getEncoded();
    Integer c509AlgId = ConstPublicKeyAlgorithm.codeForX509AlgId(encodedAlgId);
    if (c509AlgId == null) {
      throw new InvalidKeySpecException(
          "unsupported key algorithm " + x509.getAlgorithm().getAlgorithm());
    }

    if (c509AlgId == ConstPublicKeyAlgorithm.rsaEncryption) {
      RSAPublicKey rsaPk;
      try {
        rsaPk = RSAPublicKey.fromEncoded(x509.subjectPublicKey());
      } catch (CodecException e) {
        throw new InvalidKeySpecException(e.getMessage(), e);
      }
      return new C509RSASubjectPublicKey(rsaPk.modulus(), rsaPk.publicExponent());
    } else if (ConstPublicKeyAlgorithm.isWeierstrass(c509AlgId)) {
      return new C509ECSubjectPublicKey(c509AlgId, x509.subjectPublicKey());
    } else {
      return new C509BytesSubjectPublicKey(c509AlgId, x509.subjectPublicKey());
    }
  }

  public abstract SubjectPublicKeyInfo toX509SubjectPublicKey();

  public synchronized PublicKey publicKey() throws InvalidKeySpecException {
    if (jceKey == null) {
      SubjectPublicKeyInfo x509 = toX509SubjectPublicKey();

      String keyType = getKeyType(algorithm).toUpperCase();
      KeyFactory kf;
      try {
        kf = KeyFactory.getInstance(keyType);
      } catch (NoSuchAlgorithmException e) {
        throw new InvalidKeySpecException(e.getMessage(), e);
      }

      jceKey = kf.generatePublic(new X509EncodedKeySpec(x509.getEncoded()));
    }

    return jceKey;
  }

  private String getKeyType(int algId) throws InvalidKeySpecException {
    if (ConstPublicKeyAlgorithm.isWeierstrass(algId)) {
      return "EC";
    }

    switch (algId) {
      case ConstPublicKeyAlgorithm.rsaEncryption:
        return "RSA";
      case ConstPublicKeyAlgorithm.ed25519:
        return "ED25519";
      case ConstPublicKeyAlgorithm.ed448:
        return "ED448";
      case ConstPublicKeyAlgorithm.x25519:
        return "X25519";
      case ConstPublicKeyAlgorithm.x448:
        return "X448";
/*
      case ConstPublicKeyAlgorithm.xmss:
        return "XMSS";
      case ConstPublicKeyAlgorithm.xmss_mt:
        return "XMSSMT";
      case ConstPublicKeyAlgorithm.hss_lms:
        return "LMS";
  */
      case ConstPublicKeyAlgorithm.ML_DSA_44:
      case ConstPublicKeyAlgorithm.ML_DSA_65:
      case ConstPublicKeyAlgorithm.ML_DSA_87:
        return "ML-DSA";
/*
      case ConstPublicKeyAlgorithm.FALCON_512:
      case ConstPublicKeyAlgorithm.FALCON_1024:
        return "FALCON";
*/
      case ConstPublicKeyAlgorithm.ML_KEM_512:
      case ConstPublicKeyAlgorithm.ML_KEM_768:
      case ConstPublicKeyAlgorithm.ML_KEM_1024:
        return "ML-KEM";
/*
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_128f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_128s:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_192f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_192s:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_256f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHA2_256s:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_128f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_128s:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_192f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_192s:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_256f:
      case ConstPublicKeyAlgorithm.SLH_DSA_SHAKE_256s:
        return "SLH-DSA";
*/
      default:
        throw new InvalidKeySpecException("unknown key algorithm " + algorithm);
    }
  }

}
