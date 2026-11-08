// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import org.xipki.codec.Hex;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
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
import java.util.HashMap;
import java.util.Map;

/**
 * Base type for CBOR-encoded subject public keys used in C509 structures.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509SubjectPublicKey extends CborEncodable {

  private static final Map<Integer, byte[]> codeX509Map;

  private static final Map<Integer, AlgorithmIdentifier> codeX509ObjMap;

  protected final int algorithm;

  private PublicKey jceKey;

  static {
    codeX509Map = new HashMap<>(30);
    codeX509ObjMap = new HashMap<>(30);

    f(ConstPublicKeyAlgorithm.rsaEncryption, "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00");
    f(ConstPublicKeyAlgorithm.x25519, "30 05 06 03 2B 65 6E");
    f(ConstPublicKeyAlgorithm.x448, "30 05 06 03 2B 65 6F");
    f(ConstPublicKeyAlgorithm.ed25519, "30 05 06 03 2B 65 70");
    f(ConstPublicKeyAlgorithm.ed448, "30 05 06 03 2B 65 71");
    f(ConstPublicKeyAlgorithm.ec_secp256r1,
        "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07");
    f(ConstPublicKeyAlgorithm.ec_secp384r1,
        "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22");
    f(ConstPublicKeyAlgorithm.ec_secp521r1,
        "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23");
    f(ConstPublicKeyAlgorithm.ec_brainpoolP256r1,
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07");
    f(ConstPublicKeyAlgorithm.ec_brainpoolP384r1,
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B");
    f(ConstPublicKeyAlgorithm.ec_brainpoolP512r1,
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0D");
    f(ConstPublicKeyAlgorithm.ec_sm2p256v1,
        "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 81 1C CF 55 01 82 2D");
    f(ConstPublicKeyAlgorithm.ec_frp256v1,
        "30 15 06 07 2A 86 48 CE 3D 02 01 06 0A 2A 81 7A 01 81 5F 65 82 00 01");
  }

  private static void f(int c509, String x509) {
    byte[] encodedX509 = Hex.decode(x509.replace(" ", ""));
    codeX509Map.put(c509, encodedX509);
    try {
      codeX509ObjMap.put(c509, AlgorithmIdentifier.fromEncoded(encodedX509));
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
  }

  public C509SubjectPublicKey(int algorithm) {
    this.algorithm = Args.range(algorithm, "algorithm", -32768, 32767);
  }

  public int algorithm() {
    return algorithm;
  }

  protected AlgorithmIdentifier x509AlgId() {
    return codeX509ObjMap.get(algorithm);
  }

  public byte[] computeSubjectKeyIdentifier() throws CodecException {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA256");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    byte[] hv = md.digest(getEncoded());
    return Arrays.copyOf(hv, 20);
  }

  public static C509SubjectPublicKey decode(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return decode(decoder);
    }
  }

  public static C509SubjectPublicKey decode(CborDecoder decoder) throws CodecException {
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
        return C509RSASubjectPublicKey.decode(decoder);
    }

    return C509BytesSubjectPublicKey.decode(decoder, algId);
  }

  protected abstract void valueToString(StringBuilder buf, int indentLevel);

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "algorithm: ")
        .append(ConstPublicKeyAlgorithm.getDesc(algorithm)).append("\n");
    valueToString(buf, indentLevel);
    return buf;
  }

  public static C509SubjectPublicKey fromSubjectPublicKeyInfo(SubjectPublicKeyInfo x509)
      throws InvalidKeySpecException {
    byte[] encodedAlgId = x509.getAlgorithm().getEncoded();
    Integer c509AlgId = null;
    for (Map.Entry<Integer, byte[]> m : codeX509Map.entrySet()) {
      if (Arrays.equals(encodedAlgId, m.getValue())) {
        c509AlgId = m.getKey();
        break;
      }
    }

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
    switch (algId) {
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
