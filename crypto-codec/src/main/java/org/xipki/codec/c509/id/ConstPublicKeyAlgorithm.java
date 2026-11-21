// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509.id;

import org.xipki.codec.Hex;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.id.CurveOIDs;
import org.xipki.codec.exception.CodecException;

import java.util.HashMap;
import java.util.Map;

/**
 * Figure 19: C509 Public Key Algorithms.
 *
 * <p>The assignments in this class are based on draft-ietf-cose-cbor-encoded-cert-18,
 * Figure 19. Values not listed in Figure 19 are XiPKI-specific additions.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstPublicKeyAlgorithm {

  /** RSA, identifier {@code rsaEncryption}, OID {@code 1.2.840.113549.1.1.1}. */
  public static final int rsaEncryption = 0;

  /** EC Public Key (Weierstrass) with secp256r1. */
  public static final int ec_secp256r1 = 1;

  /** EC Public Key (Weierstrass) with secp384r1. */
  public static final int ec_secp384r1 = 2;

  /** EC Public Key (Weierstrass) with secp521r1. */
  public static final int ec_secp521r1 = 3;

  public static final int ec_sm2p256v1 = 6;

  /** X25519 (Montgomery), identifier {@code id-X25519}, OID {@code 1.3.101.110}. */
  public static final int x25519 = 8;

  /** X448 (Montgomery), identifier {@code id-X448}, OID {@code 1.3.101.111}. */
  public static final int x448 = 9;

  /** Ed25519 (Twisted Edwards), identifiers {@code id-Ed25519}, {@code id-EdDSA25519}. */
  public static final int ed25519 = 12;

  /** Ed448 (Edwards), identifiers {@code id-Ed448}, {@code id-EdDSA448}. */
  public static final int ed448 = 13;

  public static final int ec_brainpoolP256r1 = 24;

  public static final int ec_brainpoolP384r1 = 25;

  public static final int ec_brainpoolP512r1 = 26;

  public static final int ec_frp256v1 = 27;

  /** draft-liao-cose-c509-pq-algorithms */
  public static final int ML_KEM_512  = 14;

  public static final int ML_KEM_768  = 15;

  public static final int ML_KEM_1024 = 16;

  public static final int ML_DSA_44   = 17;

  public static final int ML_DSA_65   = 18;

  public static final int ML_DSA_87   = 19;

  public static final int MLDSA44_RSA2048_PSS_SHA256 = 293;

  public static final int MLDSA44_RSA2048_PKCS15_SHA256 = 294;

  public static final int MLDSA44_Ed25519_SHA512 = 295;

  public static final int MLDSA44_ECDSA_P256_SHA256 = 296;

  public static final int MLDSA65_RSA3072_PSS_SHA512 = 297;

  public static final int MLDSA65_RSA3072_PKCS15_SHA512 = 298;

  public static final int MLDSA65_RSA4096_PSS_SHA512 = 299;

  public static final int MLDSA65_RSA4096_PKCS15_SHA512 = 300;

  public static final int MLDSA65_ECDSA_P256_SHA512 = 301;

  public static final int MLDSA65_ECDSA_P384_SHA512 = 302;

  public static final int MLDSA65_ECDSA_brainpoolP256r1_SHA512 = 303;

  public static final int MLDSA65_Ed25519_SHA512 = 304;

  public static final int MLDSA87_ECDSA_P384_SHA512 = 305;

  public static final int MLDSA87_ECDSA_brainpoolP384r1_SHA512 = 306;

  public static final int MLDSA87_Ed448_SHAKE256 = 307;

  public static final int MLDSA87_RSA3072_PSS_SHA512 = 308;

  public static final int MLDSA87_RSA4096_PSS_SHA512 = 309;

  public static final int MLDSA87_ECDSA_P521_SHA512 = 310;

  public static final int MLKEM768_RSA2048_SHA3_256 = 311;

  public static final int MLKEM768_RSA3072_SHA3_256 = 312;

  public static final int MLKEM768_RSA4096_SHA3_256 = 313;

  public static final int MLKEM768_X25519_SHA3_256 = 314;

  public static final int MLKEM768_ECDH_P256_SHA3_256 = 315;

  public static final int MLKEM768_ECDH_P384_SHA3_256 = 316;

  public static final int MLKEM768_ECDH_brainpoolP256r1_SHA3_256 = 317;

  public static final int MLKEM1024_RSA3072_SHA3_256 = 318;

  public static final int MLKEM1024_ECDH_P384_SHA3_256 = 319;

  public static final int MLKEM1024_ECDH_brainpoolP384r1_SHA3_256 = 320;

  public static final int MLKEM1024_X448_SHA3_256 = 321;

  public static final int MLKEM1024_ECDH_P521_SHA3_256 = 322;

  private static final Map<Integer, ConstPublicKeyAlgorithm> codeToAlgo = new HashMap<>();

  private static final Map<String, Integer> x509AlgIdToCode = new HashMap<>();

  static {
    f(rsaEncryption, "RSA", "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00");
    f(x25519,        "X25519",  "30 05 06 03 2B 65 6E");
    f(x448,          "X448",    "30 05 06 03 2B 65 6F");
    f(ed25519,       "Ed25519", "30 05 06 03 2B 65 70");
    f(ed448,         "Ed448",   "30 05 06 03 2B 65 71");
/*
    f(hss_lms, "HSS / LMS", "30 0D 06 0B 2A 86 48 86 F7 0D 01 09 10 03 11");
    f(xmss,    "XMSS",      "30 0A 06 08 2B 06 01 05 05 07 06 22");
    f(xmss_mt, "XMSS^MT",   "30 0A 06 08 2B 06 01 05 05 07 06 23");
*/
    // weierstrass curves
    f(ec_secp256r1, "EC public key on curve secp256r1",
        "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07");
    f(ec_secp384r1, "EC public key on curve secp384r1",
        "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22");
    f(ec_secp521r1, "EC public key on curve secp521r1",
        "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23");
    f(ec_sm2p256v1, "EC public key on curve sm2p256v1",
        "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 81 1C CF 55 01 82 2D");
    f(ec_brainpoolP256r1, "EC public key on curve brainpoolp256r1",
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07");
    f(ec_brainpoolP384r1, "EC public key on curve brainpoolp384r1",
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B");
    f(ec_brainpoolP512r1, "EC public key on curve brainpoolp512r1",
        "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0D");
    f(ec_frp256v1, "EC public key on curve frp256v1",
        "30 15 06 07 2A 86 48 CE 3D 02 01 06 0A 2A 81 7A 01 81 5F 65 82 00 01");

    // PQC ML-KEM
    f(ML_KEM_512,  "ML-KEM-512",  "30 0B 06 09 60 86 48 01 65 03 04 04 01");
    f(ML_KEM_768,  "ML-KEM-768",  "30 0B 06 09 60 86 48 01 65 03 04 04 02");
    f(ML_KEM_1024, "ML-KEM-1024", "30 0B 06 09 60 86 48 01 65 03 04 04 03");
    // PQC ML-DSA
    f(ML_DSA_44,   "ML-DSA-44",   "30 0B 06 09 60 86 48 01 65 03 04 03 11");
    f(ML_DSA_65,   "ML-DSA-65",   "30 0B 06 09 60 86 48 01 65 03 04 03 12");
    f(ML_DSA_87,   "ML-DSA-87",   "30 0B 06 09 60 86 48 01 65 03 04 03 13");

    // Composite MLDSA
    f(MLDSA44_RSA2048_PSS_SHA256, "MLDSA44-RSA2048-PSS-SHA256",
        "30 0A 06 08 2B 06 01 05 05 07 06 25");
    f(MLDSA44_RSA2048_PKCS15_SHA256, "MLDSA44-RSA2048-PKCS15-SHA256",
        "30 0A 06 08 2B 06 01 05 05 07 06 26");
    f(MLDSA44_Ed25519_SHA512, "MLDSA44-Ed25519-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 27");
    f(MLDSA44_ECDSA_P256_SHA256, "MLDSA44-ECDSA-P256-SHA256",
        "30 0A 06 08 2B 06 01 05 05 07 06 28");
    f(MLDSA65_RSA3072_PSS_SHA512, "MLDSA65-RSA3072-PSS-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 29");
    f(MLDSA65_RSA3072_PKCS15_SHA512, "MLDSA65-RSA3072-PKCS15-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2A");
    f(MLDSA65_RSA4096_PSS_SHA512, "MLDSA65-RSA4096-PSS-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2B");
    f(MLDSA65_RSA4096_PKCS15_SHA512, "MLDSA65-RSA4096-PKCS15-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2C");
    f(MLDSA65_ECDSA_P256_SHA512, "MLDSA65-ECDSA-P256-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2D");
    f(MLDSA65_ECDSA_P384_SHA512, "MLDSA65-ECDSA-P384-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2E");
    f(MLDSA65_ECDSA_brainpoolP256r1_SHA512, "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 2F");
    f(MLDSA65_Ed25519_SHA512, "MLDSA65-Ed25519-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 30");
    f(MLDSA87_ECDSA_P384_SHA512, "MLDSA87-ECDSA-P384-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 31");
    f(MLDSA87_ECDSA_brainpoolP384r1_SHA512, "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 32");
    f(MLDSA87_Ed448_SHAKE256, "MLDSA87-Ed448-SHAKE256",
        "30 0A 06 08 2B 06 01 05 05 07 06 33");
    f(MLDSA87_RSA3072_PSS_SHA512, "MLDSA87-RSA3072-PSS-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 34");
    f(MLDSA87_RSA4096_PSS_SHA512, "MLDSA87-RSA4096-PSS-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 35");
    f(MLDSA87_ECDSA_P521_SHA512, "MLDSA87-ECDSA-P521-SHA512",
        "30 0A 06 08 2B 06 01 05 05 07 06 36");

    // Composite MLKEM
    f(MLKEM768_RSA2048_SHA3_256, "MLKEM768-RSA2048-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 37");
    f(MLKEM768_RSA3072_SHA3_256, "MLKEM768-RSA3072-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 38");
    f(MLKEM768_RSA4096_SHA3_256, "MLKEM768-RSA4096-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 39");
    f(MLKEM768_X25519_SHA3_256, "MLKEM768-X25519-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3A");
    f(MLKEM768_ECDH_P256_SHA3_256, "MLKEM768-ECDH-P256-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3B");
    f(MLKEM768_ECDH_P384_SHA3_256, "MLKEM768-ECDH-P384-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3C");
    f(MLKEM768_ECDH_brainpoolP256r1_SHA3_256, "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3D");
    f(MLKEM1024_RSA3072_SHA3_256, "MLKEM1024-RSA3072-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3E");
    f(MLKEM1024_ECDH_P384_SHA3_256, "MLKEM1024-ECDH-P384-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 3F");
    f(MLKEM1024_ECDH_brainpoolP384r1_SHA3_256, "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 40");
    f(MLKEM1024_X448_SHA3_256, "MLKEM1024-X448-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 41");
    f(MLKEM1024_ECDH_P521_SHA3_256, "MLKEM1024-ECDH-P521-SHA3-256",
        "30 0A 06 08 2B 06 01 05 05 07 06 42");
  }

  private final String name;

  private final byte[] x509AlgId;

  private final AlgorithmIdentifier x509AlgorithmIdentifier;

  private ConstPublicKeyAlgorithm(String name, byte[] x509AlgId) {
    this.name = name;
    this.x509AlgId = x509AlgId;
    if (x509AlgId == null) {
      this.x509AlgorithmIdentifier = null;
    } else {
      try {
        this.x509AlgorithmIdentifier = AlgorithmIdentifier.fromEncoded(x509AlgId);
      } catch (CodecException e) {
        throw new IllegalArgumentException("invalid x509AlgId for " + name, e);
      }
    }
  }

  private static final Map<String, Integer> ALIASES =
      Const.buildAliases(ConstPublicKeyAlgorithm.class, registeredNames());

  private static Map<Integer, String> registeredNames() {
    Map<Integer, String> names = new HashMap<>();
    for (Map.Entry<Integer, ConstPublicKeyAlgorithm> entry : codeToAlgo.entrySet()) {
      names.put(entry.getKey(), entry.getValue().name);
    }
    return names;
  }

  /**
   * Returns the code for the name of the constant in this class (e.g. {@code ec_secp256r1}, also
   * written as {@code ecsecp256r1} or {@code ec-secp256r1}; case, spaces, dashes and underscores are
   * ignored), the registered name, or the decimal code.
   *
   * @param nameOrCode the name or the decimal code.
   * @return the code, or {@code null} if the name is unknown.
   */
  public static Integer code(String nameOrCode) {
    return Const.codeOf(nameOrCode, ALIASES);
  }

  private static void f(int code, String name, String x509AlgIdHex) {
    if (codeToAlgo.containsKey(code)) {
      throw new IllegalArgumentException("duplicated code " + code);
    }

    byte[] x509AlgId = Hex.decode(x509AlgIdHex.replace(" ", ""));
    codeToAlgo.put(code, new ConstPublicKeyAlgorithm(name, x509AlgId));
    Integer prev = x509AlgIdToCode.put(Hex.encode(x509AlgId), code);
    if (prev != null) {
      throw new IllegalArgumentException(
          "duplicated x509AlgId for codes " + prev + " and " + code);
    }
  }

  /**
   * Whether the code is registered here, i.e. has a known X.509 AlgorithmIdentifier.
   */
  public static boolean isRegistered(int code) {
    return codeToAlgo.containsKey(code);
  }

  public static String describe(int code) {
    return name(code) + " (" + code + ")";
  }

  public static String name(int code) {
    ConstPublicKeyAlgorithm algo = codeToAlgo.get(code);
    return algo == null ? "unknown" : algo.name;
  }

  /**
   * Returns the DER-encoded X.509 AlgorithmIdentifier of the given C509 public key algorithm.
   *
   * @param code the C509 public key algorithm code.
   * @return the DER-encoded AlgorithmIdentifier, or {@code null} if the code is unknown.
   */
  public static byte[] getX509AlgId(int code) {
    ConstPublicKeyAlgorithm algo = codeToAlgo.get(code);
    return algo == null ? null : algo.x509AlgId.clone();
  }

  /**
   * Returns the X.509 AlgorithmIdentifier of the given C509 public key algorithm.
   *
   * @param code the C509 public key algorithm code.
   * @return the AlgorithmIdentifier, or {@code null} if the code is unknown.
   */
  public static AlgorithmIdentifier getX509AlgorithmIdentifier(int code) {
    ConstPublicKeyAlgorithm algo = codeToAlgo.get(code);
    return algo == null ? null : algo.x509AlgorithmIdentifier;
  }

  /**
   * Returns the C509 public key algorithm code for the given DER-encoded X.509 AlgorithmIdentifier.
   *
   * @param x509AlgId the DER-encoded AlgorithmIdentifier.
   * @return the C509 public key algorithm code, or {@code null} if there is no matching algorithm.
   */
  public static Integer codeForX509AlgId(byte[] x509AlgId) {
    return x509AlgId == null ? null : x509AlgIdToCode.get(Hex.encode(x509AlgId));
  }

  public static boolean isWeierstrass(long code) {
    return code == ec_secp256r1 || code == ec_secp384r1 || code == ec_secp521r1
        || code == ec_brainpoolP256r1 || code == ec_brainpoolP384r1 || code == ec_brainpoolP512r1
        || code == ec_sm2p256v1 || code == ec_frp256v1;
  }

  public static int codeForCurveOid(Asn1Oid curve) {
    if (CurveOIDs.secp256r1.equals(curve)) {
      return ec_secp256r1;
    } else if (CurveOIDs.secp384r1.equals(curve)) {
      return ec_secp384r1;
    } else if (CurveOIDs.secp521r1.equals(curve)) {
      return ec_secp521r1;
    } else if (CurveOIDs.brainpoolP256r1.equals(curve)) {
      return ec_brainpoolP256r1;
    } else if (CurveOIDs.brainpoolP384r1.equals(curve)) {
      return ec_brainpoolP384r1;
    } else if (CurveOIDs.brainpoolP512r1.equals(curve)) {
      return ec_brainpoolP512r1;
    } else if (CurveOIDs.sm2p256v1.equals(curve)) {
      return ec_sm2p256v1;
    } else if (CurveOIDs.frp256v1.equals(curve)) {
      return ec_frp256v1;
    } else {
      throw new IllegalArgumentException("unsupported EC curve " + curve);
    }
  }

  public static Asn1Oid curveOidForCode(int code) {
    switch (code) {
      case ec_secp256r1:
        return CurveOIDs.secp256r1;
      case ec_secp384r1:
        return CurveOIDs.secp384r1;
      case ec_secp521r1:
        return CurveOIDs.secp521r1;
      case ec_brainpoolP256r1:
        return CurveOIDs.brainpoolP256r1;
      case ec_brainpoolP384r1:
        return CurveOIDs.brainpoolP384r1;
      case ec_brainpoolP512r1:
        return CurveOIDs.brainpoolP512r1;
      case ec_sm2p256v1:
        return CurveOIDs.sm2p256v1;
      case ec_frp256v1:
        return CurveOIDs.frp256v1;
      default:
        throw new IllegalStateException("unsupported code " + code);
    }
  }

}
