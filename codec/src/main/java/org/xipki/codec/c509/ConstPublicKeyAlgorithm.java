// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.util.HashMap;
import java.util.Map;

/**
 * Figure 19: C509 Public Key Algorithms.
 *
 * <p>The assignments in this class are based on
 * draft-ietf-cose-cbor-encoded-cert-18, Figure 19. Values not listed in
 * Figure 19 are XiPKI-specific additions.
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

  private static final Map<Integer, String> codeToName = new HashMap<>();

  static {
    f(rsaEncryption, "RSA");
    f(x25519,        "X25519");
    f(x448,          "X448");
    f(ed25519,       "Ed25519");
    f(ed448,         "Ed448");
/*
    f(hss_lms,       HSM / LMS");
    f(xmss,          "XMSS");
    f(xmss_mt,       "XMSS^MT");
*/
    // weierstrass curves
    f(ec_secp256r1,       "EC public key on curve secp256r1");
    f(ec_secp384r1,       "EC public key on curve secp384r1");
    f(ec_secp521r1,       "EC public key on curve secp521r1");
    f(ec_sm2p256v1,       "EC public key on curve sm2p256v1");
    f(ec_brainpoolP256r1, "EC public key on curve brainpoolp256r1");
    f(ec_brainpoolP384r1, "EC public key on curve brainpoolp384r1");
    f(ec_brainpoolP512r1, "EC public key on curve brainpoolp512r1");
    f(ec_frp256v1,        "EC public key on curve frp256v1");

    // PQC ML-KEM
    f(ML_KEM_512,    "ML-KEM-512");
    f(ML_KEM_768,    "ML-KEM-768");
    f(ML_KEM_1024,   "ML-KEM-1024");
    // PQC ML-DSA
    f(ML_DSA_44,     "ML-DSA-44");
    f(ML_DSA_65,     "ML-DSA-65");
    f(ML_DSA_87,     "ML-DSA-87");

    // Composite MLDSA
    f(MLDSA44_RSA2048_PSS_SHA256, "MLDSA44-RSA2048-PSS-SHA256");

    f(MLDSA44_RSA2048_PKCS15_SHA256, "MLDSA44-RSA2048-PKCS15-SHA256");

    f(MLDSA44_Ed25519_SHA512, "MLDSA44-Ed25519-SHA512");

    f(MLDSA44_ECDSA_P256_SHA256, "MLDSA44-ECDSA-P256-SHA256");

    f(MLDSA65_RSA3072_PSS_SHA512, "MLDSA65-RSA3072-PSS-SHA512");

    f(MLDSA65_RSA3072_PKCS15_SHA512, "MLDSA65-RSA3072-PKCS15-SHA512");

    f(MLDSA65_RSA4096_PSS_SHA512, "MLDSA65-RSA4096-PSS-SHA512");

    f(MLDSA65_RSA4096_PKCS15_SHA512, "MLDSA65-RSA4096-PKCS15-SHA512");

    f(MLDSA65_ECDSA_P256_SHA512, "MLDSA65-ECDSA-P256-SHA512");

    f(MLDSA65_ECDSA_P384_SHA512, "MLDSA65-ECDSA-P384-SHA512");

    f(MLDSA65_ECDSA_brainpoolP256r1_SHA512, "MLDSA65-ECDSA-brainpoolP256r1-SHA512");

    f(MLDSA65_Ed25519_SHA512, "MLDSA65-Ed25519-SHA512");

    f(MLDSA87_ECDSA_P384_SHA512, "MLDSA87-ECDSA-P384-SHA512");

    f(MLDSA87_ECDSA_brainpoolP384r1_SHA512, "MLDSA87-ECDSA-brainpoolP384r1-SHA512");

    f(MLDSA87_Ed448_SHAKE256, "MLDSA87-Ed448-SHAKE256");

    f(MLDSA87_RSA3072_PSS_SHA512, "MLDSA87-RSA3072-PSS-SHA512");

    f(MLDSA87_RSA4096_PSS_SHA512, "MLDSA87-RSA4096-PSS-SHA512");

    f(MLDSA87_ECDSA_P521_SHA512, "MLDSA87-ECDSA-P521-SHA512");

    // Composite MLKEM
    f(MLKEM768_RSA2048_SHA3_256, "MLKEM768-RSA2048-SHA3-256");

    f(MLKEM768_RSA3072_SHA3_256, "MLKEM768-RSA3072-SHA3-256");

    f(MLKEM768_RSA4096_SHA3_256, "MLKEM768-RSA4096-SHA3-256");

    f(MLKEM768_X25519_SHA3_256, "MLKEM768-X25519-SHA3-256");

    f(MLKEM768_ECDH_P256_SHA3_256, "MLKEM768-ECDH-P256-SHA3-256");

    f(MLKEM768_ECDH_P384_SHA3_256, "MLKEM768-ECDH-P384-SHA3-256");

    f(MLKEM768_ECDH_brainpoolP256r1_SHA3_256, "MLKEM768-ECDH-brainpoolP256r1-SHA3-256");

    f(MLKEM1024_RSA3072_SHA3_256, "MLKEM1024-RSA3072-SHA3-256");

    f(MLKEM1024_ECDH_P384_SHA3_256, "MLKEM1024-ECDH-P384-SHA3-256");

    f(MLKEM1024_ECDH_brainpoolP384r1_SHA3_256, "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256");

    f(MLKEM1024_X448_SHA3_256, "MLKEM1024-X448-SHA3-256");

    f(MLKEM1024_ECDH_P521_SHA3_256, "MLKEM1024-ECDH-P521-SHA3-256");
  }

  private static void f(int code, String name) {
    Const.addEntry(code, name, codeToName);
  }


  public static String getDesc(int code) {
    return getName(code) + " (" + code + ")";
  }

  public static String getName(int code) {
    String name = codeToName.get(code);
    return name == null ? "unknown" : name;
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
