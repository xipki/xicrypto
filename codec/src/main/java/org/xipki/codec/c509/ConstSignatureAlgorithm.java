// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import java.util.HashMap;
import java.util.Map;

/**
 * Figure 18: C509 Signature Algorithms.
 *
 * <p>The assignments in this class are based on
 * draft-ietf-cose-cbor-encoded-cert-18, Figure 18. Values not listed in
 * Figure 18 are XiPKI-specific additions.
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstSignatureAlgorithm {

  /** RSASSA-PKCS1-v1_5 with SHA-1, identifier {@code sha1WithRSAEncryption}, OID {@code 1.2.840.113549.1.1.5}. */
  public static final int sha1WithRSAEncryption = -256;

  /** ECDSA with SHA-1, identifier {@code ecdsa-with-SHA1}, OID {@code 1.2.840.10045.4.1}. */
  public static final int ecdsa_with_SHA1 = -255;

  /** ECDSA with SHA-256, identifier {@code ecdsa-with-SHA256}, OID {@code 1.2.840.10045.4.3.2}. */
  public static final int ecdsa_with_SHA256 = 0;

  /** ECDSA with SHA-384, identifier {@code ecdsa-with-SHA384}, OID {@code 1.2.840.10045.4.3.3}. */
  public static final int ecdsa_with_SHA384 = 1;

  /** ECDSA with SHA-512, identifier {@code ecdsa-with-SHA512}, OID {@code 1.2.840.10045.4.3.4}. */
  public static final int ecdsa_with_SHA512 = 2;

  /** ECDSA with SHAKE128, identifier {@code id-ecdsa-with-shake128}, OID {@code 1.3.6.1.5.5.7.6.32}. */
  public static final int ecdsa_with_shake128 = 3;

  /** ECDSA with SHAKE256, identifier {@code id-ecdsa-with-shake256}, OID {@code 1.3.6.1.5.5.7.6.33}. */
  public static final int ecdsa_with_shake256 = 4;

  /** Unsigned, identifier {@code id-alg-unsigned}, OID {@code 1.3.6.1.5.5.7.6.36}. */
  public static final int unsigned = 5;

  /** SM2 with SM3, identifier {@code sm2-with-sm3}, OID {@code 1.2.156.10197.1.501}. */
  public static final int sm2_with_sm3 = 8;

  /** Ed25519, identifiers {@code id-Ed25519}, {@code id-EdDSA25519}, OID {@code 1.3.101.112}. */
  public static final int ed25519 = ConstPublicKeyAlgorithm.ed25519;

  /** Ed448, identifiers {@code id-Ed448}, {@code id-EdDSA448}, OID {@code 1.3.101.113}. */
  public static final int ed448 = ConstPublicKeyAlgorithm.ed448;

  // sa-ecdhPop-sha256-hmac-sha256, 1.3.6.1.5.5.7.6.26
  // Proof-of-possession algorithm, indexed with KDF and MAC,
  // see RFC 6955. Requires recipient public static Diffie-Hellman key.
  public static final int sa_ecdhPop_sha256_hmac_sha256 = 14;

  // sa-ecdhPop-sha384-hmac-sha384, 1.3.6.1.5.5.7.6.27
  // Proof-of-possession algorithm, indexed with KDF and MAC,
  // see RFC 6955. Requires recipient public static Diffie-Hellman key.
  public static final int sa_ecdhPop_sha384_hmac_sha384 = 15;

  // sa-ecdhPop-sha512-hmac-sha512, 1.3.6.1.5.5.7.6.28
  // Proof-of-possession algorithm, indexed with KDF and MAC,
  // see RFC 6955. Requires recipient public static Diffie-Hellman key.
  public static final int sa_ecdhPop_sha512_hmac_sha512 = 16;

  // 1.2.840.113549.1.1.11
  public static final int sha256WithRSAEncryption = 23;

  // 1.2.840.113549.1.1.12
  public static final int sha384WithRSAEncryption = 24;

  // 1.2.840.113549.1.1.13
  public static final int sha512WithRSAEncryption = 25;

  // 1.2.840.113549.1.1.10 with SHA256
  public static final int rsassa_pss_sha256 = 26;

  // 1.2.840.113549.1.1.10 with SHA384
  public static final int rsassa_pss_sha384 = 27;

  // 1.2.840.113549.1.1.10 with SHA512
  public static final int rsassa_pss_sha512 = 28;

  // 1.3.6.1.5.5.7.6.30
  public static final int rsassa_pss_shake128 = 29;

  // 1.3.6.1.5.5.7.6.31
  public static final int rsassa_pss_shake256 = 30;

  /** draft-liao-cose-c509-pq-algorithms */
  public static final int ML_DSA_44   = ConstPublicKeyAlgorithm.ML_DSA_44;

  public static final int ML_DSA_65   = ConstPublicKeyAlgorithm.ML_DSA_65;

  public static final int ML_DSA_87   = ConstPublicKeyAlgorithm.ML_DSA_87;

  public static final int MLDSA44_RSA2048_PSS_SHA256 =
      ConstPublicKeyAlgorithm.MLDSA44_RSA2048_PSS_SHA256;

  public static final int MLDSA44_RSA2048_PKCS15_SHA256 =
      ConstPublicKeyAlgorithm.MLDSA44_RSA2048_PKCS15_SHA256;

  public static final int MLDSA44_Ed25519_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA44_Ed25519_SHA512;

  public static final int MLDSA44_ECDSA_P256_SHA256 =
      ConstPublicKeyAlgorithm.MLDSA44_ECDSA_P256_SHA256;

  public static final int MLDSA65_RSA3072_PSS_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_RSA3072_PSS_SHA512;

  public static final int MLDSA65_RSA3072_PKCS15_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_RSA3072_PKCS15_SHA512;

  public static final int MLDSA65_RSA4096_PSS_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_RSA4096_PSS_SHA512;

  public static final int MLDSA65_RSA4096_PKCS15_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_RSA4096_PKCS15_SHA512;

  public static final int MLDSA65_ECDSA_P256_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_ECDSA_P256_SHA512;

  public static final int MLDSA65_ECDSA_P384_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_ECDSA_P384_SHA512;

  public static final int MLDSA65_ECDSA_brainpoolP256r1_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_ECDSA_brainpoolP256r1_SHA512;

  public static final int MLDSA65_Ed25519_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA65_Ed25519_SHA512;

  public static final int MLDSA87_ECDSA_P384_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA87_ECDSA_P384_SHA512;

  public static final int MLDSA87_ECDSA_brainpoolP384r1_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA87_ECDSA_brainpoolP384r1_SHA512;

  public static final int MLDSA87_Ed448_SHAKE256 =
      ConstPublicKeyAlgorithm.MLDSA87_Ed448_SHAKE256;

  public static final int MLDSA87_RSA3072_PSS_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA87_RSA3072_PSS_SHA512;

  public static final int MLDSA87_RSA4096_PSS_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA87_RSA4096_PSS_SHA512;

  public static final int MLDSA87_ECDSA_P521_SHA512 =
      ConstPublicKeyAlgorithm.MLDSA87_ECDSA_P521_SHA512;

  // private algorithm
  public static final int SIG_dhPop_x25519 = 32765;

  public static final int SIG_dhPop_x448   = 32766;

  public static final int SIG_KEM_GMAC_256 = 32767;

  private static final Map<Integer, String> codeToName = new HashMap<>();

  static {
    f(sha1WithRSAEncryption, "sha1WithRSAEncryption");
    f(ecdsa_with_SHA1,       "ecdsa-with-sha1");
    f(ecdsa_with_SHA256,     "ecdsa-with-sha256");
    f(ecdsa_with_SHA384,     "ecdsa-with-sha384");
    f(ecdsa_with_SHA512,     "ecdsa-with-sha512");
    f(ecdsa_with_shake128,   "ecdsa-with-shake128");
    f(ecdsa_with_shake256,   "ecdsa-with-shake256");
    f(unsigned,              "unsigned");
    f(ed25519,               "Ed25519");
    f(ed448,                 "Ed448");
    f(sa_ecdhPop_sha256_hmac_sha256, "sa-ecdhPop-sha256-hmac-sha256");
    f(sa_ecdhPop_sha384_hmac_sha384, "sa-ecdhPop-sha384-hmac-sha384");
    f(sa_ecdhPop_sha512_hmac_sha512, "sa-ecdhPop-sha512-hmac-sha512");
    f(sha256WithRSAEncryption, "sha256WithRSAEncryption");
    f(sha384WithRSAEncryption, "sha384WithRSAEncryption");
    f(sha512WithRSAEncryption, "sha512WithRSAEncryption");
    f(rsassa_pss_sha256, "rsassa-pss-with-sha256");
    f(rsassa_pss_sha384, "rsassa-pss-with-sha384");
    f(rsassa_pss_sha512, "rsassa-pss-with-sha512");
    f(rsassa_pss_shake128, "rsassa-pss-with-shake128");
    f(rsassa_pss_shake256, "rsassa-pss-with-shake256");
    f(sm2_with_sm3,        "sm2-with-sm3");

    // PQC ML-DSA
    f(ML_DSA_44,          "ML-DSA-44");
    f(ML_DSA_65,          "ML-DSA-65");
    f(ML_DSA_87,          "ML-DSA-87");

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

    // Private Signature Algorithm
    f(SIG_dhPop_x25519,   "SIG-DHPOP-X25519");
    f(SIG_dhPop_x448,     "SIG-DHPOP-X448");
    f(SIG_KEM_GMAC_256,   "SIG-KEM-GMAC-256");
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

  public static boolean isEcdsaSignature(int algId) {
    switch (algId) {
      case ecdsa_with_SHA1:
      case ecdsa_with_SHA256:
      case ecdsa_with_SHA384:
      case ecdsa_with_SHA512:
      case ecdsa_with_shake128:
      case ecdsa_with_shake256:
      case sm2_with_sm3:
        return true;
      default:
        return false;
    }
  }

}
