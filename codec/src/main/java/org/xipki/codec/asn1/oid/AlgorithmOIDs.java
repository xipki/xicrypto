// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * Cryptographic Algorithm OIDs.
 *
 * @author Lijun Liao (xipki)
 */
public final class AlgorithmOIDs {

  public static final Asn1Oid id_alg_unsigned = IanaOIDs.id_alg_unsigned;

  public static final Asn1Oid id_rsaEncryption = PkcsOIDs.rsaEncryption;

  public static final Asn1Oid id_ecPublicKey = X9OIDs.id_ecPublicKey;

  public static final Asn1Oid id_RSASSA_PSS = PkcsOIDs.id_RSASSA_PSS;

  public static final Asn1Oid id_RSAES_OAEP = PkcsOIDs.id_RSAES_OAEP;

  public static final Asn1Oid id_mgf1 = PkcsOIDs.id_mgf1;

  public static final Asn1Oid sm2sign_with_sm3 = GmOIDs.sm2sign_with_sm3;

  public static final Asn1Oid id_ml_dsa_44 = NistOIDs.id_ml_dsa_44;

  public static final Asn1Oid id_ml_dsa_65 = NistOIDs.id_ml_dsa_65;

  public static final Asn1Oid id_ml_dsa_87 = NistOIDs.id_ml_dsa_87;

  public static final Asn1Oid id_ml_kem_512 = NistOIDs.id_ml_kem_512;

  public static final Asn1Oid id_ml_kem_768 = NistOIDs.id_ml_kem_768;

  public static final Asn1Oid id_ml_kem_1024 = NistOIDs.id_ml_kem_1024;

  public static final Asn1Oid id_RSASSA_PSS_SHAKE128 = IanaOIDs.id_RSASSA_PSS_SHAKE128;

  public static final Asn1Oid id_RSASSA_PSS_SHAKE256 = IanaOIDs.id_RSASSA_PSS_SHAKE256;

  public static final Asn1Oid id_ecdsa_with_shake128 = IanaOIDs.id_ecdsa_with_shake128;

  public static final Asn1Oid id_ecdsa_with_shake256 = IanaOIDs.id_ecdsa_with_shake256;

  public static final Asn1Oid id_ecdsa_with_sha3_224 = NistOIDs.id_ecdsa_with_sha3_224;

  public static final Asn1Oid id_ecdsa_with_sha3_256 = NistOIDs.id_ecdsa_with_sha3_256;

  public static final Asn1Oid id_ecdsa_with_sha3_384 = NistOIDs.id_ecdsa_with_sha3_384;

  public static final Asn1Oid id_ecdsa_with_sha3_512 = NistOIDs.id_ecdsa_with_sha3_512;

  public static final Asn1Oid id_hmacWithSHA3_224 = NistOIDs.id_hmacWithSHA3_224;

  public static final Asn1Oid id_hmacWithSHA3_256 = NistOIDs.id_hmacWithSHA3_256;

  public static final Asn1Oid id_hmacWithSHA3_384 = NistOIDs.id_hmacWithSHA3_384;

  public static final Asn1Oid id_hmacWithSHA3_512 = NistOIDs.id_hmacWithSHA3_512;

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_224 =
      NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_224;

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_256 =
      NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_256;

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_384 =
      NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_384;

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_512 =
      NistOIDs.id_rsassa_pkcs1_v1_5_with_sha3_512;

  public static final Asn1Oid id_hmacWithSHA1 = PkcsOIDs.id_hmacWithSHA1;

  public static final Asn1Oid id_hmacWithSHA224 = PkcsOIDs.id_hmacWithSHA224;

  public static final Asn1Oid id_hmacWithSHA256 = PkcsOIDs.id_hmacWithSHA256;

  public static final Asn1Oid id_hmacWithSHA384 = PkcsOIDs.id_hmacWithSHA384;

  public static final Asn1Oid id_hmacWithSHA512 = PkcsOIDs.id_hmacWithSHA512;

  public static final Asn1Oid sha1WithRSAEncryption = PkcsOIDs.sha1WithRSAEncryption;

  public static final Asn1Oid sha224WithRSAEncryption = PkcsOIDs.sha224WithRSAEncryption;

  public static final Asn1Oid sha256WithRSAEncryption = PkcsOIDs.sha256WithRSAEncryption;

  public static final Asn1Oid sha384WithRSAEncryption = PkcsOIDs.sha384WithRSAEncryption;

  public static final Asn1Oid sha512WithRSAEncryption = PkcsOIDs.sha512WithRSAEncryption;

  public static final Asn1Oid ecdsa_with_SHA1 = X9OIDs.ecdsa_with_SHA1;

  public static final Asn1Oid ecdsa_with_SHA224 = X9OIDs.ecdsa_with_SHA224;

  public static final Asn1Oid ecdsa_with_SHA256 = X9OIDs.ecdsa_with_SHA256;

  public static final Asn1Oid ecdsa_with_SHA384 = X9OIDs.ecdsa_with_SHA384;

  public static final Asn1Oid ecdsa_with_SHA512 = X9OIDs.ecdsa_with_SHA512;

  public static final Asn1Oid AES128_GMAC = NistOIDs.id_aes128_GMAC;

  public static final Asn1Oid AES192_GMAC = NistOIDs.id_aes192_GMAC;

  public static final Asn1Oid AES256_GMAC = NistOIDs.id_aes256_GMAC;

  public static final Asn1Oid id_aes128_GCM = NistOIDs.id_aes128_GCM;

  public static final Asn1Oid id_aes192_GCM = NistOIDs.id_aes192_GCM;

  public static final Asn1Oid id_aes256_GCM = NistOIDs.id_aes256_GCM;

  public static final Asn1Oid id_sm3 = GmOIDs.sm3;

  public static final Asn1Oid id_sha1 = OiwOIDs.idSHA1;

  public static final Asn1Oid id_sha224 = NistOIDs.id_sha224;

  public static final Asn1Oid id_sha256 = NistOIDs.id_sha256;

  public static final Asn1Oid id_sha384 = NistOIDs.id_sha384;

  public static final Asn1Oid id_sha512 = NistOIDs.id_sha512;

  public static final Asn1Oid id_sha3_224 = NistOIDs.id_sha3_224;

  public static final Asn1Oid id_sha3_256 = NistOIDs.id_sha3_256;

  public static final Asn1Oid id_sha3_384 = NistOIDs.id_sha3_384;

  public static final Asn1Oid id_sha3_512 = NistOIDs.id_sha3_512;

  public static final Asn1Oid id_shake128 = NistOIDs.id_shake128;

  public static final Asn1Oid id_shake256 = NistOIDs.id_shake256;

  public static final Asn1Oid id_PBKDF2 = PkcsOIDs.id_PBKDF2;

  public static final Asn1Oid id_PBES2 = PkcsOIDs.id_PBES2;

  public static final Asn1Oid id_DES_EDE3_CBC = PkcsOIDs.des_EDE3_CBC;

  // ----- Composite Algorithms ------

  // composite_sigs
  public static final Asn1Oid id_MLDSA44_RSA2048_PSS_SHA256 =
      IanaOIDs.id_MLDSA44_RSA2048_PSS_SHA256;

  public static final Asn1Oid id_MLDSA44_RSA2048_PKCS15_SHA256 =
      IanaOIDs.id_MLDSA44_RSA2048_PKCS15_SHA256;

  public static final Asn1Oid id_MLDSA44_Ed25519_SHA512 =
      IanaOIDs.id_MLDSA44_Ed25519_SHA512;

  public static final Asn1Oid id_MLDSA44_ECDSA_P256_SHA256 =
      IanaOIDs.id_MLDSA44_ECDSA_P256_SHA256;

  public static final Asn1Oid id_MLDSA65_RSA3072_PSS_SHA512 =
      IanaOIDs.id_MLDSA65_RSA3072_PSS_SHA512;

  public static final Asn1Oid id_MLDSA65_RSA3072_PKCS15_SHA512 =
      IanaOIDs.id_MLDSA65_RSA3072_PKCS15_SHA512;

  public static final Asn1Oid id_MLDSA65_RSA4096_PSS_SHA512 =
      IanaOIDs.id_MLDSA65_RSA4096_PSS_SHA512;

  public static final Asn1Oid id_MLDSA65_RSA4096_PKCS15_SHA512 =
      IanaOIDs.id_MLDSA65_RSA4096_PKCS15_SHA512;

  public static final Asn1Oid id_MLDSA65_ECDSA_P256_SHA512 =
      IanaOIDs.id_MLDSA65_ECDSA_P256_SHA512;

  public static final Asn1Oid id_MLDSA65_ECDSA_P384_SHA512 =
      IanaOIDs.id_MLDSA65_ECDSA_P384_SHA512;

  public static final Asn1Oid id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 =
      IanaOIDs.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512;

  public static final Asn1Oid id_MLDSA65_Ed25519_SHA512 = IanaOIDs.id_MLDSA65_Ed25519_SHA512;

  public static final Asn1Oid id_MLDSA87_ECDSA_P384_SHA512 =
      IanaOIDs.id_MLDSA87_ECDSA_P384_SHA512;

  public static final Asn1Oid id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 =
      IanaOIDs.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512;

  public static final Asn1Oid id_MLDSA87_Ed448_SHAKE256 = IanaOIDs.id_MLDSA87_Ed448_SHAKE256;

  public static final Asn1Oid id_MLDSA87_RSA3072_PSS_SHA512 =
      IanaOIDs.id_MLDSA87_RSA3072_PSS_SHA512;

  public static final Asn1Oid id_MLDSA87_RSA4096_PSS_SHA512 =
      IanaOIDs.id_MLDSA87_RSA4096_PSS_SHA512;

  public static final Asn1Oid id_MLDSA87_ECDSA_P521_SHA512 =
      IanaOIDs.id_MLDSA87_ECDSA_P521_SHA512;

  // composite_kem
  public static final Asn1Oid id_MLKEM768_RSA2048_SHA3_256 =
      IanaOIDs.id_MLKEM768_RSA2048_SHA3_256;

  public static final Asn1Oid id_MLKEM768_RSA3072_SHA3_256 =
      IanaOIDs.id_MLKEM768_RSA3072_SHA3_256;

  public static final Asn1Oid id_MLKEM768_RSA4096_SHA3_256 =
      IanaOIDs.id_MLKEM768_RSA4096_SHA3_256;

  public static final Asn1Oid id_MLKEM768_X25519_SHA3_256 =
      IanaOIDs.id_MLKEM768_X25519_SHA3_256;

  public static final Asn1Oid id_MLKEM768_ECDH_P256_SHA3_256 =
      IanaOIDs.id_MLKEM768_ECDH_P256_SHA3_256;

  public static final Asn1Oid id_MLKEM768_ECDH_P384_SHA3_256 =
      IanaOIDs.id_MLKEM768_ECDH_P384_SHA3_256;

  public static final Asn1Oid id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256 =
      IanaOIDs.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256;

  public static final Asn1Oid id_MLKEM1024_RSA3072_SHA3_256 =
      IanaOIDs.id_MLKEM1024_RSA3072_SHA3_256;

  public static final Asn1Oid id_MLKEM1024_ECDH_P384_SHA3_256 =
      IanaOIDs.id_MLKEM1024_ECDH_P384_SHA3_256;

  public static final Asn1Oid id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256 =
      IanaOIDs.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256;

  public static final Asn1Oid id_MLKEM1024_X448_SHA3_256 =
      IanaOIDs.id_MLKEM1024_X448_SHA3_256;

  public static final Asn1Oid id_MLKEM1024_ECDH_P521_SHA3_256 =
      IanaOIDs.id_MLKEM1024_ECDH_P521_SHA3_256;

  public static final Asn1Oid id_X25519 = OIDs.initOid("1.3.101.110", "id-X25519");
  public static final Asn1Oid id_X448 = OIDs.initOid("1.3.101.111", "id-X448");
  public static final Asn1Oid id_Ed25519 = OIDs.initOid("1.3.101.112", "id-Ed25519");
  public static final Asn1Oid id_Ed448 = OIDs.initOid("1.3.101.113", "id-Ed448");

}
