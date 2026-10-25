// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class NistOIDs {

  private NistOIDs() {
  }

  public static final Asn1Oid id_sha256 = OIDs.initOid("2.16.840.1.101.3.4.2.1", "id-sha256");

  public static final Asn1Oid id_sha384 = OIDs.initOid("2.16.840.1.101.3.4.2.2", "id-sha384");

  public static final Asn1Oid id_sha512 = OIDs.initOid("2.16.840.1.101.3.4.2.3", "id-sha512");

  public static final Asn1Oid id_sha224 = OIDs.initOid("2.16.840.1.101.3.4.2.4", "id-sha224");

  public static final Asn1Oid id_sha512_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.5", "id-sha512-224");

  public static final Asn1Oid id_sha512_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.6", "id-sha512-256");

  public static final Asn1Oid id_sha3_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.7", "id-sha3-224");

  public static final Asn1Oid id_sha3_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.8", "id-sha3-256");

  public static final Asn1Oid id_sha3_384 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.9", "id-sha3-384");

  public static final Asn1Oid id_sha3_512 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.10", "id-sha3-512");

  public static final Asn1Oid id_shake128 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.11", "id-shake128");

  public static final Asn1Oid id_shake256 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.12", "id-shake256");

  public static final Asn1Oid id_hmacWithSHA3_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.13", "id-hmacWithSHA3-224");

  public static final Asn1Oid id_hmacWithSHA3_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.14", "id-hmacWithSHA3-256");

  public static final Asn1Oid id_hmacWithSHA3_384 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.15", "id-hmacWithSHA3-384");

  public static final Asn1Oid id_hmacWithSHA3_512 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.16", "id-hmacWithSHA3-512");

  public static final Asn1Oid id_shake128_len = OIDs.initOid(
      "2.16.840.1.101.3.4.2.17", "id-shake128-len");

  public static final Asn1Oid id_shake256_len = OIDs.initOid(
      "2.16.840.1.101.3.4.2.18", "id-shake256-len");

  public static final Asn1Oid id_KmacWithSHAKE128 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.19", "id-KmacWithSHAKE128");

  public static final Asn1Oid id_KmacWithSHAKE256 = OIDs.initOid(
      "2.16.840.1.101.3.4.2.20", "id-KmacWithSHAKE256");

  public static final Asn1Oid id_Kmac128 = OIDs.initOid("2.16.840.1.101.3.4.2.21", "id-Kmac128");

  public static final Asn1Oid id_Kmac256 = OIDs.initOid("2.16.840.1.101.3.4.2.22", "id-Kmac256");

  public static final Asn1Oid aes = OIDs.initOid("2.16.840.1.101.3.4.1", "aes");

  public static final Asn1Oid id_aes128_ECB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.1", "id-aes128-ECB");

  public static final Asn1Oid id_aes128_CBC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.2", "id-aes128-CBC");

  public static final Asn1Oid id_aes128_OFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.3", "id-aes128-OFB");

  public static final Asn1Oid id_aes128_CFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.4", "id-aes128-CFB");

  public static final Asn1Oid id_aes128_wrap = OIDs.initOid(
      "2.16.840.1.101.3.4.1.5", "id-aes128-wrap");

  public static final Asn1Oid id_aes128_GCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.6", "id-aes128-GCM");

  public static final Asn1Oid id_aes128_CCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.7", "id-aes128-CCM");

  public static final Asn1Oid id_aes128_wrap_pad = OIDs.initOid(
      "2.16.840.1.101.3.4.1.8", "id-aes128-wrap-pad");

  public static final Asn1Oid id_aes128_GMAC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.9", "id-aes128-GMAC");

  public static final Asn1Oid id_aes192_ECB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.21", "id-aes192-ECB");

  public static final Asn1Oid id_aes192_CBC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.22", "id-aes192-CBC");

  public static final Asn1Oid id_aes192_OFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.23", "id-aes192-OFB");

  public static final Asn1Oid id_aes192_CFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.24", "id-aes192-CFB");

  public static final Asn1Oid id_aes192_wrap = OIDs.initOid(
      "2.16.840.1.101.3.4.1.25", "id-aes192-wrap");

  public static final Asn1Oid id_aes192_GCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.26", "id-aes192-GCM");

  public static final Asn1Oid id_aes192_CCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.27", "id-aes192-CCM");

  public static final Asn1Oid id_aes192_wrap_pad = OIDs.initOid(
      "2.16.840.1.101.3.4.1.28", "id-aes192-wrap-pad");

  public static final Asn1Oid id_aes192_GMAC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.29", "id-aes192-GMAC");

  public static final Asn1Oid id_aes256_ECB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.41", "id-aes256-ECB");

  public static final Asn1Oid id_aes256_CBC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.42", "id-aes256-CBC");

  public static final Asn1Oid id_aes256_OFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.43", "id-aes256-OFB");

  public static final Asn1Oid id_aes256_CFB = OIDs.initOid(
      "2.16.840.1.101.3.4.1.44", "id-aes256-CFB");

  public static final Asn1Oid id_aes256_wrap = OIDs.initOid(
      "2.16.840.1.101.3.4.1.45", "id-aes256-wrap");

  public static final Asn1Oid id_aes256_GCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.46", "id-aes256-GCM");

  public static final Asn1Oid id_aes256_CCM = OIDs.initOid(
      "2.16.840.1.101.3.4.1.47", "id-aes256-CCM");

  public static final Asn1Oid id_aes256_wrap_pad = OIDs.initOid(
      "2.16.840.1.101.3.4.1.48", "id-aes256-wrap-pad");

  public static final Asn1Oid id_aes256_GMAC = OIDs.initOid(
      "2.16.840.1.101.3.4.1.49", "id-aes256-GMAC");

  public static final Asn1Oid dsa_with_sha224 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.1", "dsa-with-sha224");

  public static final Asn1Oid dsa_with_sha256 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.2", "dsa-with-sha256");

  public static final Asn1Oid dsa_with_sha384 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.3", "dsa-with-sha384");

  public static final Asn1Oid dsa_with_sha512 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.4", "dsa-with-sha512");

  public static final Asn1Oid id_dsa_with_sha3_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.5", "id-dsa-with-sha3-224");

  public static final Asn1Oid id_dsa_with_sha3_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.6", "id-dsa-with-sha3-256");

  public static final Asn1Oid id_dsa_with_sha3_384 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.7", "id-dsa-with-sha3-384");

  public static final Asn1Oid id_dsa_with_sha3_512 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.8", "id-dsa-with-sha3-512");

  public static final Asn1Oid id_ecdsa_with_sha3_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.9", "id-ecdsa-with-sha3-224");

  public static final Asn1Oid id_ecdsa_with_sha3_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.10", "id-ecdsa-with-sha3-256");

  public static final Asn1Oid id_ecdsa_with_sha3_384 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.11", "id-ecdsa-with-sha3-384");

  public static final Asn1Oid id_ecdsa_with_sha3_512 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.12", "id-ecdsa-with-sha3-512");

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_224 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.13", "id-rsassa-pkcs1-v1-5-with-sha3-224");

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_256 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.14", "id-rsassa-pkcs1-v1-5-with-sha3-256");

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_384 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.15", "id-rsassa-pkcs1-v1-5-with-sha3-384");

  public static final Asn1Oid id_rsassa_pkcs1_v1_5_with_sha3_512 = OIDs.initOid(
      "2.16.840.1.101.3.4.3.16", "id-rsassa-pkcs1-v1-5-with-sha3-512");

  public static final Asn1Oid id_ml_dsa_44 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.17", "id-ml-dsa-44");

  public static final Asn1Oid id_ml_dsa_65 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.18", "id-ml-dsa-65");

  public static final Asn1Oid id_ml_dsa_87 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.19", "id-ml-dsa-87");

  public static final Asn1Oid id_hash_ml_dsa_44_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.32", "id-hash-ml-dsa-44-with-sha512");

  public static final Asn1Oid id_hash_ml_dsa_65_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.33", "id-hash-ml-dsa-65-with-sha512");

  public static final Asn1Oid id_hash_ml_dsa_87_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.34", "id-hash-ml-dsa-87-with-sha512");

  public static final Asn1Oid id_slh_dsa_sha2_128s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.20", "id-slh-dsa-sha2-128s");

  public static final Asn1Oid id_slh_dsa_sha2_128f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.21", "id-slh-dsa-sha2-128f");

  public static final Asn1Oid id_slh_dsa_sha2_192s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.22", "id-slh-dsa-sha2-192s");

  public static final Asn1Oid id_slh_dsa_sha2_192f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.23", "id-slh-dsa-sha2-192f");

  public static final Asn1Oid id_slh_dsa_sha2_256s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.24", "id-slh-dsa-sha2-256s");

  public static final Asn1Oid id_slh_dsa_sha2_256f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.25", "id-slh-dsa-sha2-256f");

  public static final Asn1Oid id_slh_dsa_shake_128s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.26", "id-slh-dsa-shake-128s");

  public static final Asn1Oid id_slh_dsa_shake_128f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.27", "id-slh-dsa-shake-128f");

  public static final Asn1Oid id_slh_dsa_shake_192s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.28", "id-slh-dsa-shake-192s");

  public static final Asn1Oid id_slh_dsa_shake_192f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.29", "id-slh-dsa-shake-192f");

  public static final Asn1Oid id_slh_dsa_shake_256s = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.30", "id-slh-dsa-shake-256s");

  public static final Asn1Oid id_slh_dsa_shake_256f = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.31", "id-slh-dsa-shake-256f");

  public static final Asn1Oid id_hash_slh_dsa_sha2_128s_with_sha256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.35", "id-hash-slh-dsa-sha2-128s-with-sha256");

  public static final Asn1Oid id_hash_slh_dsa_sha2_128f_with_sha256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.36", "id-hash-slh-dsa-sha2-128f-with-sha256");

  public static final Asn1Oid id_hash_slh_dsa_sha2_192s_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.37", "id-hash-slh-dsa-sha2-192s-with-sha512");

  public static final Asn1Oid id_hash_slh_dsa_sha2_192f_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.38", "id-hash-slh-dsa-sha2-192f-with-sha512");

  public static final Asn1Oid id_hash_slh_dsa_sha2_256s_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.39", "id-hash-slh-dsa-sha2-256s-with-sha512");

  public static final Asn1Oid id_hash_slh_dsa_sha2_256f_with_sha512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.40", "id-hash-slh-dsa-sha2-256f-with-sha512");

  public static final Asn1Oid id_hash_slh_dsa_shake_128s_with_shake128 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.41", "id-hash-slh-dsa-shake-128s-with-shake128");

  public static final Asn1Oid id_hash_slh_dsa_shake_128f_with_shake128 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.42", "id-hash-slh-dsa-shake-128f-with-shake128");

  public static final Asn1Oid id_hash_slh_dsa_shake_192s_with_shake256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.43", "id-hash-slh-dsa-shake-192s-with-shake256");

  public static final Asn1Oid id_hash_slh_dsa_shake_192f_with_shake256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.44", "id-hash-slh-dsa-shake-192f-with-shake256");

  public static final Asn1Oid id_hash_slh_dsa_shake_256s_with_shake256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.45", "id-hash-slh-dsa-shake-256s-with-shake256");

  public static final Asn1Oid id_hash_slh_dsa_shake_256f_with_shake256 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.3.46", "id-hash-slh-dsa-shake-256f-with-shake256");

  public static final Asn1Oid id_ml_kem_512 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.4.1", "id-ml-kem-512");

  public static final Asn1Oid id_ml_kem_768 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.4.2", "id-ml-kem-768");

  public static final Asn1Oid id_ml_kem_1024 = OIDs.initPqcOid(
      "2.16.840.1.101.3.4.4.3", "id-ml-kem-1024");

}
