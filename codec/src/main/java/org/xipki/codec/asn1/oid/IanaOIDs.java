// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class IanaOIDs {

  private IanaOIDs() {
  }

  public static final Asn1Oid directory = OIDs.initOid("1.3.6.1.1", "directory");

  public static final Asn1Oid mgmt = OIDs.initOid("1.3.6.1.2", "mgmt");

  public static final Asn1Oid experimental = OIDs.initOid("1.3.6.1.3", "experimental");

  public static final Asn1Oid _private = OIDs.initOid("1.3.6.1.4", "-private");

  public static final Asn1Oid security = OIDs.initOid("1.3.6.1.5", "security");

  public static final Asn1Oid SNMPv2 = OIDs.initOid("1.3.6.1.6", "SNMPv2");

  public static final Asn1Oid mail = OIDs.initOid("1.3.6.1.7", "mail");

  public static final Asn1Oid security_mechanisms = OIDs.initOid(
      "1.3.6.1.5.5", "security-mechanisms");

  public static final Asn1Oid security_nametypes = OIDs.initOid(
      "1.3.6.1.5.6", "security-nametypes");

  public static final Asn1Oid isakmpOakley = OIDs.initOid("1.3.6.1.5.5.8.1", "isakmpOakley");

  public static final Asn1Oid hmacMD5 = OIDs.initOid("1.3.6.1.5.5.8.1.1", "hmacMD5");

  public static final Asn1Oid hmacSHA1 = OIDs.initOid("1.3.6.1.5.5.8.1.2", "hmacSHA1");

  public static final Asn1Oid hmacTIGER = OIDs.initOid("1.3.6.1.5.5.8.1.3", "hmacTIGER");

  public static final Asn1Oid hmacRIPEMD160 = OIDs.initOid("1.3.6.1.5.5.8.1.4", "hmacRIPEMD160");

  public static final Asn1Oid id_RSASSA_PSS_SHAKE128 = OIDs.initOid(
      "1.3.6.1.5.5.7.6.30", "id-RSASSA-PSS-SHAKE128");

  public static final Asn1Oid id_RSASSA_PSS_SHAKE256 = OIDs.initOid(
      "1.3.6.1.5.5.7.6.31", "id-RSASSA-PSS-SHAKE256");

  public static final Asn1Oid id_ecdsa_with_shake128 = OIDs.initOid(
      "1.3.6.1.5.5.7.6.32", "id-ecdsa-with-shake128");

  public static final Asn1Oid id_ecdsa_with_shake256 = OIDs.initOid(
      "1.3.6.1.5.5.7.6.33", "id-ecdsa-with-shake256");

  public static final Asn1Oid id_alg_unsigned = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.36", "id-alg-unsigned");

  public static final Asn1Oid id_MLDSA44_RSA2048_PSS_SHA256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.37", "id-MLDSA44-RSA2048-PSS-SHA256");

  public static final Asn1Oid id_MLDSA44_RSA2048_PKCS15_SHA256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.38", "id-MLDSA44-RSA2048-PKCS15-SHA256");

  public static final Asn1Oid id_MLDSA44_Ed25519_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.39", "id-MLDSA44-Ed25519-SHA512");

  public static final Asn1Oid id_MLDSA44_ECDSA_P256_SHA256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.40", "id-MLDSA44-ECDSA-P256-SHA256");

  public static final Asn1Oid id_MLDSA65_RSA3072_PSS_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.41", "id-MLDSA65-RSA3072-PSS-SHA512");

  public static final Asn1Oid id_MLDSA65_RSA3072_PKCS15_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.42", "id-MLDSA65-RSA3072-PKCS15-SHA512");

  public static final Asn1Oid id_MLDSA65_RSA4096_PSS_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.43", "id-MLDSA65-RSA4096-PSS-SHA512");

  public static final Asn1Oid id_MLDSA65_RSA4096_PKCS15_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.44", "id-MLDSA65-RSA4096-PKCS15-SHA512");

  public static final Asn1Oid id_MLDSA65_ECDSA_P256_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.45", "id-MLDSA65-ECDSA-P256-SHA512");

  public static final Asn1Oid id_MLDSA65_ECDSA_P384_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.46", "id-MLDSA65-ECDSA-P384-SHA512");

  public static final Asn1Oid id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.47", "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512");

  public static final Asn1Oid id_MLDSA65_Ed25519_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.48", "id-MLDSA65-Ed25519-SHA512");

  public static final Asn1Oid id_MLDSA87_ECDSA_P384_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.49", "id-MLDSA87-ECDSA-P384-SHA512");

  public static final Asn1Oid id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.50", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512");

  public static final Asn1Oid id_MLDSA87_Ed448_SHAKE256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.51", "id-MLDSA87-Ed448-SHAKE256");

  public static final Asn1Oid id_MLDSA87_RSA3072_PSS_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.52", "id-MLDSA87-RSA3072-PSS-SHA512");

  public static final Asn1Oid id_MLDSA87_RSA4096_PSS_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.53", "id-MLDSA87-RSA4096-PSS-SHA512");

  public static final Asn1Oid id_MLDSA87_ECDSA_P521_SHA512 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.54", "id-MLDSA87-ECDSA-P521-SHA512");

  public static final Asn1Oid id_MLKEM768_RSA2048_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.55", "id-MLKEM768-RSA2048-SHA3-256");

  public static final Asn1Oid id_MLKEM768_RSA3072_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.56", "id-MLKEM768-RSA3072-SHA3-256");

  public static final Asn1Oid id_MLKEM768_RSA4096_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.57", "id-MLKEM768-RSA4096-SHA3-256");

  public static final Asn1Oid id_MLKEM768_X25519_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.58", "id-MLKEM768-X25519-SHA3-256");

  public static final Asn1Oid id_MLKEM768_ECDH_P256_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.59", "id-MLKEM768-ECDH-P256-SHA3-256");

  public static final Asn1Oid id_MLKEM768_ECDH_P384_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.60", "id-MLKEM768-ECDH-P384-SHA3-256");

  public static final Asn1Oid id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.61", "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256");

  public static final Asn1Oid id_MLKEM1024_RSA3072_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.62", "id-MLKEM1024-RSA3072-SHA3-256");

  public static final Asn1Oid id_MLKEM1024_ECDH_P384_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.63", "id-MLKEM1024-ECDH-P384-SHA3-256");

  public static final Asn1Oid id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.64", "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256");

  public static final Asn1Oid id_MLKEM1024_X448_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.65", "id-MLKEM1024-X448-SHA3-256");

  public static final Asn1Oid id_MLKEM1024_ECDH_P521_SHA3_256 = OIDs.initPqcOid(
      "1.3.6.1.5.5.7.6.66", "id-MLKEM1024-ECDH-P521-SHA3-256");

}
