// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class CmsOIDs {

  private CmsOIDs() {
  }

  public static final Asn1Oid data = PkcsOIDs.data;

  public static final Asn1Oid signedData = PkcsOIDs.signedData;

  public static final Asn1Oid envelopedData = PkcsOIDs.envelopedData;

  public static final Asn1Oid signedAndEnvelopedData = PkcsOIDs.signedAndEnvelopedData;

  public static final Asn1Oid digestedData = PkcsOIDs.digestedData;

  public static final Asn1Oid encryptedData = PkcsOIDs.encryptedData;

  public static final Asn1Oid authenticatedData = PkcsOIDs.id_ct_authData;

  public static final Asn1Oid compressedData = PkcsOIDs.id_ct_compressedData;

  public static final Asn1Oid authEnvelopedData = PkcsOIDs.id_ct_authEnvelopedData;

  public static final Asn1Oid timestampedData = PkcsOIDs.id_ct_timestampedData;

  public static final Asn1Oid zlibCompress = PkcsOIDs.id_alg_zlibCompress;

  public static final Asn1Oid id_ri = OIDs.initOid("1.3.6.1.5.5.7.16", "id-ri");

  public static final Asn1Oid id_ri_ocsp_response = OIDs.initOid(
      "1.3.6.1.5.5.7.16.2", "id-ri-ocsp-response");

  public static final Asn1Oid id_ri_scvp = OIDs.initOid("1.3.6.1.5.5.7.16.4", "id-ri-scvp");

  public static final Asn1Oid id_RSASSA_PSS_SHAKE128 = IanaOIDs.id_RSASSA_PSS_SHAKE128;

  public static final Asn1Oid id_RSASSA_PSS_SHAKE256 = IanaOIDs.id_RSASSA_PSS_SHAKE256;

  public static final Asn1Oid id_ecdsa_with_shake128 = IanaOIDs.id_ecdsa_with_shake128;

  public static final Asn1Oid id_ecdsa_with_shake256 = IanaOIDs.id_ecdsa_with_shake256;

  public static final Asn1Oid id_ori_kem = OIDs.initOid("1.2.840.113549.1.9.16.13.3", "id-ori-kem");

  public static final Asn1Oid id_alg_cek_hkdf_sha256 = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.31", "id-alg-cek-hkdf-sha256");

  public static final Asn1Oid contentType = PkcsOIDs.pkcs9_at_contentType;

  public static final Asn1Oid messageDigest = PkcsOIDs.pkcs9_at_messageDigest;

  public static final Asn1Oid signingTime = PkcsOIDs.pkcs9_at_signingTime;

  public static final Asn1Oid counterSignature = PkcsOIDs.pkcs9_at_counterSignature;

  public static final Asn1Oid binarySigningTime = PkcsOIDs.pkcs_9_at_binarySigningTime;

  public static final Asn1Oid contentHint = PkcsOIDs.id_aa_contentHint;

  public static final Asn1Oid cmsAlgorithmProtect = PkcsOIDs.id_aa_cmsAlgorithmProtect;

}
