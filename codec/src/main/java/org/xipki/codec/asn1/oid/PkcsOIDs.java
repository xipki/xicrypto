// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class PkcsOIDs {

  private PkcsOIDs() {
  }

  public static final Asn1Oid rsaEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.1", "rsaEncryption");

  public static final Asn1Oid md5WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.4", "md5WithRSAEncryption");

  public static final Asn1Oid sha1WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.5", "sha1WithRSAEncryption");

  public static final Asn1Oid id_RSAES_OAEP = OIDs.initOid(
      "1.2.840.113549.1.1.7", "id-RSAES-OAEP");

  public static final Asn1Oid id_mgf1 = OIDs.initOid(
      "1.2.840.113549.1.1.8", "id-mgf1");

  public static final Asn1Oid id_pSpecified = OIDs.initOid(
      "1.2.840.113549.1.1.9", "id-pSpecified");

  public static final Asn1Oid id_RSASSA_PSS = OIDs.initOid(
      "1.2.840.113549.1.1.10", "id-RSASSA-PSS");

  public static final Asn1Oid sha256WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.11", "sha256WithRSAEncryption");

  public static final Asn1Oid sha384WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.12", "sha384WithRSAEncryption");

  public static final Asn1Oid sha512WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.13", "sha512WithRSAEncryption");

  public static final Asn1Oid sha224WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.14", "sha224WithRSAEncryption");

  public static final Asn1Oid sha512_224WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.15", "sha512-224WithRSAEncryption");

  public static final Asn1Oid sha512_256WithRSAEncryption = OIDs.initOid(
      "1.2.840.113549.1.1.16", "sha512-256WithRSAEncryption");

  public static final Asn1Oid id_PBKDF2 = OIDs.initOid("1.2.840.113549.1.5.12", "id-PBKDF2");

  public static final Asn1Oid id_PBES2 = OIDs.initOid("1.2.840.113549.1.5.13", "id-PBES2");

  public static final Asn1Oid id_PBMAC1 = OIDs.initOid("1.2.840.113549.1.5.14", "id-PBMAC1");

  public static final Asn1Oid encryptionAlgorithm = OIDs.initOid(
      "1.2.840.113549.3", "encryptionAlgorithm");

  public static final Asn1Oid des_EDE3_CBC = OIDs.initOid("1.2.840.113549.3.7", "des-EDE3-CBC");

  public static final Asn1Oid digestAlgorithm = OIDs.initOid("1.2.840.113549.2", "digestAlgorithm");

  public static final Asn1Oid id_hmacWithSHA1 = OIDs.initOid(
      "1.2.840.113549.2.7", "id-hmacWithSHA1");

  public static final Asn1Oid id_hmacWithSHA224 = OIDs.initOid(
      "1.2.840.113549.2.8", "id-hmacWithSHA224");

  public static final Asn1Oid id_hmacWithSHA256 = OIDs.initOid(
      "1.2.840.113549.2.9", "id-hmacWithSHA256");

  public static final Asn1Oid id_hmacWithSHA384 = OIDs.initOid(
      "1.2.840.113549.2.10", "id-hmacWithSHA384");

  public static final Asn1Oid id_hmacWithSHA512 = OIDs.initOid(
      "1.2.840.113549.2.11", "id-hmacWithSHA512");

  public static final Asn1Oid id_hmacWithSHA512_224 = OIDs.initOid(
      "1.2.840.113549.2.12", "id-hmacWithSHA512-224");

  public static final Asn1Oid id_hmacWithSHA512_256 = OIDs.initOid(
      "1.2.840.113549.2.13", "id-hmacWithSHA512-256");

  public static final Asn1Oid pkcs_7 = OIDs.initOid("1.2.840.113549.1.7", "pkcs-7");

  public static final Asn1Oid data = OIDs.initOid("1.2.840.113549.1.7.1", "data");

  public static final Asn1Oid signedData = OIDs.initOid("1.2.840.113549.1.7.2", "signedData");

  public static final Asn1Oid envelopedData = OIDs.initOid(
      "1.2.840.113549.1.7.3", "envelopedData");

  public static final Asn1Oid signedAndEnvelopedData = OIDs.initOid(
      "1.2.840.113549.1.7.4", "signedAndEnvelopedData");

  public static final Asn1Oid digestedData = OIDs.initOid(
      "1.2.840.113549.1.7.5", "digestedData");

  public static final Asn1Oid encryptedData = OIDs.initOid(
      "1.2.840.113549.1.7.6", "encryptedData");

  public static final Asn1Oid pkcs9_at_emailAddress = OIDs.initOid(
      "1.2.840.113549.1.9.1", "pkcs9-at-emailAddress");

  public static final Asn1Oid pkcs9_at_unstructuredName = OIDs.initOid(
      "1.2.840.113549.1.9.2", "pkcs9-at-unstructuredName");

  public static final Asn1Oid pkcs9_at_contentType = OIDs.initOid(
      "1.2.840.113549.1.9.3", "pkcs9-at-contentType");

  public static final Asn1Oid pkcs9_at_messageDigest = OIDs.initOid(
      "1.2.840.113549.1.9.4", "pkcs9-at-messageDigest");

  public static final Asn1Oid pkcs9_at_signingTime = OIDs.initOid(
      "1.2.840.113549.1.9.5", "pkcs9-at-signingTime");

  public static final Asn1Oid pkcs9_at_counterSignature = OIDs.initOid(
      "1.2.840.113549.1.9.6", "pkcs9-at-counterSignature");

  public static final Asn1Oid pkcs9_at_challengePassword = OIDs.initOid(
      "1.2.840.113549.1.9.7", "pkcs9-at-challengePassword");

  public static final Asn1Oid pkcs9_at_unstructuredAddress = OIDs.initOid(
      "1.2.840.113549.1.9.8", "pkcs9-at-unstructuredAddress");

  public static final Asn1Oid pkcs9_at_extendedCertificateAttributes = OIDs.initOid(
      "1.2.840.113549.1.9.9", "pkcs9-at-extendedCertificateAttributes");

  public static final Asn1Oid pkcs9_at_signingDescription = OIDs.initOid(
      "1.2.840.113549.1.9.13", "pkcs9-at-signingDescription");

  public static final Asn1Oid pkcs9_at_extensionRequest = OIDs.initOid(
      "1.2.840.113549.1.9.14", "pkcs9-at-extensionRequest");

  public static final Asn1Oid pkcs9_at_smimeCapabilities = OIDs.initOid(
      "1.2.840.113549.1.9.15", "pkcs9-at-smimeCapabilities");

  public static final Asn1Oid id_smime = OIDs.initOid(
      "1.2.840.113549.1.9.16", "id-smime");

  public static final Asn1Oid pkcs9_at_friendlyName = OIDs.initOid(
      "1.2.840.113549.1.9.20", "pkcs9-at-friendlyName");

  public static final Asn1Oid pkcs9_at_localKeyId = OIDs.initOid(
      "1.2.840.113549.1.9.21", "pkcs9-at-localKeyId");

  public static final Asn1Oid certTypes = OIDs.initOid(
      "1.2.840.113549.1.9.22", "certTypes");

  public static final Asn1Oid x509Certificate = OIDs.initOid(
      "1.2.840.113549.1.9.22.1", "x509Certificate");

  public static final Asn1Oid sdsiCertificate = OIDs.initOid(
      "1.2.840.113549.1.9.22.2", "sdsiCertificate");

  public static final Asn1Oid crlTypes = OIDs.initOid("1.2.840.113549.1.9.23", "crlTypes");

  public static final Asn1Oid x509Crl = OIDs.initOid("1.2.840.113549.1.9.23.1", "x509Crl");

  public static final Asn1Oid id_aa_cmsAlgorithmProtect = OIDs.initOid(
      "1.2.840.113549.1.9.52", "id-aa-cmsAlgorithmProtect");

  public static final Asn1Oid preferSignedData = OIDs.initOid(
      "1.2.840.113549.1.9.15.1", "preferSignedData");

  public static final Asn1Oid canNotDecryptAny = OIDs.initOid(
      "1.2.840.113549.1.9.15.2", "canNotDecryptAny");

  public static final Asn1Oid sMIMECapabilitiesVersions = OIDs.initOid(
      "1.2.840.113549.1.9.15.3", "sMIMECapabilitiesVersions");

  public static final Asn1Oid id_mod_cms_seed = OIDs.initOid(
      "1.2.840.113549.1.9.16.0.24", "id-mod-cms-seed");

  public static final Asn1Oid id_mod_mts_hashsig_2013 = OIDs.initOid(
      "1.2.840.113549.1.9.16.0.64", "id-mod-mts-hashsig-2013");

  public static final Asn1Oid id_mod_CMS_AEADChaCha20Poly1305 = OIDs.initOid(
      "1.2.840.113549.1.9.16.0.66", "id-mod-CMS-AEADChaCha20Poly1305");

  public static final Asn1Oid id_ct = OIDs.initOid("1.2.840.113549.1.9.16.1", "id-ct");

  public static final Asn1Oid id_ct_authData = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.2", "id-ct-authData");

  public static final Asn1Oid id_ct_TSTInfo = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.4", "id-ct-TSTInfo");

  public static final Asn1Oid id_ct_compressedData = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.9", "id-ct-compressedData");

  public static final Asn1Oid id_ct_authEnvelopedData = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.23", "id-ct-authEnvelopedData");

  public static final Asn1Oid id_ct_timestampedData = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.31", "id-ct-timestampedData");

  public static final Asn1Oid smime_alg = OIDs.initOid(
      "1.2.840.113549.1.9.16.3", "smime-alg");

  public static final Asn1Oid id_alg_ESDH = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.5", "id-alg-ESDH");

  public static final Asn1Oid id_alg_CMS3DESwrap = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.6", "id-alg-CMS3DESwrap");

  public static final Asn1Oid id_alg_CMSRC2wrap = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.7", "id-alg-CMSRC2wrap");

  public static final Asn1Oid id_alg_zlibCompress = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.8", "id-alg-zlibCompress");

  public static final Asn1Oid id_alg_PWRI_KEK = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.9", "id-alg-PWRI-KEK");

  public static final Asn1Oid id_alg_SSDH = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.10", "id-alg-SSDH");

  public static final Asn1Oid id_rsa_KEM = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.14", "id-rsa-KEM");

  public static final Asn1Oid id_alg_hss_lms_hashsig = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.17", "id-alg-hss-lms-hashsig");

  public static final Asn1Oid id_alg_AEADChaCha20Poly1305 = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.18", "id-alg-AEADChaCha20Poly1305");

  public static final Asn1Oid dhSinglePass_stdDH_hkdf_sha256_scheme = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.19", "dhSinglePass-stdDH-hkdf-sha256-scheme");

  public static final Asn1Oid dhSinglePass_stdDH_hkdf_sha384_scheme = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.20", "dhSinglePass-stdDH-hkdf-sha384-scheme");

  public static final Asn1Oid dhSinglePass_stdDH_hkdf_sha512_scheme = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.21", "dhSinglePass-stdDH-hkdf-sha512-scheme");

  public static final Asn1Oid id_alg_hkdf_with_sha256 = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.28", "id-alg-hkdf-with-sha256");

  public static final Asn1Oid id_alg_hkdf_with_sha384 = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.29", "id-alg-hkdf-with-sha384");

  public static final Asn1Oid id_alg_hkdf_with_sha512 = OIDs.initOid(
      "1.2.840.113549.1.9.16.3.30", "id-alg-hkdf-with-sha512");

  public static final Asn1Oid id_cti = OIDs.initOid(
      "1.2.840.113549.1.9.16.6", "id-cti");

  public static final Asn1Oid id_cti_ets_proofOfOrigin = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.1", "id-cti-ets-proofOfOrigin");

  public static final Asn1Oid id_cti_ets_proofOfReceipt = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.2", "id-cti-ets-proofOfReceipt");

  public static final Asn1Oid id_cti_ets_proofOfDelivery = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.3", "id-cti-ets-proofOfDelivery");

  public static final Asn1Oid id_cti_ets_proofOfSender = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.4", "id-cti-ets-proofOfSender");

  public static final Asn1Oid id_cti_ets_proofOfApproval = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.5", "id-cti-ets-proofOfApproval");

  public static final Asn1Oid id_cti_ets_proofOfCreation = OIDs.initOid(
      "1.2.840.113549.1.9.16.6.6", "id-cti-ets-proofOfCreation");

  public static final Asn1Oid id_aa = OIDs.initOid("1.2.840.113549.1.9.16.2", "id-aa");

  public static final Asn1Oid pkcs_9_at_binarySigningTime = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.46", "pkcs-9-at-binarySigningTime");

  public static final Asn1Oid id_aa_receiptRequest = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.1", "id-aa-receiptRequest");

  public static final Asn1Oid id_aa_contentHint = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.4", "id-aa-contentHint");

  public static final Asn1Oid id_aa_msgSigDigest = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.5", "id-aa-msgSigDigest");

  public static final Asn1Oid id_aa_contentReference = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.10", "id-aa-contentReference");

  public static final Asn1Oid id_aa_encrypKeyPref = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.11", "id-aa-encrypKeyPref");

  public static final Asn1Oid id_aa_signingCertificate = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.12", "id-aa-signingCertificate");

  public static final Asn1Oid id_aa_signingCertificateV2 = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.47", "id-aa-signingCertificateV2");

  public static final Asn1Oid id_aa_contentIdentifier = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.7", "id-aa-contentIdentifier");

  public static final Asn1Oid id_aa_signatureTimeStampToken = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.14", "id-aa-signatureTimeStampToken");

  public static final Asn1Oid id_aa_ets_sigPolicyId = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.15", "id-aa-ets-sigPolicyId");

  public static final Asn1Oid id_aa_ets_commitmentType = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.16", "id-aa-ets-commitmentType");

  public static final Asn1Oid id_aa_ets_signerLocation = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.17", "id-aa-ets-signerLocation");

  public static final Asn1Oid id_aa_ets_signerAttr = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.18", "id-aa-ets-signerAttr");

  public static final Asn1Oid id_aa_ets_otherSigCert = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.19", "id-aa-ets-otherSigCert");

  public static final Asn1Oid id_aa_ets_contentTimestamp = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.20", "id-aa-ets-contentTimestamp");

  public static final Asn1Oid id_aa_ets_certificateRefs = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.21", "id-aa-ets-certificateRefs");

  public static final Asn1Oid id_aa_ets_revocationRefs = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.22", "id-aa-ets-revocationRefs");

  public static final Asn1Oid id_aa_ets_certValues = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.23", "id-aa-ets-certValues");

  public static final Asn1Oid id_aa_ets_revocationValues = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.24", "id-aa-ets-revocationValues");

  public static final Asn1Oid id_aa_ets_escTimeStamp = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.25", "id-aa-ets-escTimeStamp");

  public static final Asn1Oid id_aa_ets_certCRLTimestamp = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.26", "id-aa-ets-certCRLTimestamp");

  public static final Asn1Oid id_aa_ets_archiveTimestamp = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.27", "id-aa-ets-archiveTimestamp");

  public static final Asn1Oid id_aa_decryptKeyID = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.37", "id-aa-decryptKeyID");

  public static final Asn1Oid id_aa_implCryptoAlgs = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.38", "id-aa-implCryptoAlgs");

  public static final Asn1Oid id_aa_asymmDecryptKeyID = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.54", "id-aa-asymmDecryptKeyID");

  public static final Asn1Oid id_aa_implCompressAlgs = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.43", "id-aa-implCompressAlgs");

  public static final Asn1Oid id_aa_communityIdentifiers = OIDs.initOid(
      "1.2.840.113549.1.9.16.2.40", "id-aa-communityIdentifiers");

  public static final Asn1Oid id_spq_oid = OIDs.initOid(
      "1.2.840.113549.1.9.16.5", "id-spq-oid");

  public static final Asn1Oid id_spq_ets_uri = OIDs.initOid(
      "1.2.840.113549.1.9.16.5.1", "id-spq-ets-uri");

  public static final Asn1Oid id_spq_ets_unotice = OIDs.initOid(
      "1.2.840.113549.1.9.16.5.2", "id-spq-ets-unotice");

  public static final Asn1Oid pkcs_12 = OIDs.initOid(
      "1.2.840.113549.1.12", "pkcs-12");

  public static final Asn1Oid bagtypes = OIDs.initOid(
      "1.2.840.113549.1.12.10.1", "bagtypes");

  public static final Asn1Oid keyBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.1", "keyBag");

  public static final Asn1Oid pkcs8ShroudedKeyBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.2", "pkcs8ShroudedKeyBag");

  public static final Asn1Oid certBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.3", "certBag");

  public static final Asn1Oid crlBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.4", "crlBag");

  public static final Asn1Oid secretBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.5", "secretBag");

  public static final Asn1Oid safeContentsBag = OIDs.initOid(
      "1.2.840.113549.1.12.10.1.6", "safeContentsBag");

  public static final Asn1Oid pkcs_12PbeIds = OIDs.initOid(
      "1.2.840.113549.1.12.1", "pkcs-12PbeIds");

  public static final Asn1Oid pbeWithSHAAnd128BitRC4 = OIDs.initOid(
      "1.2.840.113549.1.12.1.1", "pbeWithSHAAnd128BitRC4");

  public static final Asn1Oid pbeWithSHAAnd40BitRC4 = OIDs.initOid(
      "1.2.840.113549.1.12.1.2", "pbeWithSHAAnd40BitRC4");

  public static final Asn1Oid pbeWithSHAAnd3_KeyTripleDES_CBC = OIDs.initOid(
      "1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC");

  public static final Asn1Oid pbeWithSHAAnd2_KeyTripleDES_CBC = OIDs.initOid(
      "1.2.840.113549.1.12.1.4", "pbeWithSHAAnd2-KeyTripleDES-CBC");

  public static final Asn1Oid pbeWithSHAAnd128BitRC2_CBC = OIDs.initOid(
      "1.2.840.113549.1.12.1.5", "pbeWithSHAAnd128BitRC2-CBC");

  public static final Asn1Oid pbeWithSHAAnd40BitRC2_CBC = OIDs.initOid(
      "1.2.840.113549.1.12.1.6", "pbeWithSHAAnd40BitRC2-CBC");

}
