// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class ExtensionOIDs {

  private ExtensionOIDs() {
  }

  public static final Asn1Oid subjectDirectoryAttributes = OIDs.initOid(
      "2.5.29.9", "subjectDirectoryAttributes");

  public static final Asn1Oid subjectKeyIdentifier = OIDs.initOid(
      "2.5.29.14", "subjectKeyIdentifier");

  public static final Asn1Oid keyUsage = OIDs.initOid("2.5.29.15", "keyUsage");

  public static final Asn1Oid privateKeyUsagePeriod = OIDs.initOid(
      "2.5.29.16", "privateKeyUsagePeriod");

  public static final Asn1Oid subjectAlternativeName = OIDs.initOid(
      "2.5.29.17", "subjectAlternativeName");

  public static final Asn1Oid issuerAlternativeName = OIDs.initOid(
      "2.5.29.18", "issuerAlternativeName");

  public static final Asn1Oid basicConstraints = OIDs.initOid("2.5.29.19", "basicConstraints");

  public static final Asn1Oid cRLNumber = OIDs.initOid("2.5.29.20", "cRLNumber");

  public static final Asn1Oid reasonCode = OIDs.initOid("2.5.29.21", "reasonCode");

  public static final Asn1Oid instructionCode = OIDs.initOid("2.5.29.23", "instructionCode");

  public static final Asn1Oid invalidityDate = OIDs.initOid("2.5.29.24", "invalidityDate");

  public static final Asn1Oid deltaCRLIndicator = OIDs.initOid("2.5.29.27", "deltaCRLIndicator");

  public static final Asn1Oid issuingDistributionPoint = OIDs.initOid(
      "2.5.29.28", "issuingDistributionPoint");

  public static final Asn1Oid certificateIssuer = OIDs.initOid("2.5.29.29", "certificateIssuer");

  public static final Asn1Oid nameConstraints = OIDs.initOid("2.5.29.30", "nameConstraints");

  public static final Asn1Oid cRLDistributionPoints = OIDs.initOid(
      "2.5.29.31", "cRLDistributionPoints");

  public static final Asn1Oid certificatePolicies = OIDs.initOid(
      "2.5.29.32", "certificatePolicies");

  public static final Asn1Oid policyMappings = OIDs.initOid("2.5.29.33", "policyMappings");

  public static final Asn1Oid authorityKeyIdentifier = OIDs.initOid(
      "2.5.29.35", "authorityKeyIdentifier");

  public static final Asn1Oid policyConstraints = OIDs.initOid(
      "2.5.29.36", "policyConstraints");

  public static final Asn1Oid extendedKeyUsage = OIDs.initOid("2.5.29.37", "extendedKeyUsage");

  public static final Asn1Oid freshestCRL = OIDs.initOid("2.5.29.46", "freshestCRL");

  public static final Asn1Oid inhibitAnyPolicy = OIDs.initOid("2.5.29.54", "inhibitAnyPolicy");

  public static final Asn1Oid authorityInfoAccess = OIDs.initOid(
      "1.3.6.1.5.5.7.1.1", "authorityInfoAccess");

  public static final Asn1Oid subjectInfoAccess = OIDs.initOid(
      "1.3.6.1.5.5.7.1.11", "subjectInfoAccess");

  public static final Asn1Oid biometricInfo = OIDs.initOid("1.3.6.1.5.5.7.1.2", "biometricInfo");

  public static final Asn1Oid qCStatements = OIDs.initOid("1.3.6.1.5.5.7.1.3", "qCStatements");

  public static final Asn1Oid noRevAvail = OIDs.initOid("2.5.29.56", "noRevAvail");

  public static final Asn1Oid expiredCertsOnCRL = OIDs.initOid(
      "2.5.29.60", "expiredCertsOnCRL");

  public static final Asn1Oid IPAddrBlocks = OIDs.initOid("1.3.6.1.5.5.7.1.7", "IPAddrBlocks");

  public static final Asn1Oid ASIdentifiers = OIDs.initOid("1.3.6.1.5.5.7.1.8", "ASIdentifiers");

  public static final Asn1Oid IPAddrBlocksV2 = OIDs.initOid(
      "1.3.6.1.5.5.7.1.28", "IPAddrBlocksV2");

  public static final Asn1Oid ASIdentifiersV2 = OIDs.initOid(
      "1.3.6.1.5.5.7.1.29", "ASIdentifiersV2");

  public static final Asn1Oid id_pkix_ocsp_prefSigAlgs = OcspOIDs.id_pkix_ocsp_pref_sig_algs;

  public static final Asn1Oid id_pkix_ocsp_extendedRevoke = OcspOIDs.id_pkix_ocsp_extended_revoke;

  public static final Asn1Oid id_pkix_ocsp_nonce = OcspOIDs.id_pkix_ocsp_nonce;

  public static final Asn1Oid id_pkix_ocsp_nocheck = OcspOIDs.id_pkix_ocsp_nocheck;

  public static final Asn1Oid id_ad_timeStamping = OIDs.initOid(
      "1.3.6.1.5.5.7.48.3", "id-ad-timeStamping");

  public static final Asn1Oid id_ad_caRepository = OIDs.initOid(
      "1.3.6.1.5.5.7.48.5", "id-ad-caRepository");

  public static final Asn1Oid id_pe_tlsfeature = OIDs.initOid(
      "1.3.6.1.5.5.7.1.24", "id-pe-tlsfeature");

  public static final Asn1Oid id_dmtf_spdm_extension = SpdmOIDs.id_DMTF_SPDM_extension;

  public static final Asn1Oid id_smimeCapabilities = PkcsOIDs.pkcs9_at_smimeCapabilities;

  public static final Asn1Oid id_ce_subjectAltPublicKeyInfo = OIDs.initOid(
        "2.5.29.72", "id-ce-subjectAltPublicKeyInfo");

  public static final Asn1Oid id_ce_altSignatureAlgorithm = OIDs.initOid(
        "2.5.29.73", "id-ce-altSignatureAlgorithm");

  public static final Asn1Oid id_ce_altSignatureValue = OIDs.initOid(
        "2.5.29.74", "id-ce-altSignatureValue");

  public static final Asn1Oid id_precertificate = OIDs.initOid(
      "1.3.6.1.4.1.11129.2.4.3", "id-precertificate");

  public static final Asn1Oid id_SignedCertificateTimestampList = OIDs.initOid(
      "1.3.6.1.4.1.11129.2.4.2", "id-SignedCertificateTimestampList");

  public static final Asn1Oid id_ccc_extn = OIDs.initOid(
      "1.3.6.1.4.1.41577.5", "id-ccc-extn");

  public static final Asn1Oid id_ccc_K_Vehicle_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.1", "id-ccc-K-Vehicle-Cert");

  public static final Asn1Oid id_ccc_F_External_CA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.2", "id-ccc-F-External-CA-Cert");

  public static final Asn1Oid id_ccc_E_Instance_CA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.3", "id-ccc-E-Instance-CA-Cert");

  public static final Asn1Oid id_ccc_H_Endpoint_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.4", "id-ccc-H-Endpoint-Cert");

  public static final Asn1Oid id_ccc_P_VehicleOEM_Enc_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.5", "id-ccc-P-VehicleOEM-Enc-Cert");

  public static final Asn1Oid id_ccc_Q_VehicleOEM_Sig_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.6", "id-ccc-Q-VehicleOEM-Sig-Cert");

  public static final Asn1Oid id_ccc_Device_Enc_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.7", "id-ccc-Device-Enc-Cert");

  public static final Asn1Oid id_ccc_Vehicle_Intermediate_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.8", "id-ccc-Vehicle-Intermediate-Cert");

  public static final Asn1Oid id_ccc_J_VehicleOEM_CA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.9", "id-ccc-J-VehicleOEM-CA-Cert");

  public static final Asn1Oid id_ccc_M_VehicleOEM_CA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.10", "id-ccc-M-VehicleOEM-CA-Cert");

  public static final Asn1Oid id_ccc_R_CertificationBody_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.14", "id-ccc-R-CertificationBody-Cert");

  public static final Asn1Oid id_ccc_S_SBxDKis_Intermediate_CA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.15", "id-ccc-S-SBxDKis-Intermediate-CA-Cert");

  public static final Asn1Oid id_ccc_T_SBxDKis_Endpoint_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.16", "id-ccc-T-SBxDKis-Endpoint-Cert");

  public static final Asn1Oid id_ccc_U_SBxDKis_RootCA_Cert = OIDs.initOid(
      "1.3.6.1.4.1.41577.5.17", "id-ccc-U-SBxDKis-RootCA-Cert");

  public static final Asn1Oid id_microsoft_CertificateTemplateName = OIDs.initOid(
      "1.3.6.1.4.1.311.20.2", "id-microsoft-CertificateTemplateName");

  public static final Asn1Oid id_microsoft_CertificateTemplateInformation = OIDs.initOid(
      "1.3.6.1.4.1.311.21.7", "id-microsoft-CertificateTemplateInformation");

  public static final Asn1Oid id_microsoft_SecurityIdentifier = OIDs.initOid(
      "1.3.6.1.4.1.311.25.2", "id-microsoft-SecurityIdentifier");

  public static final Asn1Oid id_microsoft_objectSid = OIDs.initOid(
      "1.3.6.1.4.1.311.25.2.1", "id-microsoft-objectSid");

  public static final Asn1Oid id_cn_residentIdCardNumber = OIDs.initOid(
      "1.2.156.10260.4.1.1.1", "id-cn-residentIdCardNumber");

  public static final Asn1Oid id_cn_passportNumber = OIDs.initOid(
      "1.2.156.10260.4.1.1.2", "id-cn-passportNumber");

  public static final Asn1Oid id_cn_socialInsuranceNumber = OIDs.initOid(
      "1.2.156.10260.4.1.2", "id-cn-socialInsuranceNumber");

  public static final Asn1Oid id_cn_unifiedSocialCreditCode = OIDs.initOid(
      "1.2.156.10260.4.4.4", "id-cn-unifiedSocialCreditCode");

  public static final Asn1Oid id_pe_JWTClaimConstraints = OIDs.initOid(
      "1.3.6.1.5.5.7.1.27", "id-pe-JWTClaimConstraints");

  public static final Asn1Oid id_pe_TNAuthList = OIDs.initOid(
      "1.3.6.1.5.5.7.1.26", "id-pe-TNAuthList");

  public static final Asn1Oid id_pe_masa_url = OIDs.initOid(
      "1.3.6.1.5.5.7.1.32", "id-pe-masa-url");

  public static final Asn1Oid tcg_dice_ueid = DiceOIDs.tcg_dice_ueid;

  public static final Asn1Oid isismtt_at_certHash = OIDs.initOid(
      "1.3.36.8.3.13", "isismtt-at-certHash");

}
