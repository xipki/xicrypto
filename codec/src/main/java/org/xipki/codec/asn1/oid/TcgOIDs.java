// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class TcgOIDs {

  private TcgOIDs() {
  }

  public static final Asn1Oid tcg_ca = OIDs.initOid("2.23.133.11", "tcg-ca");

  public static final Asn1Oid tcg_ca_policy = OIDs.initOid("2.23.133.11.1", "tcg-ca-policy");

  public static final Asn1Oid tcg_address = OIDs.initOid("2.23.133.17", "tcg-address");

  public static final Asn1Oid tcg_registry = OIDs.initOid("2.23.133.18", "tcg-registry");

  public static final Asn1Oid tcg_traits = OIDs.initOid("2.23.133.19", "tcg-traits");

  public static final Asn1Oid tcg_common = OIDs.initOid("2.23.133.5.1", "tcg-common");

  public static final Asn1Oid tcg_at_platformConfiguration = OIDs.initOid(
      "2.23.133.5.1.7", "tcg-at-platformConfiguration");

  public static final Asn1Oid tcg_at_tcgPlatformSpecification = OIDs.initOid(
      "2.23.133.2.17", "tcg-at-tcgPlatformSpecification");

  public static final Asn1Oid tcg_at_tcgCredentialSpecification = OIDs.initOid(
      "2.23.133.2.23", "tcg-at-tcgCredentialSpecification");

  public static final Asn1Oid tcg_at_tcgCredentialType = OIDs.initOid(
      "2.23.133.2.25", "tcg-at-tcgCredentialType");

  public static final Asn1Oid tcg_kp_PlatformAttributeCertificate = OIDs.initOid(
      "2.23.133.8.2", "tcg-kp-PlatformAttributeCertificate");

  public static final Asn1Oid tcg_kp_PlatformKeyCertificate = OIDs.initOid(
      "2.23.133.8.4", "tcg-kp-PlatformKeyCertificate");

  public static final Asn1Oid tcg_kp_DeltaPlatformAttributeCertificate = OIDs.initOid(
      "2.23.133.8.5", "tcg-kp-DeltaPlatformAttributeCertificate");

  public static final Asn1Oid tcg_address_ethernetmac = OIDs.initOid(
      "2.23.133.17.1", "tcg-address-ethernetmac");

  public static final Asn1Oid tcg_address_wlanmac = OIDs.initOid(
      "2.23.133.17.2", "tcg-address-wlanmac");

  public static final Asn1Oid tcg_address_bluetoothmac = OIDs.initOid(
      "2.23.133.17.3", "tcg-address-bluetoothmac");

  public static final Asn1Oid tcg_registry_componentClass = OIDs.initOid(
      "2.23.133.18.3", "tcg-registry-componentClass");

  public static final Asn1Oid tcg_registry_componentClass_pcie = OIDs.initOid(
      "2.23.133.18.4", "tcg-registry-componentClass-pcie");

  public static final Asn1Oid tcg_registry_componentClass_disk = OIDs.initOid(
      "2.23.133.18.5", "tcg-registry-componentClass-disk");

  public static final Asn1Oid tcg_at_platformIdentifier = OIDs.initOid(
      "2.23.133.5.1.8", "tcg-at-platformIdentifier");

  public static final Asn1Oid tcg_at_platformConfiguration_v3 = OIDs.initOid(
      "2.23.133.5.1.7.3", "tcg-at-platformConfiguration-v3");

  public static final Asn1Oid tcg_at_platformConfigUri_v3 = OIDs.initOid(
      "2.23.133.5.1.7.4", "tcg-at-platformConfigUri-v3");

  public static final Asn1Oid tcg_at_previousPlatformCertificates = OIDs.initOid(
      "2.23.133.2.26", "tcg-at-previousPlatformCertificates");

  public static final Asn1Oid tcg_at_tbbSecurityAssertions_v3 = OIDs.initOid(
      "2.23.133.2.27", "tcg-at-tbbSecurityAssertions-v3");

  public static final Asn1Oid tcg_at_cryptographicAnchors = OIDs.initOid(
      "2.23.133.2.28", "tcg-at-cryptographicAnchors");

  public static final Asn1Oid tcg_at_platformOwnership = OIDs.initOid(
      "2.23.133.2.29", "tcg-at-platformOwnership");

  public static final Asn1Oid tcg_at_manufacturingAssertions = OIDs.initOid(
      "2.23.133.2.30", "tcg-at-manufacturingAssertions");

  public static final Asn1Oid tcg_kp_DeltaPlatformKeyCertificate = OIDs.initOid(
      "2.23.133.8.6", "tcg-kp-DeltaPlatformKeyCertificate");

  public static final Asn1Oid tcg_kp_AdditionalPlatformAttributeCertificate = OIDs.initOid(
      "2.23.133.8.7", "tcg-kp-AdditionalPlatformAttributeCertificate");

  public static final Asn1Oid tcg_kp_AdditionalPlatformKeyCertificate = OIDs.initOid(
      "2.23.133.8.8", "tcg-kp-AdditionalPlatformKeyCertificate");

  public static final Asn1Oid tcg_cap_verifiedPlatformCertificate = OIDs.initOid(
      "2.23.133.11.1.4", "tcg-cap-verifiedPlatformCertificate");

  public static final Asn1Oid tcg_registry_componentClass_tcg = OIDs.initOid(
      "2.23.133.18.3.1", "tcg-registry-componentClass-tcg");

  public static final Asn1Oid tcg_registry_componentClass_ietf = OIDs.initOid(
      "2.23.133.18.3.2", "tcg-registry-componentClass-ietf");

  public static final Asn1Oid tcg_registry_componentClass_dmtf = OIDs.initOid(
      "2.23.133.18.3.3", "tcg-registry-componentClass-dmtf");

  public static final Asn1Oid tcg_tr_ID = OIDs.initOid("2.23.133.19.1", "tcg-tr-ID");

  public static final Asn1Oid tcg_tr_ID_Boolean = OIDs.initOid(
      "2.23.133.19.1.1", "tcg-tr-ID-Boolean");

  public static final Asn1Oid tcg_tr_ID_certificateIdentifier = OIDs.initOid(
      "2.23.133.19.1.2", "tcg-tr-ID-certificateIdentifier");

  public static final Asn1Oid tcg_tr_ID_CommonCriteria = OIDs.initOid(
      "2.23.133.19.1.3", "tcg-tr-ID-CommonCriteria");

  public static final Asn1Oid tcg_tr_ID_componentClass = OIDs.initOid(
      "2.23.133.19.1.4", "tcg-tr-ID-componentClass");

  public static final Asn1Oid tcg_tr_ID_componentIdentifierV11 = OIDs.initOid(
      "2.23.133.19.1.5", "tcg-tr-ID-componentIdentifierV11");

  public static final Asn1Oid tcg_tr_ID_FIPSLevel = OIDs.initOid(
      "2.23.133.19.1.6", "tcg-tr-ID-FIPSLevel");

  public static final Asn1Oid tcg_tr_ID_ISO9000Level = OIDs.initOid(
      "2.23.133.19.1.7", "tcg-tr-ID-ISO9000Level");

  public static final Asn1Oid tcg_tr_ID_networkMAC = OIDs.initOid(
      "2.23.133.19.1.8", "tcg-tr-ID-networkMAC");

  public static final Asn1Oid tcg_tr_ID_OID = OIDs.initOid(
      "2.23.133.19.1.9", "tcg-tr-ID-OID");

  public static final Asn1Oid tcg_tr_ID_PEN = OIDs.initOid(
      "2.23.133.19.1.10", "tcg-tr-ID-PEN");

  public static final Asn1Oid tcg_tr_ID_platformFirmwareCapabilities = OIDs.initOid(
      "2.23.133.19.1.11", "tcg-tr-ID-platformFirmwareCapabilities");

  public static final Asn1Oid tcg_tr_ID_platformFirmwareSignatureVerification = OIDs.initOid(
      "2.23.133.19.1.12", "tcg-tr-ID-platformFirmwareSignatureVerification");

  public static final Asn1Oid tcg_tr_ID_platformFirmwareUpdateCompliance = OIDs.initOid(
      "2.23.133.19.1.13", "tcg-tr-ID-platformFirmwareUpdateCompliance");

  public static final Asn1Oid tcg_tr_ID_platformHardwareCapabilities = OIDs.initOid(
      "2.23.133.19.1.14", "tcg-tr-ID-platformHardwareCapabilities");

  public static final Asn1Oid tcg_tr_ID_RTM = OIDs.initOid("2.23.133.19.1.15", "tcg-tr-ID-RTM");

  public static final Asn1Oid tcg_tr_ID_status = OIDs.initOid(
      "2.23.133.19.1.16", "tcg-tr-ID-status");

  public static final Asn1Oid tcg_tr_ID_URI = OIDs.initOid("2.23.133.19.1.17", "tcg-tr-ID-URI");

  public static final Asn1Oid tcg_tr_ID_UTF8String = OIDs.initOid(
      "2.23.133.19.1.18", "tcg-tr-ID-UTF8String");

  public static final Asn1Oid tcg_tr_ID_IA5String = OIDs.initOid(
      "2.23.133.19.1.19", "tcg-tr-ID-IA5String");

  public static final Asn1Oid tcg_tr_ID_PEMCertString = OIDs.initOid(
      "2.23.133.19.1.20", "tcg-tr-ID-PEMCertString");

  public static final Asn1Oid tcg_tr_ID_PublicKey = OIDs.initOid(
      "2.23.133.19.1.21", "tcg-tr-ID-PublicKey");

  public static final Asn1Oid tcg_tr_category = OIDs.initOid("2.23.133.19.2", "tcg-tr-category");

  public static final Asn1Oid tcg_tr_cat_platformManufacturer = OIDs.initOid(
      "2.23.133.19.2.1", "tcg-tr-cat-platformManufacturer");

  public static final Asn1Oid tcg_tr_cat_platformModel = OIDs.initOid(
      "2.23.133.19.2.2", "tcg-tr-cat-platformModel");

  public static final Asn1Oid tcg_tr_cat_platformVersion = OIDs.initOid(
      "2.23.133.19.2.3", "tcg-tr-cat-platformVersion");

  public static final Asn1Oid tcg_tr_cat_platformSerial = OIDs.initOid(
      "2.23.133.19.2.4", "tcg-tr-cat-platformSerial");

  public static final Asn1Oid tcg_tr_cat_platformManufacturerIdentifier = OIDs.initOid(
      "2.23.133.19.2.5", "tcg-tr-cat-platformManufacturerIdentifier");

  public static final Asn1Oid tcg_tr_cat_platformOwnership = OIDs.initOid(
      "2.23.133.19.2.6", "tcg-tr-cat-platformOwnership");

  public static final Asn1Oid tcg_tr_cat_componentClass = OIDs.initOid(
      "2.23.133.19.2.7", "tcg-tr-cat-componentClass");

  public static final Asn1Oid tcg_tr_cat_componentManufacturer = OIDs.initOid(
      "2.23.133.19.2.8", "tcg-tr-cat-componentManufacturer");

  public static final Asn1Oid tcg_tr_cat_componentModel = OIDs.initOid(
      "2.23.133.19.2.9", "tcg-tr-cat-componentModel");

  public static final Asn1Oid tcg_tr_cat_componentSerial = OIDs.initOid(
      "2.23.133.19.2.10", "tcg-tr-cat-componentSerial");

  public static final Asn1Oid tcg_tr_cat_componentStatus = OIDs.initOid(
      "2.23.133.19.2.11", "tcg-tr-cat-componentStatus");

  public static final Asn1Oid tcg_tr_cat_componentLocation = OIDs.initOid(
      "2.23.133.19.2.12", "tcg-tr-cat-componentLocation");

  public static final Asn1Oid tcg_tr_cat_componentRevision = OIDs.initOid(
      "2.23.133.19.2.13", "tcg-tr-cat-componentRevision");

  public static final Asn1Oid tcg_tr_cat_componentFieldReplaceable = OIDs.initOid(
      "2.23.133.19.2.14", "tcg-tr-cat-componentFieldReplaceable");

  public static final Asn1Oid tcg_tr_cat_EKCertificate = OIDs.initOid(
      "2.23.133.19.2.15", "tcg-tr-cat-EKCertificate");

  public static final Asn1Oid tcg_tr_cat_IAKCertificate = OIDs.initOid(
      "2.23.133.19.2.16", "tcg-tr-cat-IAKCertificate");

  public static final Asn1Oid tcg_tr_cat_IDevIDCertificate = OIDs.initOid(
      "2.23.133.19.2.17", "tcg-tr-cat-IDevIDCertificate");

  public static final Asn1Oid tcg_tr_cat_DICECertificate = OIDs.initOid(
      "2.23.133.19.2.18", "tcg-tr-cat-DICECertificate");

  public static final Asn1Oid tcg_tr_cat_SPDMCertificate = OIDs.initOid(
      "2.23.133.19.2.19", "tcg-tr-cat-SPDMCertificate");

  public static final Asn1Oid tcg_tr_cat_PEMCertificate = OIDs.initOid(
      "2.23.133.19.2.20", "tcg-tr-cat-PEMCertificate");

  public static final Asn1Oid tcg_tr_cat_PlatformCertificate = OIDs.initOid(
      "2.23.133.19.2.21", "tcg-tr-cat-PlatformCertificate");

  public static final Asn1Oid tcg_tr_cat_DeltaPlatformCertificate = OIDs.initOid(
      "2.23.133.19.2.22", "tcg-tr-cat-DeltaPlatformCertificate");

  public static final Asn1Oid tcg_tr_cat_RebasePlatformCertificate = OIDs.initOid(
      "2.23.133.19.2.23", "tcg-tr-cat-RebasePlatformCertificate");

  public static final Asn1Oid tcg_tr_cat_genericCertificate = OIDs.initOid(
      "2.23.133.19.2.24", "tcg-tr-cat-genericCertificate");

  public static final Asn1Oid tcg_tr_cat_CommonCriteria = OIDs.initOid(
      "2.23.133.19.2.25", "tcg-tr-cat-CommonCriteria");

  public static final Asn1Oid tcg_tr_cat_componentIdentifierV11 = OIDs.initOid(
      "2.23.133.19.2.26", "tcg-tr-cat-componentIdentifierV11");

  public static final Asn1Oid tcg_tr_cat_FIPSLevel = OIDs.initOid(
      "2.23.133.19.2.27", "tcg-tr-cat-FIPSLevel");

  public static final Asn1Oid tcg_tr_cat_ISO9000 = OIDs.initOid(
      "2.23.133.19.2.28", "tcg-tr-cat-ISO9000");

  public static final Asn1Oid tcg_tr_cat_networkMAC = OIDs.initOid(
      "2.23.133.19.2.29", "tcg-tr-cat-networkMAC");

  public static final Asn1Oid tcg_tr_cat_attestationProtocol = OIDs.initOid(
      "2.23.133.19.2.30", "tcg-tr-cat-attestationProtocol");

  public static final Asn1Oid tcg_tr_cat_PEN = OIDs.initOid(
      "2.23.133.19.2.31", "tcg-tr-cat-PEN");

  public static final Asn1Oid tcg_tr_cat_platformFirmwareCapabilities = OIDs.initOid(
      "2.23.133.19.2.32", "tcg-tr-cat-platformFirmwareCapabilities");

  public static final Asn1Oid tcg_tr_cat_platformHardwareCapabilities = OIDs.initOid(
      "2.23.133.19.2.33", "tcg-tr-cat-platformHardwareCapabilities");

  public static final Asn1Oid tcg_tr_cat_platformFirmwareSignatureVerification = OIDs.initOid(
      "2.23.133.19.2.34", "tcg-tr-cat-platformFirmwareSignatureVerification");

  public static final Asn1Oid tcg_tr_cat_platformFirmwareUpdateCompliance = OIDs.initOid(
      "2.23.133.19.2.35", "tcg-tr-cat-platformFirmwareUpdateCompliance");

  public static final Asn1Oid tcg_tr_cat_RTM = OIDs.initOid(
      "2.23.133.19.2.36", "tcg-tr-cat-RTM");

  public static final Asn1Oid tcg_tr_cat_PublicKey = OIDs.initOid(
      "2.23.133.19.2.37", "tcg-tr-cat-PublicKey");

  public static final Asn1Oid tcg_tr_registry = OIDs.initOid(
      "2.23.133.19.3", "tcg-tr-registry");

  public static final Asn1Oid tcg_tr_reg_none = OIDs.initOid(
      "2.23.133.19.3.1", "tcg-tr-reg-none");

}
