// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class KeyPurposeOIDs {

  private KeyPurposeOIDs() {
  }

  public static final Asn1Oid anyExtendedKeyUsage = OIDs.initOid(
      "2.5.29.37.0", "anyExtendedKeyUsage");

  public static final Asn1Oid id_kp_serverAuth = OIDs.initOid(
      "1.3.6.1.5.5.7.3.1", "id-kp-serverAuth");

  public static final Asn1Oid id_kp_clientAuth = OIDs.initOid(
      "1.3.6.1.5.5.7.3.2", "id-kp-clientAuth");

  public static final Asn1Oid id_kp_codeSigning = OIDs.initOid(
      "1.3.6.1.5.5.7.3.3", "id-kp-codeSigning");

  public static final Asn1Oid id_kp_emailProtection = OIDs.initOid(
      "1.3.6.1.5.5.7.3.4", "id-kp-emailProtection");

  public static final Asn1Oid id_kp_ipsecEndSystem = OIDs.initOid(
      "1.3.6.1.5.5.7.3.5", "id-kp-ipsecEndSystem");

  public static final Asn1Oid id_kp_ipsecTunnel = OIDs.initOid(
      "1.3.6.1.5.5.7.3.6", "id-kp-ipsecTunnel");

  public static final Asn1Oid id_kp_ipsecUser = OIDs.initOid(
      "1.3.6.1.5.5.7.3.7", "id-kp-ipsecUser");

  public static final Asn1Oid id_kp_timeStamping = OIDs.initOid(
      "1.3.6.1.5.5.7.3.8", "id-kp-timeStamping");

  public static final Asn1Oid id_kp_OCSPSigning = OIDs.initOid(
      "1.3.6.1.5.5.7.3.9", "id-kp-OCSPSigning");

  public static final Asn1Oid id_kp_dvcs = OIDs.initOid("1.3.6.1.5.5.7.3.10", "id-kp-dvcs");

  public static final Asn1Oid id_kp_sbgpCertAAServerAuth = OIDs.initOid(
      "1.3.6.1.5.5.7.3.11", "id-kp-sbgpCertAAServerAuth");

  public static final Asn1Oid id_kp_scvp_responder = OIDs.initOid(
      "1.3.6.1.5.5.7.3.12", "id-kp-scvp-responder");

  public static final Asn1Oid id_kp_eapOverPPP = OIDs.initOid(
      "1.3.6.1.5.5.7.3.13", "id-kp-eapOverPPP");

  public static final Asn1Oid id_kp_eapOverLAN = OIDs.initOid(
      "1.3.6.1.5.5.7.3.14", "id-kp-eapOverLAN");

  public static final Asn1Oid id_kp_scvpServer = OIDs.initOid(
      "1.3.6.1.5.5.7.3.15", "id-kp-scvpServer");

  public static final Asn1Oid id_kp_scvpClient = OIDs.initOid(
      "1.3.6.1.5.5.7.3.16", "id-kp-scvpClient");

  public static final Asn1Oid id_kp_ipsecIKE = OIDs.initOid(
      "1.3.6.1.5.5.7.3.17", "id-kp-ipsecIKE");

  public static final Asn1Oid id_kp_capwapAC = OIDs.initOid(
      "1.3.6.1.5.5.7.3.18", "id-kp-capwapAC");

  public static final Asn1Oid id_kp_capwapWTP = OIDs.initOid(
      "1.3.6.1.5.5.7.3.19", "id-kp-capwapWTP");

  public static final Asn1Oid id_kp_cmcCA = OIDs.initOid(
      "1.3.6.1.5.5.7.3.27", "id-kp-cmcCA");

  public static final Asn1Oid id_kp_cmcRA = OIDs.initOid(
      "1.3.6.1.5.5.7.3.28", "id-kp-cmcRA");

  public static final Asn1Oid id_kp_cmKGA = OIDs.initOid(
      "1.3.6.1.5.5.7.3.32", "id-kp-cmKGA");

  public static final Asn1Oid id_kp_smartcardlogon = OIDs.initOid(
      "1.3.6.1.4.1.311.20.2.2", "id-kp-smartcardlogon");

  public static final Asn1Oid id_kp_macAddress = OIDs.initOid(
      "1.3.6.1.1.1.1.22", "id-kp-macAddress");

  public static final Asn1Oid id_kp_msSGC = OIDs.initOid(
      "1.3.6.1.4.1.311.10.3.3", "id-kp-msSGC");

  public static final Asn1Oid id_kp_nsSGC = OIDs.initOid(
      "2.16.840.1.113730.4.1", "id-kp-nsSGC");

  public static final Asn1Oid id_kp_etsiTslSigning = OIDs.initOid(
        "0.4.0.2231.3.0", "id-kp-etsiTslSigning");

  public static final Asn1Oid id_kp_icaoMasterListSigning = OIDs.initOid(
      "2.23.136.1.1.3", "id-kp-icaoMasterListSigning");

  /**
   * Intel AMT management.
   */
  public static final Asn1Oid id_kp_intelAmtManagement = OIDs.initOid(
      "2.16.840.1.113741.1.2.3", "id-kp-intelAmtManagement");

  /**
   * Kerberos Client Authentication.
   */
  public static final Asn1Oid id_kp_kerberosClientAuthentication = OIDs.initOid(
          "1.3.6.1.5.2.3.4", "id-kp-kerberosClientAuthentication");

  /**
   * Kerberos Key Distribution Center.
   */
  public static final Asn1Oid id_kp_kerberosKdc = OIDs.initOid(
      "1.3.6.1.5.2.3.5", "id-kp-kerberosKdc");

  /**
   * Microsoft Commercial Code Signing.
   */
  public static final Asn1Oid id_kp_microsoftCommercialCodeSigning = OIDs.initOid(
      "1.3.6.1.4.1.311.2.1.22", "id-kp-microsoftCommercialCodeSigning");

  /**
   * Microsoft Document Signing.
   */
  public static final Asn1Oid id_kp_microsoftDocumentSigning = OIDs.initOid(
      "1.3.6.1.4.1.311.10.3.12", "id-kp-microsoftDocumentSigning");

  /**
   * Microsoft Encrypted File System (EFS).
   */
  public static final Asn1Oid id_kp_microsoftEfs = OIDs.initOid(
      "1.3.6.1.4.1.311.10.3.4", "id-kp-microsoftEfs");

  /**
   * Microsoft EFS Recovery.
   */
  public static final Asn1Oid id_kp_microsoftEfsRecovery = OIDs.initOid(
      "1.3.6.1.4.1.311.10.3.4.1", "id-kp-microsoftEfsRecovery");

  /**
   * Microsoft Individual Code Signing.
   */
  public static final Asn1Oid id_kp_microsoftIndividualCodeSigning = OIDs.initOid(
      "1.3.6.1.4.1.311.2.1.21", "id-kp-microsoftIndividualCodeSigning");

  /**
   * PIV Card Authentication.
   */
  public static final Asn1Oid id_kp_pivCardAuthentication = OIDs.initOid(
      "2.16.840.1.101.3.6.8", "id-kp-pivCardAuthentication");

  /**
   * PDF Signing.
   */
  public static final Asn1Oid id_kp_pdfSigning = OIDs.initOid(
      "1.2.840.113583.1.1.5", "id-kp-pdfSigning");

  /**
   * SIP Domain.
   */
  public static final Asn1Oid id_kp_sipDomain = OIDs.initOid(
      "1.3.6.1.5.5.7.3.20", "id-kp-sipDomain");

  /**
   * SSH Client.
   */
  public static final Asn1Oid id_kp_sshClient = OIDs.initOid(
      "1.3.6.1.5.5.7.3.21", "id-kp-sshClient");

  /**
   * SSH Server.
   */
  public static final Asn1Oid id_kp_sshServer = OIDs.initOid(
      "1.3.6.1.5.5.7.3.22", "id-kp-sshServer");

  public static final Asn1Oid id_kp_appleSafariExtensionSigning = OIDs.initOid(
      "1.2.840.113635.100.4.8", "id-kp-appleSafariExtensionSigning");

  public static final Asn1Oid id_kp_macInstallerPackageSigning = OIDs.initOid(
      "1.2.840.113635.100.4.9", "id-kp-macInstallerPackageSigning");

  public static final Asn1Oid id_kp_macAppStoreInstallerPackageSigning = OIDs.initOid(
      "1.2.840.113635.100.4.10", "id-kp-macAppStoreInstallerPackageSigning");

  // Certificate Transparency (RFC 6962)
  public static final Asn1Oid id_kp_certificateTransparency = OIDs.initOid(
      "1.3.6.1.4.1.11129.2.4.4", "id-kp-certificateTransparency");

}
