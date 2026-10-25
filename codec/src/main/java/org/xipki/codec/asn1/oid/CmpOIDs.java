// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class CmpOIDs {

  public static final Asn1Oid passwordBasedMac = OIDs.initOid(
      "1.2.840.113533.7.66.13", "passwordBasedMac");
  public static final Asn1Oid id_regCtrl = OIDs.initOid("1.3.6.1.5.5.7.5.1", "id-regCtrl");
  public static final Asn1Oid id_regCtrl_regToken = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.1", "id-regCtrl-regToken");
  public static final Asn1Oid id_regCtrl_authenticator = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.2", "id-regCtrl-authenticator");
  public static final Asn1Oid id_regCtrl_pkiPublicationInfo = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.3", "id-regCtrl-pkiPublicationInfo");
  public static final Asn1Oid id_regCtrl_pkiArchiveOptions = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.4", "id-regCtrl-pkiArchiveOptions");
  public static final Asn1Oid id_regCtrl_oldCertID = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.5", "id-regCtrl-oldCertID");
  public static final Asn1Oid id_regCtrl_protocolEncrKey = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.6", "id-regCtrl-protocolEncrKey");
  public static final Asn1Oid id_regInfo = OIDs.initOid("1.3.6.1.5.5.7.5.2", "id-regInfo");
  public static final Asn1Oid id_regInfo_utf8Pairs = OIDs.initOid(
      "1.3.6.1.5.5.7.5.2.1", "id-regInfo-utf8Pairs");
  public static final Asn1Oid id_regInfo_certReq = OIDs.initOid(
      "1.3.6.1.5.5.7.5.2.2", "id-regInfo-certReq");
  public static final Asn1Oid id_ct_encKeyWithID = OIDs.initOid(
      "1.2.840.113549.1.9.16.1.21", "id-ct-encKeyWithID");
  public static final Asn1Oid id_dh_sig_hmac_sha1 = OIDs.initOid(
      "1.3.6.1.5.5.7.6.3", "id-dh-sig-hmac-sha1");
  public static final Asn1Oid id_alg_dh_pop = OIDs.initOid("1.3.6.1.5.5.7.6.4", "id-alg-dh-pop");

  private CmpOIDs() {
  }

  public static final Asn1Oid kemBasedMac = OIDs.initOid("1.2.840.113533.7.66.16", "kemBasedMac");

  public static final Asn1Oid dhBasedMac = OIDs.initOid("1.2.840.113533.7.66.30", "dhBasedMac");

  public static final Asn1Oid it_caProtEncCert = OIDs.initOid(
      "1.3.6.1.5.5.7.4.1", "it-caProtEncCert");

  public static final Asn1Oid it_signKeyPairTypes = OIDs.initOid(
      "1.3.6.1.5.5.7.4.2", "it-signKeyPairTypes");

  public static final Asn1Oid it_encKeyPairTypes = OIDs.initOid(
      "1.3.6.1.5.5.7.4.3", "it-encKeyPairTypes");

  public static final Asn1Oid it_preferredSymAlg = OIDs.initOid(
      "1.3.6.1.5.5.7.4.4", "it-preferredSymAlg");

  public static final Asn1Oid it_caKeyUpdateInfo = OIDs.initOid(
      "1.3.6.1.5.5.7.4.5", "it-caKeyUpdateInfo");

  public static final Asn1Oid it_currentCRL = OIDs.initOid("1.3.6.1.5.5.7.4.6", "it-currentCRL");

  public static final Asn1Oid it_unsupportedOIDs = OIDs.initOid(
      "1.3.6.1.5.5.7.4.7", "it-unsupportedOIDs");

  public static final Asn1Oid it_keyPairParamReq = OIDs.initOid(
      "1.3.6.1.5.5.7.4.10", "it-keyPairParamReq");

  public static final Asn1Oid it_keyPairParamRep = OIDs.initOid(
      "1.3.6.1.5.5.7.4.11", "it-keyPairParamRep");

  public static final Asn1Oid it_revPassphrase = OIDs.initOid(
      "1.3.6.1.5.5.7.4.12", "it-revPassphrase");

  public static final Asn1Oid it_implicitConfirm = OIDs.initOid(
      "1.3.6.1.5.5.7.4.13", "it-implicitConfirm");

  public static final Asn1Oid it_confirmWaitTime = OIDs.initOid(
      "1.3.6.1.5.5.7.4.14", "it-confirmWaitTime");

  public static final Asn1Oid it_origPKIMessage = OIDs.initOid(
      "1.3.6.1.5.5.7.4.15", "it-origPKIMessage");

  public static final Asn1Oid it_suppLangTags = OIDs.initOid(
      "1.3.6.1.5.5.7.4.16", "it-suppLangTags");

  public static final Asn1Oid id_it_caCerts = OIDs.initOid("1.3.6.1.5.5.7.4.17", "id-it-caCerts");

  public static final Asn1Oid id_it_rootCaKeyUpdate = OIDs.initOid(
      "1.3.6.1.5.5.7.4.18", "id-it-rootCaKeyUpdate");

  public static final Asn1Oid id_it_certReqTemplate = OIDs.initOid(
      "1.3.6.1.5.5.7.4.19", "id-it-certReqTemplate");

  public static final Asn1Oid id_it_rootCaCert = OIDs.initOid(
      "1.3.6.1.5.5.7.4.20", "id-it-rootCaCert");

  public static final Asn1Oid id_it_certProfile = OIDs.initOid(
      "1.3.6.1.5.5.7.4.21", "id-it-certProfile");

  public static final Asn1Oid id_it_crlStatusList = OIDs.initOid(
      "1.3.6.1.5.5.7.4.22", "id-it-crlStatusList");

  public static final Asn1Oid id_it_crls = OIDs.initOid("1.3.6.1.5.5.7.4.23", "id-it-crls");

  public static final Asn1Oid regCtrl_altCertTemplate = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.7", "regCtrl-altCertTemplate");

  public static final Asn1Oid id_regCtrl_algId = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.11", "id-regCtrl-algId");

  public static final Asn1Oid id_regCtrl_rsaKeyLen = OIDs.initOid(
      "1.3.6.1.5.5.7.5.1.12", "id-regCtrl-rsaKeyLen");

}
