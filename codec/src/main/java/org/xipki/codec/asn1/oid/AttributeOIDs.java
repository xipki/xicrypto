// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class AttributeOIDs {

  private AttributeOIDs() {
  }

  public static final Asn1Oid country = X509OIDs.countryName;

  public static final Asn1Oid organization = X509OIDs.organization;

  public static final Asn1Oid organizationIdentifier = X509OIDs.id_at_organizationIdentifier;

  public static final Asn1Oid organizationalUnit = X509OIDs.organizationalUnitName;

  public static final Asn1Oid title = OIDs.initOid("2.5.4.12", "title");

  public static final Asn1Oid commonName = X509OIDs.commonName;

  public static final Asn1Oid serialNumber = OIDs.initOid("2.5.4.5", "serialNumber");

  public static final Asn1Oid street = OIDs.initOid("2.5.4.9", "street");

  public static final Asn1Oid locality = X509OIDs.localityName;

  public static final Asn1Oid state = X509OIDs.stateOrProvinceName;

  public static final Asn1Oid surname = OIDs.initOid("2.5.4.4", "surname");

  public static final Asn1Oid givenName = OIDs.initOid("2.5.4.42", "givenName");

  public static final Asn1Oid initials = OIDs.initOid("2.5.4.43", "initials");

  public static final Asn1Oid generationQualifier = OIDs.initOid("2.5.4.44", "generationQualifier");

  public static final Asn1Oid businessCategory = OIDs.initOid("2.5.4.15", "businessCategory");

  public static final Asn1Oid postalCode = OIDs.initOid("2.5.4.17", "postalCode");

  public static final Asn1Oid dnQualifier = OIDs.initOid("2.5.4.46", "dnQualifier");

  public static final Asn1Oid pseudonym = OIDs.initOid("2.5.4.65", "pseudonym");

  public static final Asn1Oid dateOfBirth = OIDs.initOid("1.3.6.1.5.5.7.9.1", "dateOfBirth");

  public static final Asn1Oid placeOfBirth = OIDs.initOid("1.3.6.1.5.5.7.9.2", "placeOfBirth");

  public static final Asn1Oid gender = OIDs.initOid("1.3.6.1.5.5.7.9.3", "gender");

  public static final Asn1Oid countryOfCitizenship = OIDs.initOid(
      "1.3.6.1.5.5.7.9.4", "countryOfCitizenship");

  public static final Asn1Oid countryOfResidence = OIDs.initOid(
      "1.3.6.1.5.5.7.9.5", "countryOfResidence");

  public static final Asn1Oid nameAtBirth = OIDs.initOid("1.3.36.8.3.14", "nameAtBirth");

  public static final Asn1Oid postalAddress = OIDs.initOid("2.5.4.16", "postalAddress");

  public static final Asn1Oid dmdName = OIDs.initOid("2.5.4.54", "dmdName");

  public static final Asn1Oid telephoneNumber = X509OIDs.id_at_telephoneNumber;

  public static final Asn1Oid name = X509OIDs.id_at_name;

  public static final Asn1Oid emailAddress = PkcsOIDs.pkcs9_at_emailAddress;

  public static final Asn1Oid domainComponent = OIDs.initOid(
      "0.9.2342.19200300.100.1.25", "domainComponent");

  public static final Asn1Oid userid = OIDs.initOid("0.9.2342.19200300.100.1.1", "userid");

  public static final Asn1Oid jurIncorporationLocality = OIDs.initOid(
      "1.3.6.1.4.1.311.60.2.1.1", "jurIncorporationLocality");

  public static final Asn1Oid jurIncorporationState = OIDs.initOid(
      "1.3.6.1.4.1.311.60.2.1.2", "jurIncorporationState");

  public static final Asn1Oid jurIncorporationCountry = OIDs.initOid(
      "1.3.6.1.4.1.311.60.2.1.3", "jurIncorporationCountry");

  public static final Asn1Oid unstructuredName = PkcsOIDs.pkcs9_at_unstructuredName;

  public static final Asn1Oid unstructuredAddress = PkcsOIDs.pkcs9_at_unstructuredAddress;

  public static final Asn1Oid pkcs9_at_challengePassword = PkcsOIDs.pkcs9_at_challengePassword;

  public static final Asn1Oid pkcs9_at_extensionRequest = PkcsOIDs.pkcs9_at_extensionRequest;

  public static final Asn1Oid id_at_statementOfPossession = OIDs.initOid(
      "1.3.6.1.4.1.22112.2.1", "id-at-statementOfPossession");

  public static final Asn1Oid contentType = PkcsOIDs.pkcs9_at_contentType;

  public static final Asn1Oid messageDigest = PkcsOIDs.pkcs9_at_messageDigest;

  public static final Asn1Oid signingTime = PkcsOIDs.pkcs9_at_signingTime;

  public static final Asn1Oid binarySigningTime = PkcsOIDs.pkcs_9_at_binarySigningTime;

  public static final Asn1Oid contentHint = PkcsOIDs.id_aa_contentHint;

  public static final Asn1Oid pkcs_9_at_friendlyName = PkcsOIDs.pkcs9_at_friendlyName;

  public static final Asn1Oid pkcs_9_at_localKeyId = PkcsOIDs.pkcs9_at_localKeyId;

  public static final Asn1Oid id_aa_cmsAlgorithmProtect = PkcsOIDs.id_aa_cmsAlgorithmProtect;

  public static final Asn1Oid id_oracle_pkcs12_trusted_key_usage =
      MiscOIDs.id_oracle_pkcs12_trusted_key_usage;

  public static final Asn1Oid scep_transactionId = OIDs.initOid(
      "2.16.840.1.113733.1.9.7", "scep-transactionId");

  public static final Asn1Oid scep_messageType = OIDs.initOid(
      "2.16.840.1.113733.1.9.2", "scep-messageType");

  public static final Asn1Oid scep_pkiStatus = OIDs.initOid(
      "2.16.840.1.113733.1.9.3", "scep-pkiStatus");

  public static final Asn1Oid scep_failInfo = OIDs.initOid(
      "2.16.840.1.113733.1.9.4", "scep-failInfo");

  public static final Asn1Oid scep_senderNonce = OIDs.initOid(
      "2.16.840.1.113733.1.9.5", "scep-senderNonce");

  public static final Asn1Oid scep_recipientNonce = OIDs.initOid(
      "2.16.840.1.113733.1.9.6", "scep-recipientNonce");

  public static final Asn1Oid scep_failInfoText = OIDs.initOid(
      "1.3.6.1.5.5.7.24.1", "scep-failInfoText");

  public static final Asn1Oid id_cmc_changeSubjectName = OIDs.initOid(
      "1.3.6.1.5.5.7.7.36", "id-cmc-changeSubjectName");

}
