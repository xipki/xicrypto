// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class X509OIDs {

  private X509OIDs() {
  }

  public static final Asn1Oid attributeType = OIDs.initOid("2.5.4", "attributeType");

  public static final Asn1Oid commonName = OIDs.initOid("2.5.4.3", "commonName");

  public static final Asn1Oid countryName = OIDs.initOid("2.5.4.6", "countryName");

  public static final Asn1Oid localityName = OIDs.initOid("2.5.4.7", "localityName");

  public static final Asn1Oid stateOrProvinceName = OIDs.initOid("2.5.4.8", "stateOrProvinceName");

  public static final Asn1Oid organization = OIDs.initOid("2.5.4.10", "organization");

  public static final Asn1Oid organizationalUnitName = OIDs.initOid(
      "2.5.4.11", "organizationalUnitName");

  public static final Asn1Oid id_at_telephoneNumber = OIDs.initOid(
      "2.5.4.20", "id-at-telephoneNumber");

  public static final Asn1Oid id_at_name = OIDs.initOid("2.5.4.41", "id-at-name");

  public static final Asn1Oid id_at_organizationIdentifier = OIDs.initOid(
      "2.5.4.97", "id-at-organizationIdentifier");

  public static final Asn1Oid id_pda = OIDs.initOid("1.3.6.1.5.5.7.9", "id-pda");

  public static final Asn1Oid id_ad = OIDs.initOid("1.3.6.1.5.5.7.48", "id-ad");

  public static final Asn1Oid id_ad_caIssuers = OIDs.initOid(
      "1.3.6.1.5.5.7.48.2", "id-ad-caIssuers");

  public static final Asn1Oid id_ad_ocsp = OcspOIDs.id_pkix_ocsp;

  public static final Asn1Oid ocspAccessMethod = OcspOIDs.id_pkix_ocsp;

  public static final Asn1Oid id_ad_rpkiManifest = OIDs.initOid(
      "1.3.6.1.5.5.7.48.10", "RPKI Manifest");

  public static final Asn1Oid id_ad_signedObject = OIDs.initOid(
      "1.3.6.1.5.5.7.48.11", "Signed Object");

  public static final Asn1Oid id_ad_rpkiNotify = OIDs.initOid(
      "1.3.6.1.5.5.7.48.13", "RPKI Notify");

  // otherName with hardwareModuleName
  public static final Asn1Oid id_on_hardwareModuleName = OIDs.initOid(
      "1.3.6.1.5.5.7.8.4", "hardwareModuleName");

  // otherName with SmtpUTF8Mailbox
  public static final Asn1Oid id_on_SmtpUTF8Mailbox = OIDs.initOid(
      "1.3.6.1.5.5.7.8.9", "SmtpUTF8Mailbox");

  // otherName with id_on_MACAddress
  public static final Asn1Oid id_on_MACAddress = OIDs.initOid(
      "1.3.6.1.5.5.7.8.12", "MACAddress");

}
