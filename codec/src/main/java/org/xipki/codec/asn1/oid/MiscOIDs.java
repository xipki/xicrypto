// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class MiscOIDs {

  private MiscOIDs() {
  }

  public static final Asn1Oid id_pe_acmeIdentifier = OIDs.initOid(
      "1.3.6.1.5.5.7.1.31", "pe-acmeIdentifier");

  public static final Asn1Oid oqs_falcon_512 = OIDs.initOid(
      "1.3.9999.3.11", "oqs-falcon-512");

  public static final Asn1Oid oqs_falcon_1024 = OIDs.initOid(
      "1.3.9999.3.14", "oqs-falcon-1024");

  public static final Asn1Oid ossl_dilithium2 = OIDs.initOid(
      "1.3.6.1.4.1.2.267.12.4.4", "ossl-dilithium2");

  public static final Asn1Oid ossl_dilithium3 = OIDs.initOid(
      "1.3.6.1.4.1.2.267.12.6.5", "ossl-dilithium3");

  public static final Asn1Oid ossl_dilithium5 = OIDs.initOid(
      "1.3.6.1.4.1.2.267.12.8.7", "ossl-dilithium5");

  public static final Asn1Oid ossl_dilithium2_aes = OIDs.initOid(
      "1.3.6.1.4.1.2.267.11.4.4", "ossl-dilithium2-aes");

  public static final Asn1Oid ossl_dilithium3_aes = OIDs.initOid(
      "1.3.6.1.4.1.2.267.11.6.5", "ossl-dilithium3-aes");

  public static final Asn1Oid ossl_dilithium5_aes = OIDs.initOid(
      "1.3.6.1.4.1.2.267.11.8.7", "ossl-dilithium5-aes");

  public static final Asn1Oid netscape = OIDs.initOid("2.16.840.1.113730.1", "netscape");

  public static final Asn1Oid netscapeCertType = OIDs.initOid(
      "2.16.840.1.113730.1.1", "netscapeCertType");

  public static final Asn1Oid netscapeBaseURL = OIDs.initOid(
      "2.16.840.1.113730.1.2", "netscapeBaseURL");

  public static final Asn1Oid netscapeRevocationURL = OIDs.initOid(
      "2.16.840.1.113730.1.3", "netscapeRevocationURL");

  public static final Asn1Oid netscapeCARevocationURL = OIDs.initOid(
      "2.16.840.1.113730.1.4", "netscapeCARevocationURL");

  public static final Asn1Oid netscapeRenewalURL = OIDs.initOid(
      "2.16.840.1.113730.1.7", "netscapeRenewalURL");

  public static final Asn1Oid netscapeCApolicyURL = OIDs.initOid(
      "2.16.840.1.113730.1.8", "netscapeCApolicyURL");

  public static final Asn1Oid netscapeSSLServerName = OIDs.initOid(
      "2.16.840.1.113730.1.12", "netscapeSSLServerName");

  public static final Asn1Oid netscapeCertComment = OIDs.initOid(
      "2.16.840.1.113730.1.13", "netscapeCertComment");

  public static final Asn1Oid cast5CBC = OIDs.initOid("1.2.840.113533.7.66.10", "cast5CBC");

  public static final Asn1Oid as_sys_sec_alg_ideaCBC = OIDs.initOid(
      "1.3.6.1.4.1.188.7.1.1.2", "as-sys-sec-alg-ideaCBC");

  public static final Asn1Oid id_oracle_pkcs12_trusted_key_usage = OIDs.initOid(
      "2.16.840.1.113894.746875.1.1", "id-oracle-pkcs12-trusted-key-usage");

}
