// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class OcspOIDs {

  private OcspOIDs() {
  }

  public static final Asn1Oid id_pkix_ocsp = OIDs.initOid("1.3.6.1.5.5.7.48.1", "id-pkix-ocsp");

  public static final Asn1Oid id_pkix_ocsp_basic = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.1", "id-pkix-ocsp-basic");

  public static final Asn1Oid id_pkix_ocsp_nonce = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.2", "id-pkix-ocsp-nonce");

  public static final Asn1Oid id_pkix_ocsp_crl = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.3", "id-pkix-ocsp-crl");

  public static final Asn1Oid id_pkix_ocsp_response = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.4", "id-pkix-ocsp-response");

  public static final Asn1Oid id_pkix_ocsp_nocheck = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.5", "id-pkix-ocsp-nocheck");

  public static final Asn1Oid id_pkix_ocsp_archive_cutoff = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.6", "id-pkix-ocsp-archive-cutoff");

  public static final Asn1Oid id_pkix_ocsp_service_locator = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.7", "id-pkix-ocsp-service-locator");

  public static final Asn1Oid id_pkix_ocsp_pref_sig_algs = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.8", "id-pkix-ocsp-pref-sig-algs");

  public static final Asn1Oid id_pkix_ocsp_extended_revoke = OIDs.initOid(
      "1.3.6.1.5.5.7.48.1.9", "id-pkix-ocsp-extended-revoke");

}
