// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * Certificate Policy OIDs.
 *
 * @author Lijun Liao (xipki)
 */
public class CertPolicyOIDs {

  private CertPolicyOIDs() {
  }

  public static final Asn1Oid id_anyPolicy = OIDs.initOid("2.5.29.32.0", "Any Policy");

  public static final Asn1Oid id_domain_validated = OIDs.initOid(
      "2.23.140.1.2.1", "Domain Validation (DV)");

  public static final Asn1Oid id_organization_validated = OIDs.initOid(
      "2.23.140.1.2.2", "Organization Validation (OV)");

  public static final Asn1Oid id_individual_validated = OIDs.initOid(
      "2.23.140.1.2.3", "Individual Validation (IV)");

  public static final Asn1Oid extended_validation = OIDs.initOid(
      "2.23.140.1.1", "Extended Validation (EV)");

  public static final Asn1Oid id_cp_ipAddr_asNumber = OIDs.initOid(
      "1.3.6.1.5.5.7.14.2", "id-cp-ipAddr-asNumber");

  public static final Asn1Oid id_cp_ipAddr_asNumber_v2 = OIDs.initOid(
      "1.3.6.1.5.5.7.14.3", "id-cp-ipAddr-asNumber-v2");

  /* Remote SIM Provisioning Role Certificate Issuer */
  public static final Asn1Oid id_rspRole_ci = OIDs.initOid(
      "2.23.146.1.2.1.0", "id-rspRole-ci");

  /* Remote SIM Provisioning Role eUIC */
  public static final Asn1Oid id_rspRole_euicc = OIDs.initOid(
      "2.23.146.1.2.1.1", "id-rspRole-euicc");

  /* Remote SIM Provisioning Role eUICC Manufacturer */
  public static final Asn1Oid id_rspRole_eum = OIDs.initOid(
      "2.23.146.1.2.1.2", "id-rspRole-eum");

  /* Remote SIM Provisioning Role SM-DP+ TLS */
  public static final Asn1Oid id_rspRole_dp_tls = OIDs.initOid(
      "2.23.146.1.2.1.3", "id-rspRole-dp-tls");

  /* Remote SIM Provisioning Role SM-DP+ Authentication */
  public static final Asn1Oid id_rspRole_dp_auth = OIDs.initOid(
      "2.23.146.1.2.1.4", "id-rspRole-dp-auth");

  /* Remote SIM Provisioning Role SM-DP+ Profile Binding */
  public static final Asn1Oid id_rspRole_dp_pb = OIDs.initOid(
      "2.23.146.1.2.1.5", "id-rspRole-dp-pb");

  /* Remote SIM Provisioning Role SM-DS TLS */
  public static final Asn1Oid id_rspRole_ds_tls = OIDs.initOid(
      "2.23.146.1.2.1.6", "id-rspRole-ds-tls");

  /* Remote SIM Provisioning Role SM-DS Authentication */
  public static final Asn1Oid id_rspRole_ds_auth = OIDs.initOid(
      "2.23.146.1.2.1.7", "id-rspRole-ds-auth");

  }
