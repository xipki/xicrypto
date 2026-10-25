// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class EtsiQcOIDs {

  private EtsiQcOIDs() {
  }

  public static final Asn1Oid id_etsi_qcs_QcCompliance = OIDs.initOid(
      "0.4.0.1862.1.1", "id-etsi-qcs-QcCompliance");

  public static final Asn1Oid id_etsi_qcs_LimitedValue = OIDs.initOid(
      "0.4.0.1862.1.2", "id-etsi-qcs-LimitedValue");

  public static final Asn1Oid id_etsi_qcs_RetentionPeriod = OIDs.initOid(
      "0.4.0.1862.1.3", "id-etsi-qcs-RetentionPeriod");

  public static final Asn1Oid id_etsi_qcs_QcSSCD = OIDs.initOid(
      "0.4.0.1862.1.4", "id-etsi-qcs-QcSSCD");

  public static final Asn1Oid id_etsi_qcs_QcPds = OIDs.initOid(
      "0.4.0.1862.1.5", "id-etsi-qcs-QcPds");

  public static final Asn1Oid id_etsi_qcs_QcType = OIDs.initOid(
      "0.4.0.1862.1.6", "id-etsi-qcs-QcType");

  public static final Asn1Oid id_etsi_qct_esign = OIDs.initOid(
      "0.4.0.1862.1.6.1", "id-etsi-qct-esign");

  public static final Asn1Oid id_etsi_qct_eseal = OIDs.initOid(
      "0.4.0.1862.1.6.2", "id-etsi-qct-eseal");

  public static final Asn1Oid id_etsi_qct_web = OIDs.initOid(
      "0.4.0.1862.1.6.3", "id-etsi-qct-web");

  public static final Asn1Oid id_etsi_qcs_QcCClegislation = OIDs.initOid(
      "0.4.0.1862.1.7", "id-etsi-qcs-QcCClegislation");

}
