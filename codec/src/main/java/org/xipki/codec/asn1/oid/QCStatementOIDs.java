// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class QCStatementOIDs {

  private QCStatementOIDs() {
  }

  public static final Asn1Oid id_qcs_pkixQCSyntax_v1 = OIDs.initOid(
      "1.3.6.1.5.5.7.11.1", "id-qcs-pkixQCSyntax-v1");

  public static final Asn1Oid id_qcs_pkixQCSyntax_v2 = OIDs.initOid(
      "1.3.6.1.5.5.7.11.2", "id-qcs-pkixQCSyntax-v2");

  public static final Asn1Oid id_etsi_qcs_QcCompliance = EtsiQcOIDs.id_etsi_qcs_QcCompliance;

  public static final Asn1Oid id_etsi_qcs_QcLimitValue = EtsiQcOIDs.id_etsi_qcs_LimitedValue;

  public static final Asn1Oid id_etsi_qcs_QcRetentionPeriod =
      EtsiQcOIDs.id_etsi_qcs_RetentionPeriod;

  public static final Asn1Oid id_etsi_qcs_QcSSCD = EtsiQcOIDs.id_etsi_qcs_QcSSCD;

  public static final Asn1Oid id_etsi_qcs_QcPDS = EtsiQcOIDs.id_etsi_qcs_QcPds;

  public static final Asn1Oid id_etsi_qcs_QcType = EtsiQcOIDs.id_etsi_qcs_QcType;

  public static final Asn1Oid id_etsi_qcs_QcCClegislation = EtsiQcOIDs.id_etsi_qcs_QcCClegislation;

  public static final Asn1Oid id_etsi_psd2_qcStatement = OIDs.initOid(
      "0.4.0.19495.2", "id-etsi-psd2-qcStatement");

}
