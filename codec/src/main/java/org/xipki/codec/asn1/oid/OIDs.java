// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.Args;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author Lijun Liao (xipki)
 */
public class OIDs {

  private static final Map<String, String> oidNameMap = new HashMap<>();

  private static final Set<String> pqcOids = new HashSet<>(100);

  public static final Asn1Oid.OidNameResolver OID_NAME_RESOLVER = new DefaultOidNameResolver();

  private static boolean initialized = false;

  static Asn1Oid initOid(String oid, String name) {
    return initOid(oid, name, false);
  }

  static Asn1Oid initPqcOid(String oid, String name) {
    return initOid(oid, name, true);
  }

  private static Asn1Oid initOid(String oid, String name, boolean pqc) {
    Asn1Oid oidObj = new Asn1Oid(oid);
    String mainAlias = name != null ? name.trim() : oid;

    if (oidNameMap.put(oid, mainAlias) != null) {
      throw new RuntimeException("duplicated oid: " + oid + " (alias " + mainAlias + ")");
    }

    if (pqc) {
      pqcOids.add(oid);
    }

    return oidObj;
  }

  private static void init() {
    if (initialized) {
      return;
    }

    AlgorithmOIDs.AES128_GMAC.getId();
    AttributeOIDs.binarySigningTime.getId();
    BsiOIDs.ecdsa_plain_SHA256.getId();
    CertPolicyOIDs.extended_validation.getId();
    CmpOIDs.id_regInfo_utf8Pairs.getId();
    CmsOIDs.authenticatedData.getId();
    CurveOIDs.brainpoolP192r1.getId();
    DiceOIDs.tcg_dice.getId();
    AlgorithmOIDs.id_Ed448.getId();
    EtsiQcOIDs.id_etsi_qcs_LimitedValue.getId();
    ExtensionOIDs.id_microsoft_objectSid.getId();
    GmOIDs.hmac_sm3.getId();
    IanaOIDs._private.getId();
    IsoIecOIDs.ripemd160.getId();
    KeyPurposeOIDs.anyExtendedKeyUsage.getId();
    MatterOIDs.csa_root.getId();
    MiscOIDs.as_sys_sec_alg_ideaCBC.getId();
    MrtdOIDs.id_icao_mrtd_security_extensions_documentTypeList.getId();
    NistOIDs.aes.getId();
    NttOIDs.id_camellia128_cbc.getId();
    OcspOIDs.id_pkix_ocsp.getId();
    OiwOIDs.desCBC.getId();
    PkcsOIDs.id_PBMAC1.getId();
    PolicyQualifierOIDs.id_qt_cps.getId();
    QCStatementOIDs.id_etsi_psd2_qcStatement.getId();
    SecOIDs.mqvSinglePass_sha256kdf_scheme.getId();
    SpdmOIDs.id_DMTF_device_info.getId();
    TcgOIDs.tcg_at_platformIdentifier.getId();
    TeleTrustOIDs.brainpoolP160r1.getId();
    X9OIDs.dhpublicnumber.getId();
    X509OIDs.id_on_MACAddress.getId();
    XipkiOIDs.id_alg_dhPop_x448.getId();

    initialized = true;
  }

  /**
   * Returns the name for the oid, or the text representation of OID if found no registered name.
   * @param oid the OID
   * @return the name, must not be null.
   */
  public static String getName(Asn1Oid oid) {
    return getName(oid.getId());
  }

  /**
   * Returns the name for the oid, or the text representation of OID if found no registered name.
   * @param oid the OID
   * @return the name, must not be null.
   */
  public static String getName(String oid) {
    init();
    String name = oidNameMap.get(oid);
    return name == null ? oid : name;
  }

  public static String oidToDisplayName(Asn1Oid oid) {
    String name = getName(Args.notNull(oid, "oid"));
    return (name == null) ? oid.getId() : oid.getId() + " (" + name + ")";
  }

  private static final class DefaultOidNameResolver implements Asn1Oid.OidNameResolver {

    @Override
    public String engineGetName(Asn1Oid oid) {
      init();
      return oidNameMap.get(oid.getId());
    }
  }

  public static boolean isPqcAlgorithm(Asn1Oid oid) {
    init();
    return pqcOids.contains(oid.getId());
  }

  public static boolean isPqcAlgorithm(String oid) {
    init();
    return pqcOids.contains(oid);
  }

}
