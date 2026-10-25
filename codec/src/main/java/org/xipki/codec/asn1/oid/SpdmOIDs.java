// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class SpdmOIDs {

  private SpdmOIDs() {
  }

  public static final Asn1Oid id_DMTF_device_info = OIDs.initOid(
      "1.3.6.1.4.1.412.274.1", "id-DMTF-device-info");

  public static final Asn1Oid id_DMTF_hardware_identity = OIDs.initOid(
      "1.3.6.1.4.1.412.274.2", "id-DMTF-hardware-identity");

  public static final Asn1Oid id_DMTF_eku_responder_auth = OIDs.initOid(
      "1.3.6.1.4.1.412.274.3", "id-DMTF-eku-responder-auth");

  public static final Asn1Oid id_DMTF_eku_requestor_auth = OIDs.initOid(
      "1.3.6.1.4.1.412.274.4", "id-DMTF-eku-requestor-auth");

  public static final Asn1Oid id_DMTF_mutable_certificate = OIDs.initOid(
      "1.3.6.1.4.1.412.274.5", "id-DMTF-mutable-certificate");

  public static final Asn1Oid id_DMTF_SPDM_extension = OIDs.initOid(
      "1.3.6.1.4.1.412.274.6", "id-DMTF-SPDM-extension");

}
