// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class MatterOIDs {

  private MatterOIDs() {
  }

  public static final Asn1Oid csa_root = OIDs.initOid("1.3.6.1.4.1.37244", "csa-root");

  public static final Asn1Oid matter_node_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.1", "matter-node-id");

  public static final Asn1Oid matter_firmware_signing_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.2", "matter-firmware-signing-id");

  public static final Asn1Oid matter_icac_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.3", "matter-icac-id");

  public static final Asn1Oid matter_rcac_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.4", "matter-rcac-id");

  public static final Asn1Oid matter_fabric_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.5", "matter-fabric-id");

  public static final Asn1Oid matter_noc_cat = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.6", "matter-noc-cat");

  public static final Asn1Oid matter_vvs_id = OIDs.initOid(
      "1.3.6.1.4.1.37244.1.7", "matter-vvs-id");

  public static final Asn1Oid matter_oid_vid = OIDs.initOid(
      "1.3.6.1.4.1.37244.2.1", "matter-oid-vid");

  public static final Asn1Oid matter_oid_pid = OIDs.initOid(
      "1.3.6.1.4.1.37244.2.2", "matter-oid-pid");

}
