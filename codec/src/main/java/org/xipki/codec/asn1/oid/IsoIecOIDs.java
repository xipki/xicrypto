// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class IsoIecOIDs {

  private IsoIecOIDs() {
  }

  public static final Asn1Oid ripemd160 = OIDs.initOid("1.0.10118.3.0.49", "ripemd160");

  public static final Asn1Oid is18033_2 = OIDs.initOid("1.0.18033.2", "is18033-2");

  public static final Asn1Oid id_ac_generic_hybrid = OIDs.initOid(
      "1.0.18033.2.1.2", "id-ac-generic-hybrid");

  public static final Asn1Oid id_kem_rsa = OIDs.initOid("1.0.18033.2.2.4", "id-kem-rsa");

}
