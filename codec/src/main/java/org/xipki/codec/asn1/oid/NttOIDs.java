// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class NttOIDs {

  private NttOIDs() {
  }

  public static final Asn1Oid id_camellia128_cbc = OIDs.initOid(
      "1.2.392.200011.61.1.1.1.2", "id-camellia128-cbc");

  public static final Asn1Oid id_camellia192_cbc = OIDs.initOid(
      "1.2.392.200011.61.1.1.1.3", "id-camellia192-cbc");

  public static final Asn1Oid id_camellia256_cbc = OIDs.initOid(
      "1.2.392.200011.61.1.1.1.4", "id-camellia256-cbc");

  public static final Asn1Oid id_camellia128_wrap = OIDs.initOid(
      "1.2.392.200011.61.1.1.3.2", "id-camellia128-wrap");

  public static final Asn1Oid id_camellia192_wrap = OIDs.initOid(
      "1.2.392.200011.61.1.1.3.3", "id-camellia192-wrap");

  public static final Asn1Oid id_camellia256_wrap = OIDs.initOid(
      "1.2.392.200011.61.1.1.3.4", "id-camellia256-wrap");

}
