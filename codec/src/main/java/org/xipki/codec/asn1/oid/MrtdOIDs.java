// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class MrtdOIDs {

  private MrtdOIDs() {
  }

  public static final Asn1Oid id_icao_mrtd_security_extensions_nameChange = OIDs.initOid(
      "2.23.136.1.1.6.1", "id-icao-mrtd-security-extensions-nameChange");

  public static final Asn1Oid id_icao_mrtd_security_extensions_documentTypeList = OIDs.initOid(
      "2.23.136.1.1.6.2", "id-icao-mrtd-security-extensions-documentTypeList");

}
