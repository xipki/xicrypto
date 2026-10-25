// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class PolicyQualifierOIDs {

  private PolicyQualifierOIDs() {
  }

  public static final Asn1Oid id_qt_cps = OIDs.initOid("1.3.6.1.5.5.7.2.1", "id-qt-cps");

  public static final Asn1Oid id_qt_unotice = OIDs.initOid("1.3.6.1.5.5.7.2.2", "id-qt-unotice");

}
