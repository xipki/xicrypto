// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.NistOIDs;

/**
 * @author Lijun Liao (xipki)
 */
public enum MlkemVariant {
   ml_kem_512, ml_kem_768, ml_kem_1024;

  public static MlkemVariant fromOid(Asn1Oid oid) {
    if (NistOIDs.id_ml_kem_512.equals(oid)) {
      return ml_kem_512;
    } else if (NistOIDs.id_ml_kem_768.equals(oid)) {
      return ml_kem_768;
    } else if (NistOIDs.id_ml_kem_1024.equals(oid)) {
      return ml_kem_1024;
    } else {
      return null;
    }
  }
}
