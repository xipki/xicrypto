// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.NistOIDs;

/**
 * @author Lijun Liao (xipki)
 */
public enum MldsaVariant {
  ml_dsa_44, ml_dsa_65, ml_dsa_87;

  public static MldsaVariant fromOid(Asn1Oid oid) {
    if (NistOIDs.id_ml_dsa_44.equals(oid)) {
      return ml_dsa_44;
    } else if (NistOIDs.id_ml_dsa_65.equals(oid)) {
      return ml_dsa_65;
    } else if (NistOIDs.id_ml_dsa_87.equals(oid)) {
      return ml_dsa_87;
    } else {
      return null;
    }
  }
}
