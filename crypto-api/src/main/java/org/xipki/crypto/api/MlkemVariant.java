// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.c509.ConstPublicKeyAlgorithm;

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

  public static MlkemVariant fromC509PublicKeyAlg(int c509AlgId) {
    switch (c509AlgId) {
      case ConstPublicKeyAlgorithm.ML_KEM_512:
        return ml_kem_512;
      case ConstPublicKeyAlgorithm.ML_KEM_768:
        return ml_kem_768;
      case ConstPublicKeyAlgorithm.ML_KEM_1024:
        return ml_kem_1024;
      default:
        return null;
    }
  }

}
