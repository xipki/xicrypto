// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.core.KeySpec;

/**
 * Comp Kem MLKEM Variant enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum CompKemMlkemVariant {

  mlkem768(64, 1184, 1088,  MlkemVariant.ml_kem_768, AlgorithmOIDs.id_ml_kem_768),
  mlkem1024(64, 1568, 1568, MlkemVariant.ml_kem_1024, AlgorithmOIDs.id_ml_kem_1024);

  private final Asn1Oid oid;
  private final int skSize;
  private final int pkSize;
  private final int ctSize;
  private final MlkemVariant params;

  CompKemMlkemVariant(int skSize, int pkSize, int ctSize,
                      MlkemVariant params, Asn1Oid oid) {
    this.skSize = skSize;
    this.pkSize = pkSize;
    this.ctSize = ctSize;
    this.params = params;
    this.oid = oid;
  }

  public KeySpec keySpec() {
    return (this == CompKemMlkemVariant.mlkem768) ? KeySpec.MLKEM768 : KeySpec.MLKEM1024;
  }

  public Asn1Oid oid() {
    return oid;
  }

  public int skSize() {
    return skSize;
  }

  public int pkSize() {
    return pkSize;
  }

  public int ctSize() {
    return ctSize;
  }

  public MlkemVariant params() {
    return params;
  }
}
