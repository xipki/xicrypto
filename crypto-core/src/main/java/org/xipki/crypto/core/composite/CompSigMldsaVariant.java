// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.SignAlgo;

/**
 * Comp Sig MLDSA Variant enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum CompSigMldsaVariant {

  mldsa44(32, 1312, 2420, MldsaVariant.ml_dsa_44),
  mldsa65(32, 1952, 3309, MldsaVariant.ml_dsa_65),
  mldsa87(32, 2592, 4627, MldsaVariant.ml_dsa_87);

  private final int skSize;
  private final int pkSize;
  private final int sigSize;
  private final MldsaVariant params;

  CompSigMldsaVariant(int skSize, int pkSize, int sigSize, MldsaVariant params) {
    this.skSize = skSize;
    this.pkSize = pkSize;
    this.sigSize = sigSize;
    this.params = params;
  }

  public SignAlgo signAlgo() {
    switch (this) {
      case mldsa44:
        return SignAlgo.MLDSA44;
      case mldsa65:
        return SignAlgo.MLDSA65;
      default:
        return SignAlgo.MLDSA87;
    }
  }

  public KeySpec keySpec() {
    switch (this) {
      case mldsa44:
        return KeySpec.MLDSA44;
      case mldsa65:
        return KeySpec.MLDSA65;
      default:
        return KeySpec.MLDSA87;
    }
  }

  public int skSize() {
    return skSize;
  }

  public int pkSize() {
    return pkSize;
  }

  public int sigSize() {
    return sigSize;
  }

  public MldsaVariant params() {
    return params;
  }
}
