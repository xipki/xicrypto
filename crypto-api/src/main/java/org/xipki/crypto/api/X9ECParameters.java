// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import java.math.BigInteger;

/**
 * @author Lijun Liao (xipki)
 */
public interface X9ECParameters {

  ECCurve getCurve();

  ECPoint getG();

  /**
   * Returns u1·G + u2·Q, e.g. for the verification of ECDSA or SM2 signatures. For public
   * values only: implementations may be variable-time.
   * @param u1 the scalar of the base point G.
   * @param u2 the scalar of Q.
   * @param q the point Q.
   * @return u1·G + u2·Q.
   */
  default ECPoint sumOfTwoMultiplies(BigInteger u1, BigInteger u2, ECPoint q) {
    return getG().multiply(u1).add(q.multiply(u2));
  }

}
