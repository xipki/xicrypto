// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import java.math.BigInteger;

/**
 * @author Lijun Liao (xipki)
 */
public interface ECCurve {

  BigInteger getOrder();

  int getFieldSize();

  ECPoint decodePoint(byte[] bytes);

}
