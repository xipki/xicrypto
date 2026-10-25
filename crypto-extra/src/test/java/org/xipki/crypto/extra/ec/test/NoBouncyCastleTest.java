// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.test;

import org.junit.Assert;
import org.junit.Test;

/**
 * Asserts that BouncyCastle is not on the classpath. Runs only in the execution "no-bc",
 * together with the tests that do not need BouncyCastle.
 *
 * @author Lijun Liao (xipki)
 */
public class NoBouncyCastleTest {

  @Test
  public void testNoBouncyCastle() {
    try {
      Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
      Assert.fail("BouncyCastle is on the classpath");
    } catch (ClassNotFoundException e) {
      // expected
    }
  }

}
