// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;

/**
 * Asserts that BouncyCastle is not on the classpath. Runs only in the execution "no-bc",
 * together with the conformance and routing tests.
 *
 * @author Lijun Liao (xipki)
 */
public class NoBouncyCastleTest {

  @Test
  public void testNoBouncyCastle() {
    for (String name : new String[]{"org.bouncycastle.jce.provider.BouncyCastleProvider",
        "org.xipki.crypto.bc.CryptoBc"}) {
      try {
        Class.forName(name);
        Assert.fail(name + " is on the classpath");
      } catch (ClassNotFoundException e) {
        // expected
      }
    }
  }

}
