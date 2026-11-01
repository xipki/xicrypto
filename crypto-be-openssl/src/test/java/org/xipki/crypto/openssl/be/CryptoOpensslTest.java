// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl.be;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.crypto.openssl.OpenSsl;

/**
 * Tests that {@link CryptoOpenssl} rejects the FIPS mode of OpenSSL. The algorithms are tested in
 * the module crypto-openssl.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpensslTest {

  @Test
  public void testFipsMode() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    if (OpenSsl.isFipsEnabled() == false) {
      Assert.assertEquals("openssl", new CryptoOpenssl().name());
    } else {
      try {
        new CryptoOpenssl();
        Assert.fail("openssl accepted the FIPS mode of OpenSSL");
      } catch (IllegalStateException e) {
        Assert.assertTrue(e.getMessage(), e.getMessage().contains("use the backend openssl-fips"));
      }
    }
  }

}
