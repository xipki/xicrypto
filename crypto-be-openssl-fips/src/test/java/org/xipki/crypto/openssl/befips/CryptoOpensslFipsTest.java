// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl.befips;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.crypto.openssl.OpenSsl;

/**
 * Tests that {@link CryptoOpensslFips} accepts only the FIPS mode of OpenSSL. The algorithms are
 * tested in the module crypto-openssl.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpensslFipsTest {

  @Test
  public void testFipsMode() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    if (OpenSsl.isFipsEnabled() == true) {
      Assert.assertEquals("openssl-fips", new CryptoOpensslFips().name());
    } else {
      try {
        new CryptoOpensslFips();
        Assert.fail("openssl-fips accepted OpenSSL without the FIPS mode");
      } catch (IllegalStateException e) {
        Assert.assertTrue(e.getMessage(), e.getMessage().contains("requires the FIPS mode"));
      }
    }
  }

}
