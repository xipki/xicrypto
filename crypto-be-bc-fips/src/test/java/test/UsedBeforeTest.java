// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.crypto.bcfips.CryptoBcFips;

/**
 * Tests that the BC-FIPS backend is not created if BC-FIPS was used in the normal mode before:
 * the mode is fixed at the first use of BC-FIPS. Runs in its own JVM (surefire execution
 * {@code used-before}).
 *
 * @author Lijun Liao (xipki)
 */
public class UsedBeforeTest {

  @Test
  public void testRejected() {
    // first use of BC-FIPS, with the system property false
    Assert.assertFalse("in approved-only mode", CryptoServicesRegistrar.isInApprovedOnlyMode());
    IllegalStateException e = Assert.assertThrows(IllegalStateException.class,
        CryptoBcFips::new);
    Assert.assertTrue(e.getMessage(), e.getMessage().contains("used in the normal mode"));
  }

}
