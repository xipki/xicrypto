// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.bcfips.CryptoBcFips;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

/**
 * Tests that the BC-FIPS backend uses BC-FIPS (and BCPQC-FIPS) only: the algorithms BC-FIPS does
 * not offer as such (SM3, SM3withSM2, RSA-PSS and ECDSA with SHAKE) are not offered, and other
 * JCA providers of the JVM are not used.
 *
 * @author Lijun Liao (xipki)
 */
public class BcFipsOnlyTest {

  private static CryptoApi crypto;

  @BeforeClass
  public static void init() {
    crypto = new CryptoBcFips();
  }

  @Test
  public void testNotOffered() {
    Assert.assertThrows(NoSuchAlgorithmException.class, () -> crypto.newMessageDigest("SM3"));
    for (String alg : new String[] {"SM3WITHSM2", "SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS",
        "SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}) {
      Assert.assertThrows(alg, NoSuchAlgorithmException.class, () -> crypto.newSignature(alg));
    }
  }

  /** Spi of {@link #testNoOtherProvider()}, never instantiated by the backend. */
  public static final class DummyDigestSpi extends MessageDigestSpi {

    @Override
    protected void engineUpdate(byte input) {
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
    }

    @Override
    protected byte[] engineDigest() {
      return new byte[32];
    }

    @Override
    protected void engineReset() {
    }

  }

  /** The JCA providers of the JVM other than BC-FIPS and BCPQC-FIPS are unused. */
  @Test
  public void testNoOtherProvider() throws Exception {
    Provider other = new Provider("XiTestOther", "1.0", "test") {
      {
        put("MessageDigest.SM3", DummyDigestSpi.class.getName());
      }
    };
    Security.addProvider(other);
    try {
      Assert.assertNotNull(MessageDigest.getInstance("SM3"));
      Assert.assertThrows(NoSuchAlgorithmException.class, () -> crypto.newMessageDigest("SM3"));
    } finally {
      Security.removeProvider(other.getName());
    }
  }

  @Test
  public void testGmacFromBcFips() throws Exception {
    Mac mac = crypto.newMac("AES-GMAC");
    Assert.assertEquals(BouncyCastleFipsProvider.PROVIDER_NAME, mac.getProvider().getName());
  }

}
