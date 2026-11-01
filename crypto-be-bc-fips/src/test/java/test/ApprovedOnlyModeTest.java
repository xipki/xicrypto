// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.bcfips.CryptoBcFips;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests that the BC-FIPS backend sets the approved-only mode of BC-FIPS itself: the tests run
 * with {@code -Dorg.bouncycastle.fips.approved_only=false}, which the backend overrides.
 *
 * @author Lijun Liao (xipki)
 */
public class ApprovedOnlyModeTest {

  private static final byte[] MSG = "message to be signed".getBytes();

  private static CryptoApi crypto;

  @BeforeClass
  public static void init() {
    // before any other use of BC-FIPS; must not throw FipsUnapprovedOperationError
    crypto = new CryptoBcFips();
    Assert.assertTrue("not in approved-only mode",
        CryptoServicesRegistrar.isInApprovedOnlyMode());
    Assert.assertEquals("true", System.getProperty(CryptoBcFips.PROP_APPROVED_ONLY));
    Assert.assertEquals("true", Security.getProperty(CryptoBcFips.PROP_APPROVED_ONLY));
  }

  @Test
  public void testDefaultSecureRandom() {
    SecureRandom rnd = CryptoServicesRegistrar.getSecureRandom();
    Assert.assertTrue(rnd.getClass().getName(), rnd instanceof FipsSecureRandom);
    Assert.assertEquals(32, rnd.generateSeed(32).length);
    byte[] b = new byte[32];
    rnd.nextBytes(b);
  }

  @Test
  public void testApprovedAlgorithms() throws Exception {
    KeyPair kp = ecKeyPair("secp256r1");
    Assert.assertTrue(signVerify("SHA256WITHECDSA", kp));

    KeyPairGenerator kpGen = crypto.newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    Assert.assertTrue(signVerify("SHA256WITHRSA", kpGen.generateKeyPair()));
  }

  @Test
  public void testUnapprovedAlgorithms() throws Exception {
    // BC-FIPS rejects keys on sm2p256v1
    try {
      ecKeyPair("sm2p256v1");
      Assert.fail("sm2p256v1 key generated in approved-only mode");
    } catch (Error | Exception e) {
      // expected
    }

    // not offered by the backend, in any mode
    Assert.assertThrows(NoSuchAlgorithmException.class, () -> crypto.newMessageDigest("SM3"));
    for (String alg : new String[] {"SHAKE256WITHRSAPSS", "SHAKE256WITHECDSA"}) {
      Assert.assertThrows(alg, NoSuchAlgorithmException.class, () -> crypto.newSignature(alg));
    }
  }

  private static KeyPair ecKeyPair(String curve) throws Exception {
    KeyPairGenerator kpGen = crypto.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec(curve));
    return kpGen.generateKeyPair();
  }

  private static boolean signVerify(String alg, KeyPair kp) throws Exception {
    Signature signer = crypto.newSignature(alg);
    signer.initSign(kp.getPrivate());
    signer.update(MSG);
    byte[] sig = signer.sign();

    Signature verifier = crypto.newSignature(alg);
    verifier.initVerify(kp.getPublic());
    verifier.update(MSG);
    return verifier.verify(sig);
  }

}
