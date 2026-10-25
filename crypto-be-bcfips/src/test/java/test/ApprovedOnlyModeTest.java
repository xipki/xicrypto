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
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests the BC-FIPS backend in the approved-only mode of BC-FIPS. Runs in its own JVM with
 * {@code -Dorg.bouncycastle.fips.approved_only=true} (surefire execution {@code approved-only}),
 * because the mode is fixed when BC-FIPS is loaded.
 *
 * @author Lijun Liao (xipki)
 */
public class ApprovedOnlyModeTest {

  private static final byte[] MSG = "message to be signed".getBytes();

  private static CryptoApi crypto;

  @BeforeClass
  public static void init() {
    Assert.assertTrue("not in approved-only mode",
        CryptoServicesRegistrar.isInApprovedOnlyMode());
    // must not throw FipsUnapprovedOperationError
    crypto = new CryptoBcFips();
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
    for (String alg : new String[] {"SHA256WITHECDSA", "SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}) {
      Assert.assertTrue(alg, signVerify(alg, kp));
    }

    KeyPairGenerator kpGen = crypto.newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    Assert.assertTrue(signVerify("SHA256WITHRSA", kpGen.generateKeyPair()));
  }

  @Test
  public void testSm3OutsideBcFips() throws Exception {
    // SM3 is computed by xicrypto, outside BC-FIPS: the mode does not restrict it
    Assert.assertEquals(32, crypto.newMessageDigest("SM3").digest(MSG).length);
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

    // RSA-PSS with SHAKE needs the raw RSA operation, which is not available
    KeyPairGenerator kpGen = crypto.newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();
    try {
      signVerify("SHAKE256WITHRSAPSS", kp);
      Assert.fail("SHAKE256WITHRSAPSS worked in approved-only mode");
    } catch (Error | Exception e) {
      // expected
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
