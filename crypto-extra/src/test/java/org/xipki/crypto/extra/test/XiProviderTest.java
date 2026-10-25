// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests SM3, SM2 and RSA-PSS with SHAKE of {@link XiPKIProvider} against BouncyCastle.
 *
 * @author Lijun Liao (xipki)
 */
public class XiProviderTest {

  private static final SecureRandom RND = new SecureRandom();

  private static final Provider XI = new XiPKIProvider();

  private static final Provider BC = new BouncyCastleProvider();

  @Test
  public void testSm3() throws Exception {
    Assume.assumeFalse("SM disabled", EcCurve.isSmDisabled());
    // GB/T 32905-2016, example 1
    Assert.assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        Hex.encode(MessageDigest.getInstance("SM3", XI).digest(
            "abc".getBytes(StandardCharsets.US_ASCII))));

    byte[] m = new byte[1000];
    RND.nextBytes(m);
    Assert.assertArrayEquals(MessageDigest.getInstance("SM3", BC).digest(m),
        MessageDigest.getInstance("SM3", XI).digest(m));
  }

  @Test
  public void testSm2() throws Exception {
    Assume.assumeFalse("SM disabled", EcCurve.isSmDisabled());
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
    kpGen.initialize(new ECGenParameterSpec("sm2p256v1"), RND);
    crossCheck("SM3WITHSM2", kpGen.generateKeyPair());
  }

  @Test
  public void testRsaPssShake() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
    kpGen.initialize(2048, RND);
    KeyPair kp = kpGen.generateKeyPair();
    crossCheck("SHAKE128WITHRSAPSS", kp);
    crossCheck("SHAKE256WITHRSAPSS", kp);

    // modulus length not a multiple of 8, the encoded message is one byte shorter than the
    // modulus (BouncyCastle cannot generate such keys quickly)
    KeyPairGenerator jdkKpGen = KeyPairGenerator.getInstance("RSA");
    jdkKpGen.initialize(2049, RND);
    KeyPair kp2049 = jdkKpGen.generateKeyPair();
    // the leftmost byte of EM has no zero bits to check; half of the signatures have it >= 0x80
    for (int i = 0; i < 16; i++) {
      crossCheck("SHAKE128WITHRSAPSS", kp2049);
    }
  }

  private static void crossCheck(String alg, KeyPair kp) throws Exception {
    byte[] m = new byte[100];
    RND.nextBytes(m);

    byte[] sig = sign(XI, alg, kp, m);
    Assert.assertTrue(alg + ": XiPKI -> BC", verify(BC, alg, kp, m, sig));
    Assert.assertTrue(alg + ": XiPKI -> XiPKI", verify(XI, alg, kp, m, sig));
    Assert.assertFalse(alg + ": changed message", verify(XI, alg, kp, new byte[1], sig));

    sig = sign(BC, alg, kp, m);
    Assert.assertTrue(alg + ": BC -> XiPKI", verify(XI, alg, kp, m, sig));
  }

  private static byte[] sign(Provider provider, String alg, KeyPair kp, byte[] m)
      throws Exception {
    Signature sig = Signature.getInstance(alg, provider);
    sig.initSign(kp.getPrivate(), RND);
    sig.update(m);
    return sig.sign();
  }

  private static boolean verify(Provider provider, String alg, KeyPair kp, byte[] m,
                                byte[] value) throws Exception {
    Signature sig = Signature.getInstance(alg, provider);
    sig.initVerify(kp.getPublic());
    sig.update(m);
    return sig.verify(value);
  }

}
