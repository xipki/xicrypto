// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.bcfips;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.math.EcCurve;

import javax.crypto.Mac;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * Tests {@link CryptoBcFips.BcFipsXiPKIProvider}: the replaced ECDSA with
 * SHAKE on BC-FIPS, and SM2 and RSA-PSS with SHAKE of xicrypto on BC-FIPS
 * keys. The counterpart is the plain {@link XiPKIProvider}, which xicrypto
 * tests against BouncyCastle LTS.
 *
 * @author Lijun Liao (xipki)
 */
public class BcFipsXiPKIProviderTest {

  private static final SecureRandom RND = new SecureRandom();

  private static final byte[] MSG = "message to be signed".getBytes();

  private static CryptoApi crypto;

  private static Provider bcFips;

  private static Provider ext;

  /** xicrypto with the default primitives, independent of BC-FIPS. */
  private static Provider plain;

  @BeforeClass
  public static void init() {
    // registers BC-FIPS
    crypto = new CryptoBcFips();
    bcFips = Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);
    ext = new CryptoBcFips.BcFipsXiPKIProvider(bcFips);
    plain = new XiPKIProvider();
  }

  @Test
  public void testEntries() {
    Assert.assertEquals(CryptoBcFips.BcFipsXiPKIProvider.PROVIDER_NAME, ext.getName());
    String[][] entries = {
        {"SHAKE128WITHECDSA", AlgorithmOIDs.id_ecdsa_with_shake128.getId(),
            ShakeEcdsaSignatureSpi.class.getName()},
        {"SHAKE256WITHECDSA", AlgorithmOIDs.id_ecdsa_with_shake256.getId(),
            ShakeEcdsaSignatureSpi.class.getName()}};
    for (String[] e : entries) {
      Assert.assertEquals(e[0], e[2], ext.getService("Signature", e[0]).getClassName());
      Assert.assertEquals(e[1], e[2], ext.getService("Signature", e[1]).getClassName());
    }
  }

  @Test
  public void testShakeEcdsaInterop() throws Exception {
    for (String curve : new String[] {"secp256r1", "secp384r1", "secp521r1"}) {
      KeyPair kp = ecKeyPair(curve);
      for (String alg : new String[] {"SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}) {
        String desc = curve + " " + alg;
        byte[] sig1 = sign(alg, ext, kp);
        byte[] sig2 = sign(alg, ext, kp);
        // random nonce
        Assert.assertFalse(desc + " random nonce", Arrays.equals(sig1, sig2));

        Assert.assertTrue(desc + " BC-FIPS -> BC-FIPS", verify(alg, ext, kp, sig1));
        Assert.assertTrue(desc + " BC-FIPS -> crypto-extra", verify(alg, plain, kp, sig1));
        Assert.assertTrue(desc + " crypto-extra -> BC-FIPS",
            verify(alg, ext, kp, sign(alg, plain, kp)));

        // via the CryptoApi
        Signature sig = crypto.newSignature(alg);
        sig.initSign(kp.getPrivate());
        sig.update(MSG);
        Assert.assertTrue(desc + " CryptoApi", verify(alg, plain, kp, sig.sign()));
      }
    }
  }

  @Test
  public void testShakeEcdsaInvalidSignatures() throws Exception {
    KeyPair kp = ecKeyPair("secp256r1");
    String alg = "SHAKE256WITHECDSA";
    byte[] sig = sign(alg, ext, kp);

    byte[] modified = sig.clone();
    modified[modified.length - 1] ^= 1;
    Assert.assertFalse("modified", verify(alg, ext, kp, modified));

    // BER instead of DER: the length of the SEQUENCE in long form
    byte[] ber = new byte[sig.length + 1];
    ber[0] = 0x30;
    ber[1] = (byte) 0x81;
    System.arraycopy(sig, 1, ber, 2, sig.length - 1);
    Assert.assertFalse("BER", verify(alg, ext, kp, ber));

    Assert.assertFalse("garbage", verify(alg, ext, kp, new byte[] {1, 2, 3}));
    Assert.assertFalse("empty", verify(alg, ext, kp, new byte[0]));

    Signature verifier = Signature.getInstance(alg, ext);
    verifier.initVerify(kp.getPublic());
    verifier.update("other message".getBytes());
    Assert.assertFalse("other message", verifier.verify(sig));
  }

  @Test
  public void testSm2WithBcFipsKey() throws Exception {
    Assume.assumeFalse("SM disabled", EcCurve.isSmDisabled());
    KeyPair kp = ecKeyPair("sm2p256v1");
    String alg = "SM3WITHSM2";
    Assert.assertTrue(verify(alg, ext, kp, sign(alg, ext, kp)));
    Assert.assertTrue(verify(alg, plain, kp, sign(alg, ext, kp)));
    Assert.assertTrue(verify(alg, ext, kp, sign(alg, plain, kp)));
  }

  @Test
  public void testRsaPssShakeWithBcFipsKey() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", bcFips);
    kpGen.initialize(2048, RND);
    KeyPair kp = kpGen.generateKeyPair();
    for (String alg : new String[] {"SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS"}) {
      Assert.assertTrue(alg, verify(alg, ext, kp, sign(alg, ext, kp)));
      Assert.assertTrue(alg, verify(alg, plain, kp, sign(alg, ext, kp)));
      Assert.assertTrue(alg, verify(alg, ext, kp, sign(alg, plain, kp)));
    }
  }

  @Test
  public void testGmacFromBcFips() throws Exception {
    Mac mac = crypto.newMac("AES-GMAC");
    Assert.assertEquals(BouncyCastleFipsProvider.PROVIDER_NAME, mac.getProvider().getName());
  }

  private static KeyPair ecKeyPair(String curve) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", bcFips);
    kpGen.initialize(new ECGenParameterSpec(curve), RND);
    return kpGen.generateKeyPair();
  }

  private static byte[] sign(String alg, Provider provider, KeyPair kp) throws Exception {
    Signature signer = Signature.getInstance(alg, provider);
    signer.initSign(kp.getPrivate(), RND);
    signer.update(MSG);
    return signer.sign();
  }

  private static boolean verify(String alg, Provider provider, KeyPair kp, byte[] sig)
      throws Exception {
    Signature verifier = Signature.getInstance(alg, provider);
    verifier.initVerify(kp.getPublic());
    verifier.update(MSG);
    return verifier.verify(sig);
  }

}
