// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.jdk.CryptoJdk;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests the routing of crypto-be-jdk between SunEC and its XiPKIProvider instance by curve.
 *
 * @author Lijun Liao (xipki)
 */
public class EcRoutingTest {

  private static final byte[] MSG = "routing".getBytes(StandardCharsets.UTF_8);

  private static final SecureRandom RND = new SecureRandom();

  private static final CryptoApi crypto = new CryptoJdk();

  @Test
  public void testKeyGeneration() throws Exception {
    // NIST curves: SunEC
    for (String curve : new String[]{"secp256r1", "secp384r1", "secp521r1"}) {
      KeyPair kp = keyPair(curve);
      Assert.assertTrue(curve + ": " + kp.getPublic().getClass().getName(),
          kp.getPublic().getClass().getName().startsWith("sun.security.ec."));
      assertSignVerify("SHA256WITHECDSA", kp);
    }

    // the other curves: SunEC if it supports the curve (JDK 11 to 15: legacy native library,
    // e.g. brainpool), otherwise xicrypto
    for (String curve : new String[]{"brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
        "1.2.250.1.223.101.256.1"}) {
      KeyPair kp = keyPair(curve);
      Assert.assertEquals(curve, !sunEcSupports(curve), isXiKey(kp.getPublic()));
      assertSignVerify("SHA256WITHECDSA", kp);
      assertSignVerify("SHA3-384WITHECDSA", kp);
    }
  }

  @Test
  public void testSm2() throws Exception {
    KeyPair kp = keyPair("sm2p256v1");
    Assert.assertTrue(isXiKey(kp.getPublic()));
    assertSignVerify("SM3WITHSM2", kp);
  }

  @Test
  public void testKeyDecoding() throws Exception {
    KeyPair kp = keyPair("secp256r1");
    PublicKey pk = crypto.getPublicKey(SubjectPublicKeyInfo.fromEncoded(
        kp.getPublic().getEncoded()));
    Assert.assertTrue(pk.getClass().getName().startsWith("sun.security.ec."));

    // the JDK 16+ would parse brainpool keys, but cannot use them; JDK 11 to 15 can use them
    pk = crypto.getPublicKey(SubjectPublicKeyInfo.fromEncoded(resource("brainpoolP256r1.spki")));
    Assert.assertEquals(!sunEcSupports("brainpoolP256r1"), isXiKey(pk));
    PrivateKey sk = crypto.getPrivateKey(PrivateKeyInfo.fromEncoded(
        resource("brainpoolP256r1.p8")));
    assertSignVerify("SHA256WITHECDSA", new KeyPair(pk, sk));
    Assert.assertTrue(verify("SHA256WITHECDSA", pk, resource("msg.bin"),
        resource("brainpoolP256r1-sha256.sig")));

    // SM2 key and signature of OpenSSL
    pk = crypto.getPublicKey(SubjectPublicKeyInfo.fromEncoded(resource("sm2.spki")));
    Assert.assertTrue(verify("SM3WITHSM2", pk, resource("msg.bin"), resource("sm2-sm3.sig")));
  }

  /**
   * Brainpool keys created by SunEC (its curve table knows brainpool) are signed and verified by
   * xicrypto.
   */
  @Test
  public void testJdkBrainpoolKeys() throws Exception {
    KeyFactory sunEc = KeyFactory.getInstance("EC", "SunEC");
    PublicKey pk = sunEc.generatePublic(new X509EncodedKeySpec(resource("brainpoolP256r1.spki")));
    PrivateKey sk = sunEc.generatePrivate(new PKCS8EncodedKeySpec(resource("brainpoolP256r1.p8")));
    Assert.assertTrue(pk.getClass().getName().startsWith("sun.security.ec."));

    Assert.assertTrue(verify("SHA256WITHECDSA", pk, resource("msg.bin"),
        resource("brainpoolP256r1-sha256.sig")));
    assertSignVerify("SHA256WITHECDSA", new KeyPair(pk, sk));
  }

  /**
   * SunEC has no ECDSA with SHAKE, xicrypto implements it for all curves.
   */
  @Test
  public void testEcdsaShake() throws Exception {
    for (String curve : new String[]{"secp256r1", "brainpoolP256r1"}) {
      KeyPair kp = keyPair(curve);
      assertSignVerify("SHAKE128WITHECDSA", kp);
      assertSignVerify("SHAKE256WITHECDSA", kp);
    }
  }

  /**
   * Returns whether SunEC can generate keys on the curve, the criterion of the routing.
   */
  static boolean sunEcSupports(String curve) {
    try {
      KeyPairGenerator.getInstance("EC", "SunEC").initialize(new ECGenParameterSpec(curve));
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean isXiKey(PublicKey pk) {
    return pk.getClass().getName().startsWith("org.xipki.crypto.extra.");
  }

  private static KeyPair keyPair(String curve) throws Exception {
    KeyPairGenerator kpGen = crypto.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec(curve), RND);
    return kpGen.generateKeyPair();
  }

  private static void assertSignVerify(String alg, KeyPair kp) throws Exception {
    Signature sig = crypto.newSignature(alg);
    sig.initSign(kp.getPrivate(), RND);
    sig.update(MSG);
    byte[] value = sig.sign();
    Assert.assertTrue(alg, verify(alg, kp.getPublic(), MSG, value));
    Assert.assertFalse(alg, verify(alg, kp.getPublic(), new byte[]{1}, value));
  }

  private static boolean verify(String alg, PublicKey pk, byte[] msg, byte[] value)
      throws Exception {
    Signature sig = crypto.newSignature(alg);
    sig.initVerify(pk);
    sig.update(msg);
    return sig.verify(value);
  }

  private static byte[] resource(String name) throws IOException {
    try (InputStream is = EcRoutingTest.class.getResourceAsStream("/ec-openssl/" + name)) {
      Assert.assertNotNull("missing resource " + name, is);
      return is.readAllBytes();
    }
  }

}
