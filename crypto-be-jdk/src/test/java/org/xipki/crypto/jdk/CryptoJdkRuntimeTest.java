// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Tests the behaviour of crypto-be-jdk on the different JDK versions: ML-DSA and ML-KEM require
 * JDK 25+, EdDSA JDK 15+, HmacSHA3 and SHA3 with RSA JDK 16+; on an older JDK they fail with a
 * clear message. Also the ML-KEM through reflection ({@link JdkCompat.Kem}).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkRuntimeTest {

  private static final int FEATURE = JdkCompat.FEATURE;

  private static final CryptoJdk CRYPTO = new CryptoJdk();

  private static final SecureRandom RND = new SecureRandom();

  @Test
  public void testRequirements() throws Exception {
    // independent of the running JDK
    String[][] pqc = {{"KeyPairGenerator", "ML-DSA"}, {"KeyFactory", "ML-KEM"},
        {"Signature", "ML-DSA-65"}, {"KEM", "ML-KEM"}, {"KeyFactory", "2.16.840.1.101.3.4.3.17"},
        {"KeyFactory", "2.16.840.1.101.3.4.4.3"}};
    for (String[] c : pqc) {
      JdkCompat.checkPqc(c[0], c[1], 25);
      try {
        JdkCompat.checkPqc(c[0], c[1], 24);
        Assert.fail(c[1] + " accepted on JDK 24");
      } catch (NoSuchAlgorithmException e) {
        Assert.assertTrue(e.getMessage(), e.getMessage().contains("requires JDK 25"));
      }
    }
    // not PQC: no check before the lookup
    JdkCompat.checkPqc("Signature", "SHA256WITHECDSA", 11);
    JdkCompat.checkPqc("KeyPairGenerator", "Ed25519", 11);

    Assert.assertEquals(15, JdkCompat.minVersion("KeyPairGenerator", "Ed25519"));
    Assert.assertEquals(15, JdkCompat.minVersion("KeyFactory", "1.3.101.113"));
    // SHA3 works on every JDK 11+ (on JDK 11 to 15 with xicrypto)
    Assert.assertEquals(0, JdkCompat.minVersion("Mac", "HmacSHA3-256"));
    Assert.assertEquals(0, JdkCompat.minVersion("Signature", "SHA3-384WITHRSA"));
    Assert.assertEquals(0, JdkCompat.minVersion("Signature", "2.16.840.1.101.3.4.3.14"));
    Assert.assertEquals(0, JdkCompat.minVersion("Signature", "SHA3-256WITHECDSA"));
    Assert.assertEquals(0, JdkCompat.minVersion("Mac", "HmacSHA256"));
    Assert.assertEquals(0, JdkCompat.minVersion("KeyPairGenerator", "X25519"));

    Assert.assertTrue(JdkCompat.hint("KeyPairGenerator", "Ed25519", 11)
        .contains("requires JDK 15"));
    Assert.assertEquals("", JdkCompat.hint("KeyPairGenerator", "Ed25519", 15));
    Assert.assertEquals("", JdkCompat.hint("Mac", "HmacSHA3-256", 11));
    Assert.assertEquals("", JdkCompat.hint("Mac", "HmacSHA256", 11));
  }

  /**
   * On a JDK older than 25, every ML-DSA / ML-KEM entry point fails with the message.
   */
  @Test
  public void testPqcOnOldJdk() throws Exception {
    Assume.assumeTrue("JDK 25+", FEATURE < JdkCompat.PQC);

    assertPqcError(() -> CRYPTO.generateKeyPair(MldsaVariant.ml_dsa_44, RND));
    assertPqcError(() -> CRYPTO.generateKeyPair(MlkemVariant.ml_kem_768, RND));
    assertPqcError(() -> CRYPTO.newSignature("ML-DSA-65"));
    assertPqcError(() -> CRYPTO.newKeyFactory("ML-DSA"));
    assertPqcError(() -> CRYPTO.newKeyPairGenerator("ML-KEM"));
    assertPqcError(() -> CRYPTO.expandMldsaSeed(MldsaVariant.ml_dsa_44, new byte[32]));
    assertPqcError(() -> CRYPTO.expandMlkemSeed(MlkemVariant.ml_kem_512, new byte[64]));
    assertPqcError(() -> CRYPTO.encapsulateKey(MlkemVariant.ml_kem_768, new byte[1184], RND));
    assertPqcError(() -> CRYPTO.decapsulateKey(MlkemVariant.ml_kem_768, new byte[64],
        new byte[1088]));

    // keys of BouncyCastle
    KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-44", new BouncyCastleProvider())
        .generateKeyPair();
    assertPqcError(() -> CRYPTO.getPublicKey(
        SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded())));
    assertPqcError(() -> CRYPTO.getPrivateKey(
        PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded())));
  }

  /**
   * On JDK 11 to 14, EdDSA is not available, with the hint on the required JDK version.
   */
  @Test
  public void testEdDsaOnOldJdk() throws Exception {
    Assume.assumeTrue("JDK 15+", FEATURE < 15);
    assertHint(() -> CRYPTO.newKeyPairGenerator("Ed25519"), "requires JDK 15");
    assertHint(() -> CRYPTO.newSignature("Ed448"), "requires JDK 15");
  }

  /**
   * On JDK 11 to 15, which have SHA3 only as MessageDigest, HmacSHA3, SHA3 with RSA (PKCS#1
   * v1.5 and PSS) and the signing of SHA3-ECDSA come from xicrypto; checked against
   * BouncyCastle.
   */
  @Test
  public void testSha3OnOldJdk() throws Exception {
    Assume.assumeTrue("JDK 16+", FEATURE < 16);
    java.security.Provider bc = new BouncyCastleProvider();
    byte[] data = "message to be signed".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    // HmacSHA3
    javax.crypto.Mac mac = CRYPTO.newMac("HmacSHA3-256");
    Assert.assertEquals("XiPKI", mac.getProvider().getName());
    byte[] key = new byte[200];
    RND.nextBytes(key);
    javax.crypto.Mac bcMac = javax.crypto.Mac.getInstance("HmacSHA3-256", bc);
    for (int keyLen : new int[] {16, 136, 200}) {
      javax.crypto.spec.SecretKeySpec k = new javax.crypto.spec.SecretKeySpec(
          java.util.Arrays.copyOf(key, keyLen), "HmacSHA3-256");
      mac.init(k);
      bcMac.init(k);
      Assert.assertArrayEquals("key length " + keyLen, bcMac.doFinal(data), mac.doFinal(data));
    }

    // SHA3 with RSA: PKCS#1 v1.5 (deterministic, equal to BouncyCastle) and PSS
    KeyPairGenerator rsaGen = CRYPTO.newKeyPairGenerator("RSA");
    rsaGen.initialize(2048);
    KeyPair rsa = rsaGen.generateKeyPair();
    Signature signer = CRYPTO.newSignature("SHA3-256WITHRSA");
    Assert.assertEquals("XiPKI", signer.getProvider().getName());
    signer.initSign(rsa.getPrivate());
    signer.update(data);
    byte[] sig = signer.sign();
    Signature bcSigner = Signature.getInstance("SHA3-256WITHRSA", bc);
    bcSigner.initSign(rsa.getPrivate());
    bcSigner.update(data);
    Assert.assertArrayEquals(bcSigner.sign(), sig);

    for (String alg : new String[] {"SHA3-256WITHRSA", "SHA3-256WITHRSAANDMGF1",
        "SHA3-512WITHRSAANDMGF1"}) {
      assertInteropWithBc(alg, rsa, bc, data);
    }

    // SHA3-ECDSA: deterministic (RFC 6979 with HmacSHA3) without SecureRandom
    KeyPairGenerator ecGen = CRYPTO.newKeyPairGenerator("EC");
    ecGen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ec = ecGen.generateKeyPair();
    byte[] sig1 = sign(CRYPTO.newSignature("SHA3-256WITHECDSA"), ec, data);
    byte[] sig2 = sign(CRYPTO.newSignature("SHA3-256WITHECDSA"), ec, data);
    Assert.assertArrayEquals("deterministic", sig1, sig2);
    assertInteropWithBc("SHA3-256WITHECDSA", ec, bc, data);
  }

  private static byte[] sign(Signature signer, KeyPair kp, byte[] data) throws Exception {
    signer.initSign(kp.getPrivate());
    signer.update(data);
    return signer.sign();
  }

  /**
   * Signs with crypto-be-jdk and verifies with BouncyCastle, and vice versa.
   */
  private static void assertInteropWithBc(String alg, KeyPair kp, java.security.Provider bc,
      byte[] data) throws Exception {
    byte[] sig = sign(CRYPTO.newSignature(alg), kp, data);
    Signature verifier = Signature.getInstance(alg, bc);
    verifier.initVerify(kp.getPublic());
    verifier.update(data);
    Assert.assertTrue(alg + ": BouncyCastle verifies crypto-be-jdk", verifier.verify(sig));

    Signature bcSigner = Signature.getInstance(alg, bc);
    bcSigner.initSign(kp.getPrivate(), RND);
    bcSigner.update(data);
    sig = bcSigner.sign();
    verifier = CRYPTO.newSignature(alg);
    verifier.initVerify(kp.getPublic());
    verifier.update(data);
    Assert.assertTrue(alg + ": crypto-be-jdk verifies BouncyCastle", verifier.verify(sig));
  }

  /**
   * X25519 and X448 keys of crypto-be-jdk are encoded as in RFC 8410 on every JDK (JDK 11 does
   * not, JDK-8213363), are readable from RFC 8410 encodings, and work in the key agreement.
   */
  @Test
  public void testXdhRfc8410() throws Exception {
    java.security.Provider bc = new BouncyCastleProvider();
    for (String alg : new String[] {"X25519", "X448"}) {
      // keys of crypto-be-jdk: readable by BouncyCastle
      KeyPair kp = CRYPTO.newKeyPairGenerator(alg).generateKeyPair();
      java.security.KeyFactory bcKf = java.security.KeyFactory.getInstance(alg, bc);
      java.security.PrivateKey bcSk = bcKf.generatePrivate(
          new java.security.spec.PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
      java.security.PublicKey bcPk = bcKf.generatePublic(
          new java.security.spec.X509EncodedKeySpec(kp.getPublic().getEncoded()));
      // RFC 8410: no parameters in the AlgorithmIdentifier, CurvePrivateKey (OCTET STRING)
      Assert.assertArrayEquals(alg, bcPk.getEncoded(), kp.getPublic().getEncoded());
      PrivateKeyInfo info = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());
      Assert.assertNull(alg, info.getPrivateKeyAlgorithm().getParameters());
      Assert.assertEquals(alg, 0x04, info.privateKey()[0] & 0xFF);

      // keys of BouncyCastle (PKCS#8 v2 with the public key): readable by crypto-be-jdk
      KeyPair bcKp = KeyPairGenerator.getInstance(alg, bc).generateKeyPair();
      java.security.PrivateKey sk = CRYPTO.getPrivateKey(
          PrivateKeyInfo.fromEncoded(bcKp.getPrivate().getEncoded()));
      java.security.PublicKey pk = CRYPTO.getPublicKey(
          SubjectPublicKeyInfo.fromEncoded(bcKp.getPublic().getEncoded()));
      Assert.assertArrayEquals(alg, bcKp.getPublic().getEncoded(), pk.getEncoded());

      // key agreement in both directions
      javax.crypto.KeyAgreement ka = CRYPTO.newKeyAgreement(alg);
      ka.init(sk);
      ka.doPhase(kp.getPublic(), true);
      byte[] z1 = ka.generateSecret();
      javax.crypto.KeyAgreement bcKa = javax.crypto.KeyAgreement.getInstance(alg, bc);
      bcKa.init(bcSk);
      bcKa.doPhase(bcKp.getPublic(), true);
      Assert.assertArrayEquals(alg, z1, bcKa.generateSecret());
    }
  }

  /**
   * The wrapper of the JDK 11 workaround produces the encoding of RFC 8410, on every JDK: on
   * JDK 12+ it is equal to the encoding of the JDK itself.
   */
  @Test
  public void testJdk11XdhWrapper() throws Exception {
    for (String alg : new String[] {"X25519", "X448"}) {
      KeyPair jdk = KeyPairGenerator.getInstance(alg).generateKeyPair();
      byte[] sk = Jdk11Xdh.wrap(jdk.getPrivate()).getEncoded();
      byte[] pk = Jdk11Xdh.wrap(jdk.getPublic()).getEncoded();
      if (FEATURE >= Jdk11Xdh.FIXED_IN) {
        Assert.assertArrayEquals(alg, jdk.getPrivate().getEncoded(), sk);
        Assert.assertArrayEquals(alg, jdk.getPublic().getEncoded(), pk);
      }
      // the conversion into the form of JDK 11 and back
      byte[] jdk11 = Jdk11Xdh.toJdk11Pkcs8(sk);
      Assert.assertEquals(alg, sk.length - 2, jdk11.length);
      Assert.assertArrayEquals(alg, jdk11, Jdk11Xdh.toJdk11Pkcs8(jdk11));
    }
    Assert.assertEquals(FEATURE < 12, Jdk11Xdh.isNeeded("X25519"));
    Assert.assertFalse(Jdk11Xdh.isNeeded("EC"));
  }

  @Test
  public void testMlkemInvalidCiphertext() throws Exception {
    Assume.assumeTrue("ML-KEM requires JDK 25+", JdkCompat.isPqcAvailable());
    for (MlkemVariant variant : MlkemVariant.values()) {
      byte[] pk = SubjectPublicKeyInfo.fromEncoded(
          CRYPTO.generateKeyPair(variant, RND).getPublic().getEncoded()).subjectPublicKey();
      SecretWithEncap encap = CRYPTO.encapsulateKey(variant, pk, RND);
      Assert.assertEquals(32, encap.secret().length);

      byte[] seed = new byte[64];
      RND.nextBytes(seed);
      byte[] shortCt = new byte[encap.encap().length - 1];
      try {
        CRYPTO.decapsulateKey(variant, seed, shortCt);
        Assert.fail(variant + ": invalid ciphertext length accepted");
      } catch (IllegalArgumentException e) {
        // expected: the GeneralSecurityException of the JDK, unwrapped by JdkCompat.Kem
        Assert.assertTrue(variant + ": " + e, e.getCause() instanceof GeneralSecurityException);
      }
    }
  }

  @FunctionalInterface
  private interface Call {
    Object run() throws Exception;
  }

  private static void assertPqcError(Call call) {
    assertHint(call, "requires JDK 25");
  }

  private static void assertHint(Call call, String hint) {
    try {
      call.run();
      Assert.fail("no exception, expected: " + hint);
    } catch (Exception e) {
      // the message of the exception or of its cause
      boolean found = false;
      for (Throwable t = e; t != null && !found; t = t.getCause()) {
        found = t.getMessage() != null && t.getMessage().contains(hint);
      }
      Assert.assertTrue(e + ": expected " + hint, found);
      Assert.assertTrue(e.toString(), e instanceof NoSuchAlgorithmException
          || e instanceof InvalidKeySpecException || e instanceof IllegalArgumentException
          || e instanceof UnsupportedOperationException);
    }
  }

}
