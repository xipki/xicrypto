// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.Hex;
import org.xipki.crypto.extra.ec.math.EcCurve;
import org.xipki.crypto.extra.XiPKIProvider;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests the EC services of the XiPKI provider (keys, key factory, key generation, ECDSA, SM2
 * keys) against BouncyCastle and OpenSSL.
 *
 * @author Lijun Liao (xipki)
 */
public class XiEcProviderTest {

  private static final String[] CURVES = {"brainpoolP256r1", "brainpoolP384r1",
      "brainpoolP512r1", "FRP256v1", "SM2", "secp256r1", "secp384r1", "secp521r1"};

  private static final String[] ECDSA_CURVES = {"brainpoolP256r1", "brainpoolP384r1",
      "brainpoolP512r1", "FRP256v1", "secp256r1", "secp521r1"};

  private static final String[] HASHES = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
      "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};

  private static final byte[] MSG = "message to be signed".getBytes(StandardCharsets.UTF_8);

  private static final SecureRandom RND = new SecureRandom();

  private static Provider xipki;

  private static Provider bc;

  @BeforeClass
  public static void init() {

    xipki = new XiPKIProvider();
    bc = new BouncyCastleProvider();
  }

  @Test
  public void testKeyGenerationAndEncoding() throws Exception {
    for (String curve : CURVES) {
      if ("SM2".equals(curve) && EcCurve.isSmDisabled()) {
        continue;
      }

      KeyPair kp = xiKeyPair(curve);
      ECPublicKey pk = (ECPublicKey) kp.getPublic();
      ECPrivateKey sk = (ECPrivateKey) kp.getPrivate();

      // XiPKI -> BouncyCastle
      KeyFactory bcKf = KeyFactory.getInstance("EC", bc);
      ECPublicKey bcPk = (ECPublicKey) bcKf.generatePublic(
          new X509EncodedKeySpec(pk.getEncoded()));
      ECPrivateKey bcSk = (ECPrivateKey) bcKf.generatePrivate(
          new PKCS8EncodedKeySpec(sk.getEncoded()));
      Assert.assertEquals(curve, pk.getW(), bcPk.getW());
      Assert.assertEquals(curve, sk.getS(), bcSk.getS());

      // BouncyCastle -> XiPKI
      KeyPairGenerator bcKpGen = KeyPairGenerator.getInstance("EC", bc);
      bcKpGen.initialize(new ECGenParameterSpec("SM2".equals(curve) ? "sm2p256v1" : curve));
      KeyPair bcKp = bcKpGen.generateKeyPair();
      KeyFactory kf = KeyFactory.getInstance("EC", xipki);
      ECPublicKey pk2 = (ECPublicKey) kf.generatePublic(
          new X509EncodedKeySpec(bcKp.getPublic().getEncoded()));
      ECPrivateKey sk2 = (ECPrivateKey) kf.generatePrivate(
          new PKCS8EncodedKeySpec(bcKp.getPrivate().getEncoded()));
      Assert.assertEquals(curve, ((ECPublicKey) bcKp.getPublic()).getW(), pk2.getW());
      Assert.assertEquals(curve, ((ECPrivateKey) bcKp.getPrivate()).getS(), sk2.getS());
      Assert.assertArrayEquals(curve, bcKp.getPublic().getEncoded(), pk2.getEncoded());

      // round trips: encodings and KeySpecs
      Assert.assertEquals(curve, pk, kf.generatePublic(new X509EncodedKeySpec(pk.getEncoded())));
      Assert.assertEquals(curve, sk,
          kf.generatePrivate(new PKCS8EncodedKeySpec(sk.getEncoded())));
      ECPublicKeySpec pkSpec = kf.getKeySpec(pk, ECPublicKeySpec.class);
      Assert.assertEquals(curve, pk, kf.generatePublic(pkSpec));
      ECPrivateKeySpec skSpec = kf.getKeySpec(sk, ECPrivateKeySpec.class);
      Assert.assertEquals(curve, sk, kf.generatePrivate(skSpec));

      // key generation with ECParameterSpec
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", xipki);
      kpGen.initialize(pk.getParams(), RND);
      Assert.assertNotNull(kpGen.generateKeyPair());

      // AlgorithmParameters
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC", xipki);
      params.init(new ECGenParameterSpec(curve));
      ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
      Assert.assertEquals(curve, pk.getParams().getOrder(), spec.getOrder());
    }
  }

  @Test
  public void testEcdsaWithBouncyCastle() throws Exception {
    for (String curve : ECDSA_CURVES) {
      KeyPair kp = xiKeyPair(curve);
      KeyFactory bcKf = KeyFactory.getInstance("EC", bc);
      PublicKey bcPk = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
      PrivateKey bcSk = bcKf.generatePrivate(
          new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

      for (String hash : HASHES) {
        String alg = hash + "WITHECDSA";
        String desc = curve + "/" + alg;

        // XiPKI signs (hedged), BouncyCastle verifies; signing needs the HMAC of the hash
        if (hmacAvailable(hash)) {
          byte[] sig = sign(xipki, alg, kp.getPrivate(), RND);
          Assert.assertTrue(desc, verify(bc, alg, bcPk, sig));
        }

        // BouncyCastle signs, XiPKI verifies
        byte[] sig = sign(bc, alg, bcSk, RND);
        Assert.assertTrue(desc, verify(xipki, alg, kp.getPublic(), sig));

        // changed message
        Signature verifier = Signature.getInstance(alg, xipki);
        verifier.initVerify(kp.getPublic());
        verifier.update(new byte[]{1, 2, 3});
        Assert.assertFalse(desc, verifier.verify(sig));
      }

      // SHAKE (RFC 8692), BouncyCastle has no ECDSA with SHAKE: self-test
      for (String alg : new String[]{"SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}) {
        byte[] sig = sign(xipki, alg, kp.getPrivate(), RND);
        Assert.assertTrue(curve + "/" + alg, verify(xipki, alg, kp.getPublic(), sig));
      }
    }
  }

  /**
   * Without SecureRandom, the signature is deterministic (RFC 6979) and equals the
   * deterministic ECDSA of BouncyCastle.
   */
  @Test
  public void testDeterministicEcdsa() throws Exception {
    for (String curve : ECDSA_CURVES) {
      KeyPair kp = xiKeyPair(curve);
      PrivateKey bcSk = KeyFactory.getInstance("EC", bc).generatePrivate(
          new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

      for (String hash : new String[]{"SHA256", "SHA384", "SHA512", "SHA3-256"}) {
        if (!hmacAvailable(hash)) {
          continue;
        }
        String desc = curve + "/" + hash;
        byte[] sig1 = sign(xipki, hash + "WITHECDSA", kp.getPrivate(), null);
        byte[] sig2 = sign(xipki, hash + "WITHECDSA", kp.getPrivate(), null);
        Assert.assertArrayEquals(desc, sig1, sig2);

        byte[] bcSig = sign(bc, hash + "WITHECDDSA", bcSk, null);
        Assert.assertArrayEquals(desc + " vs BouncyCastle ECDDSA", bcSig, sig1);

        // hedged: different signatures
        byte[] sig3 = sign(xipki, hash + "WITHECDSA", kp.getPrivate(), RND);
        Assert.assertFalse(desc, java.util.Arrays.equals(sig1, sig3));
      }
    }
  }

  /**
   * RFC 6979, A.2.5: P-256 with SHA-256, message "sample".
   */
  @Test
  public void testRfc6979Vector() throws Exception {
    BigInteger x = new BigInteger(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);
    ECParameterSpec params = ((ECPublicKey) xiKeyPair("secp256r1").getPublic()).getParams();
    PrivateKey sk = KeyFactory.getInstance("EC", xipki).generatePrivate(
        new ECPrivateKeySpec(x, params));

    Signature signer = Signature.getInstance("SHA256WITHECDSA", xipki);
    signer.initSign(sk);
    signer.update("sample".getBytes(StandardCharsets.US_ASCII));
    byte[] sig = signer.sign();

    String r = "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716";
    String s = "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8";
    // r and s have the highest bit set: INTEGER with leading 00
    String expected = "3046" + "022100" + r + "022100" + s;
    Assert.assertEquals(expected, Hex.encodeUpper(sig));
  }

  @Test
  public void testSm2WithBouncyCastle() throws Exception {
    Assume.assumeFalse("SM disabled", EcCurve.isSmDisabled());
    KeyPair kp = xiKeyPair("SM2");
    KeyFactory bcKf = KeyFactory.getInstance("EC", bc);
    PublicKey bcPk = bcKf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
    PrivateKey bcSk = bcKf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

    byte[] sig = sign(xipki, "SM3WITHSM2", kp.getPrivate(), RND);
    Assert.assertTrue(verify(bc, "SM3WITHSM2", bcPk, sig));

    sig = sign(bc, "SM3WITHSM2", bcSk, RND);
    Assert.assertTrue(verify(xipki, "SM3WITHSM2", kp.getPublic(), sig));
  }

  /**
   * Keys and signatures generated by OpenSSL 3.6.
   */
  @Test
  public void testOpenSslInterop() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("EC", xipki);
    byte[] msg = resource("msg.bin");

    // brainpoolP256r1, ECDSA with SHA-256
    PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(resource("brainpoolP256r1.spki")));
    PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(resource("brainpoolP256r1.p8")));
    Assert.assertTrue(verify(xipki, "SHA256WITHECDSA", pk, msg,
        resource("brainpoolP256r1-sha256.sig")));
    Assert.assertTrue(verify(xipki, "SHA256WITHECDSA", pk, msg,
        sign(xipki, "SHA256WITHECDSA", sk, msg, RND)));

    // SM2 with SM3, default user ID
    if (EcCurve.isSmDisabled()) {
      return;
    }
    pk = kf.generatePublic(new X509EncodedKeySpec(resource("sm2.spki")));
    sk = kf.generatePrivate(new PKCS8EncodedKeySpec(resource("sm2.p8")));
    Assert.assertTrue(verify(xipki, "SM3WITHSM2", pk, msg, resource("sm2-sm3.sig")));
    Assert.assertTrue(verify(xipki, "SM3WITHSM2", pk, msg,
        sign(xipki, "SM3WITHSM2", sk, msg, RND)));
  }

  @Test
  public void testInvalidKeys() throws Exception {
    KeyFactory kf = KeyFactory.getInstance("EC", xipki);
    ECPublicKey pk = (ECPublicKey) xiKeyPair("brainpoolP256r1").getPublic();
    ECParameterSpec params = pk.getParams();
    BigInteger n = params.getOrder();

    // point not on the curve
    ECPoint w = pk.getW();
    assertInvalidPublic(kf, new ECPublicKeySpec(
        new ECPoint(w.getAffineX(), w.getAffineY().add(BigInteger.ONE)), params));

    // private value out of range
    for (BigInteger s : new BigInteger[]{BigInteger.ZERO, n, n.add(BigInteger.ONE)}) {
      try {
        kf.generatePrivate(new ECPrivateKeySpec(s, params));
        Assert.fail("InvalidKeySpecException expected for s=" + s);
      } catch (InvalidKeySpecException e) {
        // expected
      }
    }

    // parameters not of a named curve
    SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.fromEncoded(pk.getEncoded());
    byte[] withNull = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, Asn1Null.INSTANCE),
        pkInfo.subjectPublicKey()).getEncoded();
    assertInvalidPublic(kf, new X509EncodedKeySpec(withNull));

    // point at infinity (encoded as 0x00)
    byte[] infinity = new SubjectPublicKeyInfo(pkInfo.getAlgorithm(), new byte[1]).getEncoded();
    assertInvalidPublic(kf, new X509EncodedKeySpec(infinity));

    // PKCS#8 with a public key that does not match
    ECPrivateKey sk1 = (ECPrivateKey) xiKeyPair("brainpoolP256r1").getPrivate();
    ECPrivateKey sk2 = (ECPrivateKey) xiKeyPair("brainpoolP256r1").getPrivate();
    byte[] mixed = replacePublicKey(sk1.getEncoded(), sk2.getEncoded());
    try {
      kf.generatePrivate(new PKCS8EncodedKeySpec(mixed));
      Assert.fail("InvalidKeySpecException expected for a non-matching public key");
    } catch (InvalidKeySpecException e) {
      // expected
    }
  }

  private static void assertInvalidPublic(KeyFactory kf, java.security.spec.KeySpec spec) {
    try {
      kf.generatePublic(spec);
      Assert.fail("InvalidKeySpecException expected");
    } catch (InvalidKeySpecException e) {
      // expected
    }
  }

  /**
   * Returns the first encoding with the public key (the last 65 bytes, uncompressed point of a
   * 256-bit curve) of the second one.
   */
  private static byte[] replacePublicKey(byte[] encoded1, byte[] encoded2) {
    byte[] r = encoded1.clone();
    System.arraycopy(encoded2, encoded2.length - 64, r, r.length - 64, 64);
    return r;
  }

  /**
   * Whether the JDK has the HMAC of the hash, needed for the nonce of RFC 6979 (HmacSHA3-*
   * requires JDK 16+).
   */
  private static boolean hmacAvailable(String hash) {
    try {
      javax.crypto.Mac.getInstance("Hmac" + hash);
      return true;
    } catch (java.security.NoSuchAlgorithmException e) {
      return false;
    }
  }

  private static KeyPair xiKeyPair(String curve) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", xipki);
    kpGen.initialize(new ECGenParameterSpec(curve), RND);
    return kpGen.generateKeyPair();
  }

  private static byte[] sign(Provider provider, String alg, PrivateKey key, SecureRandom rnd)
      throws Exception {
    return sign(provider, alg, key, MSG, rnd);
  }

  private static byte[] sign(Provider provider, String alg, PrivateKey key, byte[] msg,
                             SecureRandom rnd) throws Exception {
    Signature sig = Signature.getInstance(alg, provider);
    if (rnd == null) {
      sig.initSign(key);
    } else {
      sig.initSign(key, rnd);
    }
    sig.update(msg);
    return sig.sign();
  }

  private static boolean verify(Provider provider, String alg, PublicKey key, byte[] sigValue)
      throws Exception {
    return verify(provider, alg, key, MSG, sigValue);
  }

  private static boolean verify(Provider provider, String alg, PublicKey key, byte[] msg,
                                byte[] sigValue) throws Exception {
    Signature sig = Signature.getInstance(alg, provider);
    sig.initVerify(key);
    sig.update(msg);
    return sig.verify(sigValue);
  }

  private static byte[] resource(String name) throws IOException {
    try (InputStream is = XiEcProviderTest.class.getResourceAsStream("/ec-openssl/" + name)) {
      Assert.assertNotNull("missing resource " + name, is);
      return is.readAllBytes();
    }
  }

}
