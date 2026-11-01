// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.openssl.OpenSsl;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;

/**
 * The algorithms of OpenSSL against independent implementations: the JDK providers and
 * BouncyCastle, both in both directions.
 *
 * @author Lijun Liao (xipki)
 */
public class OpensslCrossTest {

  private static final byte[] MSG = "cross test message".getBytes(StandardCharsets.UTF_8);

  private static final Provider BC = new BouncyCastleProvider();

  private static CryptoApi openssl;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    openssl = new OpensslTestBackend();
  }

  /** Skips the test in the FIPS mode: it uses non-approved algorithms or parameters. */
  private static void assumeNotFips() {
    Assume.assumeFalse("FIPS mode", OpenSsl.isFipsEnabled());
  }

  private static KeyPair jdkKeyPair(String alg, Object param) throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance(alg);
    if (param instanceof Integer bits) {
      kpGen.initialize(bits);
    } else if (param != null) {
      kpGen.initialize((AlgorithmParameterSpec) param);
    }
    return kpGen.generateKeyPair();
  }

  private static byte[] sign(Signature sig, PrivateKey key) throws Exception {
    sig.initSign(key);
    sig.update(MSG);
    return sig.sign();
  }

  private static boolean verify(Signature sig, PublicKey key, byte[] sigValue)
      throws Exception {
    sig.initVerify(key);
    sig.update(MSG);
    return sig.verify(sigValue);
  }

  /** OpenSSL signs and verifies the keys of the other provider, and vice versa. */
  private static void assertCross(String opensslAlg, Signature other, KeyPair otherKp,
                                  KeyPair opensslKp) throws Exception {
    Signature sig = openssl.newSignature(opensslAlg);
    // OpenSSL signs with the key of the other provider, the other verifies
    Assert.assertTrue(opensslAlg, verify(other, otherKp.getPublic(),
        sign(sig, otherKp.getPrivate())));
    // the other signs, OpenSSL verifies
    Assert.assertTrue(opensslAlg, verify(sig, otherKp.getPublic(),
        sign(other, otherKp.getPrivate())));
    // the keys of OpenSSL in the other provider
    if (opensslKp != null) {
      Assert.assertTrue(opensslAlg, verify(other, opensslKp.getPublic(),
          sign(sig, opensslKp.getPrivate())));
    }
  }

  @Test
  public void testRsaSignatures() throws Exception {
    assumeNotFips();
    KeyPair jdkKp = jdkKeyPair("RSA", 2048);
    KeyPairGenerator kpGen = openssl.newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();

    for (String alg : new String[]{"SHA256WITHRSA", "SHA512WITHRSA", "SHA3-256WITHRSA"}) {
      assertCross(alg, Signature.getInstance(alg), jdkKp, kp);
    }

    // PSS: the same as RSASSA-PSS of the JDK with the parameters of the name
    for (String hash : new String[]{"SHA-1", "SHA-256", "SHA-384", "SHA3-256"}) {
      String name = hash.replace("SHA-", "SHA") + "WITHRSAANDMGF1";
      Signature jdk = Signature.getInstance("RSASSA-PSS");
      int saltLen = hash.equals("SHA-1") ? 20 : hash.endsWith("384") ? 48 : 32;
      jdk.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash),
          saltLen, 1));
      assertCross(name, jdk, jdkKp, kp);
    }

    // RSASSA-PSS with explicit parameters
    PSSParameterSpec spec = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA256,
        20, 1);
    Signature jdk = Signature.getInstance("RSASSA-PSS");
    jdk.setParameter(spec);
    Signature sig = openssl.newSignature("RSASSA-PSS");
    sig.setParameter(spec);
    Assert.assertTrue(verify(jdk, jdkKp.getPublic(), sign(sig, jdkKp.getPrivate())));
    sig.setParameter(spec);
    Assert.assertTrue(verify(sig, jdkKp.getPublic(), sign(jdk, jdkKp.getPrivate())));
  }

  /** RFC 8702: the EMSA-PSS encoding of crypto-be-openssl against BouncyCastle. */
  @Test
  public void testRsaPssShake() throws Exception {
    assumeNotFips();
    // odd modulus sizes: emLen < k for 2049 bits
    for (int bits : new int[]{2048, 2049, 3072}) {
      KeyPair kp = jdkKeyPair("RSA", bits);
      for (String alg : new String[]{"SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS"}) {
        assertCross(alg, Signature.getInstance(alg, BC), kp, null);

        // tampered signature
        byte[] sigValue = sign(openssl.newSignature(alg), kp.getPrivate());
        sigValue[sigValue.length / 2] ^= 1;
        Assert.assertFalse(verify(openssl.newSignature(alg), kp.getPublic(), sigValue));
        Assert.assertFalse(verify(openssl.newSignature(alg), kp.getPublic(), new byte[10]));
      }
    }
  }

  @Test
  public void testEcdsa() throws Exception {
    assumeNotFips();
    for (String curve : new String[]{"secp256r1", "secp384r1", "secp521r1"}) {
      KeyPair jdkKp = jdkKeyPair("EC", new ECGenParameterSpec(curve));
      for (String alg : new String[]{"SHA256WITHECDSA", "SHA512WITHECDSA", "SHA3-256WITHECDSA"}) {
        assertCross(alg, Signature.getInstance(alg), jdkKp, null);
      }
    }

    // brainpool and SHAKE (RFC 8692) against BouncyCastle
    for (String curve : new String[]{"secp256r1", "brainpoolP256r1", "brainpoolP512r1"}) {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
      kpGen.initialize(new ECGenParameterSpec(curve));
      KeyPair bcKp = kpGen.generateKeyPair();
      assertCross("SHA256WITHECDSA", Signature.getInstance("SHA256WITHECDSA", BC), bcKp, null);
      assertCross("SHAKE128WITHECDSA", Signature.getInstance("SHAKE128WITHECDSA", BC),
          bcKp, null);
      assertCross("SHAKE256WITHECDSA", Signature.getInstance("SHAKE256WITHECDSA", BC),
          bcKp, null);
    }
  }

  @Test
  public void testEdDsa() throws Exception {
    for (String alg : new String[]{"Ed25519", "Ed448"}) {
      KeyPair jdkKp = jdkKeyPair(alg, null);
      KeyPair kp = openssl.newKeyPairGenerator(alg).generateKeyPair();
      assertCross(alg, Signature.getInstance(alg), jdkKp, kp);

      // EdDSA is deterministic: the same signatures
      Assert.assertArrayEquals(sign(Signature.getInstance(alg), jdkKp.getPrivate()),
          sign(openssl.newSignature(alg), jdkKp.getPrivate()));

      // the public point equals that of the JDK
      PublicKey pk = openssl.newKeyFactory(alg).generatePublic(
          new X509EncodedKeySpec(jdkKp.getPublic().getEncoded()));
      EdECPublicKey jdkPk = (EdECPublicKey) jdkKp.getPublic();
      Assert.assertEquals(jdkPk.getPoint().getY(), ((EdECPublicKey) pk).getPoint().getY());
      Assert.assertEquals(jdkPk.getPoint().isXOdd(), ((EdECPublicKey) pk).getPoint().isXOdd());
      PublicKey fromSpec = openssl.newKeyFactory(alg).generatePublic(
          new EdECPublicKeySpec(jdkPk.getParams(), jdkPk.getPoint()));
      Assert.assertArrayEquals(jdkPk.getEncoded(), fromSpec.getEncoded());
    }
  }

  @Test
  public void testXdh() throws Exception {
    assumeNotFips();
    for (String alg : new String[]{"X25519", "X448"}) {
      KeyPair jdkKp = jdkKeyPair(alg, null);
      KeyPair kp = openssl.newKeyPairGenerator(alg).generateKeyPair();

      KeyAgreement jdkKa = KeyAgreement.getInstance(alg);
      jdkKa.init(jdkKp.getPrivate());
      jdkKa.doPhase(kp.getPublic(), true);
      KeyAgreement ka = openssl.newKeyAgreement(alg);
      ka.init(kp.getPrivate());
      ka.doPhase(jdkKp.getPublic(), true);
      Assert.assertArrayEquals(alg, jdkKa.generateSecret(), ka.generateSecret());

      XECPublicKey jdkPk = (XECPublicKey) jdkKp.getPublic();
      PublicKey fromSpec = openssl.newKeyFactory(alg).generatePublic(
          new XECPublicKeySpec(jdkPk.getParams(), jdkPk.getU()));
      Assert.assertArrayEquals(jdkPk.getEncoded(), fromSpec.getEncoded());
      Assert.assertEquals(jdkPk.getU(), ((XECPublicKey) fromSpec).getU());
    }
  }

  @Test
  public void testEcdh() throws Exception {
    KeyPair jdkKp = jdkKeyPair("EC", new ECGenParameterSpec("secp384r1"));
    KeyPairGenerator kpGen = openssl.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec("secp384r1"));
    KeyPair kp = kpGen.generateKeyPair();

    KeyAgreement jdkKa = KeyAgreement.getInstance("ECDH");
    jdkKa.init(jdkKp.getPrivate());
    jdkKa.doPhase(kp.getPublic(), true);
    KeyAgreement ka = openssl.newKeyAgreement("ECDH");
    ka.init(kp.getPrivate());
    ka.doPhase(jdkKp.getPublic(), true);
    Assert.assertArrayEquals(jdkKa.generateSecret(), ka.generateSecret());
  }

  @Test
  public void testKeyConversions() throws Exception {
    // RSA: the values of the keys, and the keys of the specs
    KeyPair jdkKp = jdkKeyPair("RSA", 2048);
    KeyFactory kf = openssl.newKeyFactory("RSA");
    RSAPrivateCrtKey jdkSk = (RSAPrivateCrtKey) jdkKp.getPrivate();
    RSAPrivateCrtKey sk = (RSAPrivateCrtKey) kf.generatePrivate(
        new PKCS8EncodedKeySpec(jdkSk.getEncoded()));
    Assert.assertEquals(jdkSk.getModulus(), sk.getModulus());
    Assert.assertEquals(jdkSk.getPrivateExponent(), sk.getPrivateExponent());
    Assert.assertEquals(jdkSk.getPrimeQ(), sk.getPrimeQ());
    Assert.assertEquals(jdkSk.getCrtCoefficient(), sk.getCrtCoefficient());

    RSAPublicKey jdkPk = (RSAPublicKey) jdkKp.getPublic();
    PublicKey pk = kf.generatePublic(
        new RSAPublicKeySpec(jdkPk.getModulus(), jdkPk.getPublicExponent()));
    Assert.assertArrayEquals(jdkPk.getEncoded(), pk.getEncoded());
    PrivateKey sk2 = kf.generatePrivate(kf.getKeySpec(sk, RSAPrivateCrtKeySpec.class));
    Assert.assertTrue(verify(Signature.getInstance("SHA256WITHRSA"), jdkPk,
        sign(openssl.newSignature("SHA256WITHRSA"), sk2)));

    // EC: the values of the keys, and the keys of the specs
    jdkKp = jdkKeyPair("EC", new ECGenParameterSpec("secp256r1"));
    kf = openssl.newKeyFactory("EC");
    ECPublicKey jdkEcPk = (ECPublicKey) jdkKp.getPublic();
    ECPublicKey ecPk = (ECPublicKey) kf.generatePublic(
        new X509EncodedKeySpec(jdkEcPk.getEncoded()));
    Assert.assertEquals(jdkEcPk.getW(), ecPk.getW());
    Assert.assertEquals(jdkEcPk.getParams().getCurve(), ecPk.getParams().getCurve());
    Assert.assertEquals(jdkEcPk.getParams().getGenerator(), ecPk.getParams().getGenerator());

    PublicKey ecPk2 = kf.generatePublic(new ECPublicKeySpec(jdkEcPk.getW(),
        jdkEcPk.getParams()));
    Assert.assertArrayEquals(jdkEcPk.getEncoded(), ecPk2.getEncoded());

    ECPrivateKey jdkEcSk = (ECPrivateKey) jdkKp.getPrivate();
    PrivateKey ecSk = kf.generatePrivate(new ECPrivateKeySpec(jdkEcSk.getS(),
        jdkEcSk.getParams()));
    Assert.assertEquals(jdkEcSk.getS(), ((ECPrivateKey) ecSk).getS());
    Assert.assertTrue(verify(Signature.getInstance("SHA256WITHECDSA"), jdkEcPk,
        sign(openssl.newSignature("SHA256WITHECDSA"), ecSk)));
  }

  @Test
  public void testAes() throws Exception {
    for (int keyLen : new int[]{16, 24, 32}) {
      byte[] keyBytes = new byte[keyLen];
      openssl.getSecureRandom().nextBytes(keyBytes);
      SecretKey key = new SecretKeySpec(keyBytes, "AES");
      byte[] data = new byte[1000 + keyLen];
      openssl.getSecureRandom().nextBytes(data);

      // GCM, with AAD and a 16-byte IV
      for (int ivLen : new int[]{12, 16}) {
        byte[] iv = new byte[ivLen];
        openssl.getSecureRandom().nextBytes(iv);
        GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
        Cipher jdk = Cipher.getInstance("AES/GCM/NoPadding");
        jdk.init(Cipher.ENCRYPT_MODE, key, gcm);
        jdk.updateAAD(MSG);
        byte[] ct = jdk.doFinal(data);

        Cipher c = openssl.newCipher("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, gcm);
        c.updateAAD(MSG);
        Assert.assertArrayEquals(ct, c.doFinal(data));

        c.init(Cipher.DECRYPT_MODE, key, gcm);
        c.updateAAD(MSG);
        Assert.assertArrayEquals(data, c.doFinal(ct));

        // a modified ciphertext
        ct[3] ^= 1;
        c.init(Cipher.DECRYPT_MODE, key, gcm);
        c.updateAAD(MSG);
        byte[] modified = ct;
        Assert.assertThrows(AEADBadTagException.class, () -> c.doFinal(modified));
      }

      // CBC in parts
      byte[] iv = new byte[16];
      openssl.getSecureRandom().nextBytes(iv);
      Cipher jdk = Cipher.getInstance("AES/CBC/PKCS5Padding");
      jdk.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] ct = jdk.doFinal(data);
      Cipher c = openssl.newCipher("AES/CBC/PKCS5Padding");
      c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] part1 = c.update(ct, 0, 100);
      byte[] part2 = c.doFinal(ct, 100, ct.length - 100);
      byte[] pt = new byte[part1.length + part2.length];
      System.arraycopy(part1, 0, pt, 0, part1.length);
      System.arraycopy(part2, 0, pt, part1.length, part2.length);
      Assert.assertArrayEquals(data, pt);
      // reusable after doFinal
      Assert.assertArrayEquals(data, c.doFinal(ct));

      // key wrap with padding against BouncyCastle
      Cipher bcKwp = Cipher.getInstance("AESWrapPad", BC);
      bcKwp.init(Cipher.WRAP_MODE, key);
      SecretKey toWrap = new SecretKeySpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9}, "HmacSHA256");
      byte[] wrapped = bcKwp.wrap(toWrap);
      c = openssl.newCipher("AESWrapPad");
      c.init(Cipher.UNWRAP_MODE, key);
      Assert.assertArrayEquals(toWrap.getEncoded(),
          c.unwrap(wrapped, "HmacSHA256", Cipher.SECRET_KEY).getEncoded());
    }
  }

  @Test
  public void testRsaCiphers() throws Exception {
    assumeNotFips();
    KeyPair jdkKp = jdkKeyPair("RSA", 2048);
    byte[] data = "secret".getBytes(StandardCharsets.US_ASCII);

    OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1",
        MGF1ParameterSpec.SHA256, new PSource.PSpecified(new byte[]{1, 2, 3}));
    Cipher jdk = Cipher.getInstance("RSA/ECB/OAEPPadding");
    jdk.init(Cipher.ENCRYPT_MODE, jdkKp.getPublic(), oaep);
    Cipher c = openssl.newCipher("RSA/ECB/OAEPPadding");
    c.init(Cipher.DECRYPT_MODE, jdkKp.getPrivate(), oaep);
    Assert.assertArrayEquals(data, c.doFinal(jdk.doFinal(data)));

    // the default OAEP parameters: SHA-1, MGF1 with SHA-1
    jdk.init(Cipher.ENCRYPT_MODE, jdkKp.getPublic());
    c.init(Cipher.DECRYPT_MODE, jdkKp.getPrivate());
    Assert.assertArrayEquals(data, c.doFinal(jdk.doFinal(data)));

    jdk = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    c = openssl.newCipher("RSA/NONE/PKCS1PADDING");
    c.init(Cipher.ENCRYPT_MODE, jdkKp.getPublic());
    jdk.init(Cipher.DECRYPT_MODE, jdkKp.getPrivate());
    Assert.assertArrayEquals(data, jdk.doFinal(c.doFinal(data)));

    // raw RSA: the private key operation, then the public one
    c = openssl.newCipher("RSA/ECB/NoPadding");
    c.init(Cipher.DECRYPT_MODE, jdkKp.getPrivate());
    byte[] raw = c.doFinal(data);
    jdk = Cipher.getInstance("RSA/ECB/NoPadding");
    jdk.init(Cipher.ENCRYPT_MODE, jdkKp.getPublic());
    byte[] back = jdk.doFinal(raw);
    Assert.assertArrayEquals(data, Arrays.copyOfRange(back,
        back.length - data.length, back.length));
  }

  @Test
  public void testDesedeAndMacs() throws Exception {
    byte[] iv = new byte[8];
    // 112 bits: two keys (K3 = K1); 168 bits and its alias 192: three keys
    for (int keySize : new int[]{112, 168, 192}) {
      KeyGenerator kg = openssl.newKeyGenerator("DESede");
      kg.init(keySize);
      byte[] k = kg.generateKey().getEncoded();
      Assert.assertEquals(24, k.length);
      // odd parity
      for (byte b : k) {
        Assert.assertEquals(1, Integer.bitCount(b & 0xFF) % 2);
      }
      byte[] k1 = Arrays.copyOfRange(k, 0, 8);
      byte[] k2 = Arrays.copyOfRange(k, 8, 16);
      byte[] k3 = Arrays.copyOfRange(k, 16, 24);
      Assert.assertEquals(keySize == 112, Arrays.equals(k1, k3));
      Assert.assertFalse(Arrays.equals(k1, k2));
      for (byte[] sub : new byte[][]{k1, k2, k3}) {
        Assert.assertFalse(DESKeySpec.isWeak(sub, 0));
      }

      SecretKey key = new SecretKeySpec(k, "DESede");
      Cipher jdk = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      jdk.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      Cipher c = openssl.newCipher("DESede/CBC/PKCS5Padding");
      c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      Assert.assertArrayEquals(MSG, c.doFinal(jdk.doFinal(MSG)));
    }
    KeyGenerator kg = openssl.newKeyGenerator("DESede");
    Assert.assertThrows(InvalidParameterException.class, () -> kg.init(128));

    byte[] macKey = new byte[32];
    openssl.getSecureRandom().nextBytes(macKey);
    for (String alg : new String[]{"HmacSHA256", "HmacSHA512", "HmacSHA3-384"}) {
      Mac jdkMac = Mac.getInstance(alg);
      jdkMac.init(new SecretKeySpec(macKey, alg));
      Mac mac = openssl.newMac(alg);
      mac.init(new SecretKeySpec(macKey, alg));
      mac.update(MSG, 0, 5);
      Mac clone = (Mac) mac.clone();
      mac.update(MSG, 5, MSG.length - 5);
      clone.update(MSG, 5, MSG.length - 5);
      byte[] expected = jdkMac.doFinal(MSG);
      Assert.assertArrayEquals(alg, expected, mac.doFinal());
      Assert.assertArrayEquals(alg, expected, clone.doFinal());
      // reusable after doFinal
      Assert.assertArrayEquals(alg, expected, mac.doFinal(MSG));
    }
  }

}
