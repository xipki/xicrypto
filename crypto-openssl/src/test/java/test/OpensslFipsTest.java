// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.openssl.OpenSsl;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Tests in the FIPS mode of OpenSSL: the approved services work, and the others are rejected.
 * The rejections assume the default configuration of the provider fips (fipsmodule.cnf of
 * {@code make install_fips}). Skipped if not in the FIPS mode.
 * <p>
 * Example: OpenSSL built with {@code enable-fips}, and
 * <pre>
 * OPENSSL_CONF=openssl-fips.cnf OPENSSL_MODULES=&lt;prefix&gt;/lib/ossl-modules \
 * JDK_JAVA_OPTIONS="-Dxipki.openssl.lib=&lt;prefix&gt;/lib/libcrypto.3.dylib" mvn test
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OpensslFipsTest {

  private static final byte[] MSG = "message in the FIPS mode".getBytes(StandardCharsets.UTF_8);

  @FunctionalInterface
  private interface Op {
    void run() throws Exception;
  }

  private static CryptoApi openssl;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    Assume.assumeTrue("not in the FIPS mode", OpenSsl.isFipsEnabled());
    openssl = new OpensslTestBackend();
  }

  private static void assertRejected(String what, Op op) {
    try {
      op.run();
    } catch (Exception e) {
      return;
    }
    Assert.fail(what + " is accepted in the FIPS mode");
  }

  private static void assertSignVerify(String alg, KeyPair kp) throws Exception {
    Signature sig = openssl.newSignature(alg);
    sig.initSign(kp.getPrivate());
    sig.update(MSG);
    byte[] value = sig.sign();
    sig.initVerify(kp.getPublic());
    sig.update(MSG);
    Assert.assertTrue(alg, sig.verify(value));
  }

  private static KeyPair rsaKeyPair() throws Exception {
    KeyPairGenerator kpGen = openssl.newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    return kpGen.generateKeyPair();
  }

  @Test
  public void testRsa() throws Exception {
    KeyPair kp = rsaKeyPair();
    for (String alg : new String[]{"SHA256WITHRSA", "SHA3-256WITHRSA", "SHA256WITHRSAANDMGF1",
        "SHA512WITHRSAANDMGF1"}) {
      assertSignVerify(alg, kp);
    }

    Signature pss = openssl.newSignature("RSASSA-PSS");
    pss.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48,
        PSSParameterSpec.TRAILER_FIELD_BC));
    pss.initSign(kp.getPrivate());
    pss.update(MSG);
    byte[] pssValue = pss.sign();
    pss.initVerify(kp.getPublic());
    pss.update(MSG);
    Assert.assertTrue("RSASSA-PSS", pss.verify(pssValue));

    // SHA-1: signing is rejected, the verification of the JDK signatures is allowed
    assertRejected("SHA1WITHRSA signing", () -> assertSignVerify("SHA1WITHRSA", kp));
    Signature jdk = Signature.getInstance("SHA1withRSA");
    jdk.initSign(kp.getPrivate());
    jdk.update(MSG);
    byte[] value = jdk.sign();
    Signature sig = openssl.newSignature("SHA1WITHRSA");
    sig.initVerify(kp.getPublic());
    sig.update(MSG);
    Assert.assertTrue("SHA1WITHRSA verification", sig.verify(value));

    // OAEP with SHA-256
    OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1",
        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    Cipher cipher = openssl.newCipher("RSA/ECB/OAEPPadding");
    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
    byte[] encrypted = cipher.doFinal(MSG);
    cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
    Assert.assertArrayEquals(MSG, cipher.doFinal(encrypted));

    // PKCS#1 v1.5 encryption
    assertRejected("RSA PKCS#1 v1.5 encryption", () -> {
      Cipher c = openssl.newCipher("RSA/ECB/PKCS1Padding");
      c.init(Cipher.ENCRYPT_MODE, kp.getPublic());
      c.doFinal(MSG);
    });
  }

  @Test
  public void testEc() throws Exception {
    for (String curve : new String[]{"secp256r1", "secp384r1", "secp521r1"}) {
      KeyPairGenerator kpGen = openssl.newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec(curve));
      KeyPair kp = kpGen.generateKeyPair();
      assertSignVerify("SHA256WITHECDSA", kp);
      assertSignVerify("SHA3-384WITHECDSA", kp);
    }

    // composed of SHAKE and the signing of the hash: not offered in the FIPS mode
    for (String alg : new String[]{"SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}) {
      assertRejected(alg, () -> openssl.newSignature(alg));
    }

    assertRejected("brainpoolP256r1", () -> {
      KeyPairGenerator kpGen = openssl.newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
      kpGen.generateKeyPair();
    });
  }

  @Test
  public void testEdDsa() throws Exception {
    for (String alg : new String[]{"Ed25519", "Ed448"}) {
      assertSignVerify(alg, openssl.newKeyPairGenerator(alg).generateKeyPair());
    }
  }

  @Test
  public void testXdh() {
    Assert.assertThrows(UnsupportedOperationException.class,
        () -> openssl.generateX25519PrivateKey());
    Assert.assertThrows(UnsupportedOperationException.class,
        () -> openssl.generateX448PublicKey(new byte[56]));
  }

  @Test
  public void testHmacAndKdfs() throws Exception {
    Mac mac = openssl.newMac("HmacSHA256");
    mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
    Assert.assertEquals(32, mac.doFinal(MSG).length);
    assertRejected("HMAC with a 32-bit key", () -> {
      Mac m = openssl.newMac("HmacSHA256");
      m.init(new SecretKeySpec(new byte[4], "HmacSHA256"));
      m.doFinal(MSG);
    });

    char[] password = "a password of enough length".toCharArray();
    Assert.assertEquals(32,
        openssl.pbkdf2("HmacSHA256", password, new byte[16], 1000, 32).length);
    assertRejected("PBKDF2 with a 4-byte salt",
        () -> openssl.pbkdf2("HmacSHA256", password, new byte[4], 1000, 32));

    Assert.assertEquals(42, openssl.hkdfSha256Derive(new byte[32], null, MSG, 42).length);
    Assert.assertEquals(100, openssl.xof("SHAKE256", MSG, 100).length);
  }

  @Test
  public void testCiphers() throws Exception {
    SecretKey key = openssl.newKeyGenerator("AES").generateKey();
    byte[] iv = new byte[12];
    openssl.getSecureRandom().nextBytes(iv);
    Cipher cipher = openssl.newCipher("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    byte[] encrypted = cipher.doFinal(MSG);
    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    Assert.assertArrayEquals(MSG, cipher.doFinal(encrypted));

    Cipher wrap = openssl.newCipher("AESWrap");
    wrap.init(Cipher.ENCRYPT_MODE, key);
    byte[] wrapped = wrap.doFinal(new byte[32]);
    wrap.init(Cipher.DECRYPT_MODE, key);
    Assert.assertArrayEquals(new byte[32], wrap.doFinal(wrapped));

    // DESede: the decryption of the JDK ciphertexts only
    SecretKey desKey = openssl.newKeyGenerator("DESede").generateKey();
    IvParameterSpec desIv = new IvParameterSpec(new byte[8]);
    Cipher jdk = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(desKey.getEncoded(), "DESede"), desIv);
    byte[] desEncrypted = jdk.doFinal(MSG);
    Cipher des = openssl.newCipher("DESede/CBC/PKCS5Padding");
    des.init(Cipher.DECRYPT_MODE, desKey, desIv);
    Assert.assertArrayEquals(MSG, des.doFinal(desEncrypted));
    assertRejected("DESede encryption", () -> {
      Cipher c = openssl.newCipher("DESede/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE, desKey, desIv);
      c.doFinal(MSG);
    });
  }

}
