// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiConformance;
import org.xipki.crypto.bcfips.CryptoBcFips;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Conformance tests of the BouncyCastle FIPS backend, in the approved-only mode of BC-FIPS. The
 * tests of the base class with operations that are not approved are replaced: the approved part
 * is tested, and the rejection of the other part. The expected values come from the providers
 * of the JDK.
 *
 * @author Lijun Liao (xipki)
 */
public class BcProvUtilTest extends CryptoApiConformance {

  private static final CryptoApi cryptoApi = new CryptoBcFips();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

  /** SM3 and SM3withSM2 are not offered: they would be computed outside BC-FIPS. */
  @Override
  protected boolean supportsSm() {
    return false;
  }

  /** SHAKE128/256withRSAPSS is not offered: its EMSA-PSS would be computed outside BC-FIPS. */
  @Override
  protected boolean supportsRsaPssShake() {
    return false;
  }

  /** SHAKE128/256withECDSA: not offered by the BC-FIPS backend. */
  @Override
  protected boolean supportsEcdsaShake() {
    return false;
  }

  /** X25519 and X448 are not approved. */
  @Override
  protected boolean supportsXdh() {
    return false;
  }

  /** HMAC keys of at least 112 bits. */
  @Override
  @Test
  public void testMac() throws Exception {
    byte[] data = "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII);
    byte[] key = new byte[20];
    rnd().nextBytes(key);
    for (String name : new String[]{"HmacSHA256", "HmacSHA3-256"}) {
      Mac jdk = Mac.getInstance(name, "SunJCE");
      jdk.init(new SecretKeySpec(key, name));
      Mac mac = crypto().newMac(name);
      mac.init(new SecretKeySpec(key, name));
      Assert.assertArrayEquals(name, jdk.doFinal(data), mac.doFinal(data));
    }

    // 32-bit key
    Mac mac = crypto().newMac("HmacSHA256");
    assertRejected("HMAC with a 32-bit key",
        () -> mac.init(new SecretKeySpec(new byte[4], "HmacSHA256")));
  }

  /** Passwords of at least 112 bits (14 characters). */
  @Override
  @Test
  public void testPbkdf2() throws Exception {
    char[] password = "passwordPASSWORDpassword".toCharArray();
    byte[] salt = new byte[16];
    rnd().nextBytes(salt);
    for (String hmac : new String[]{"HmacSHA1", "HmacSHA256", "HmacSHA512"}) {
      byte[] expected = SecretKeyFactory.getInstance("PBKDF2With" + hmac, "SunJCE")
          .generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();
      Assert.assertArrayEquals(hmac, expected, crypto().pbkdf2(hmac, password, salt, 1000, 32));
    }

    assertRejected("PBKDF2 with an 8-character password",
        () -> crypto().pbkdf2("HmacSHA256", "password".toCharArray(), salt, 1000, 32));
  }

  /** DESede: decryption only. */
  @Override
  @Test
  public void testDesedeCipher() throws Exception {
    SecretKey key = crypto().newKeyGenerator("DESede").generateKey();
    byte[] iv = new byte[8];
    rnd().nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    for (String name : new String[]{"DESede/CBC/PKCS5Padding", "DESede/CBC/NoPadding"}) {
      Cipher jdk = Cipher.getInstance(name, "SunJCE");
      jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getEncoded(), "DESede"), ivSpec);
      byte[] encrypted = jdk.doFinal(new byte[16]);

      Cipher cipher = crypto().newCipher(name);
      cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
      Assert.assertArrayEquals(name, new byte[16], cipher.doFinal(encrypted));
      assertRejected(name + " encryption",
          () -> cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec));
    }
  }

  /**
   * RSA: no signing with SHA-1 (verification only); encryption with OAEP in WRAP_MODE only, none
   * with PKCS#1 v1.5; decryption with both.
   */
  @Override
  @Test
  public void testRsa() throws Exception {
    KeyPairGenerator kpGen = crypto().newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();

    for (String name : new String[]{"SHA256WITHRSA", "SHA3-256WITHRSA", "SHA256WITHRSAANDMGF1",
        "SHA384WITHRSAANDMGF1", "SHA3-256WITHRSAANDMGF1"}) {
      assertSignVerify(name, kp);
    }
    assertKeyConversion(kp, "SHA256WITHRSA");

    // SHA-1: the JDK signs, BC-FIPS verifies; BC-FIPS does not sign
    byte[] data = "message".getBytes(StandardCharsets.US_ASCII);
    Signature jdk = Signature.getInstance("RSASSA-PSS", "SunRsaSign");
    jdk.setParameter(new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1));
    jdk.initSign(kp.getPrivate());
    jdk.update(data);
    byte[] sig = jdk.sign();
    Signature verifier = crypto().newSignature("SHA1WITHRSAANDMGF1");
    verifier.initVerify(kp.getPublic());
    verifier.update(data);
    Assert.assertTrue("SHA1WITHRSAANDMGF1 verification", verifier.verify(sig));
    Signature signer = crypto().newSignature("SHA1WITHRSAANDMGF1");
    assertRejected("SHA1WITHRSAANDMGF1 signing", () -> {
      signer.initSign(kp.getPrivate());
      signer.update(data);
      signer.sign();
    });

    // key transport. Encryption: OAEP in WRAP_MODE only, PKCS#1 v1.5 not at all. Decryption:
    // both, in DECRYPT_MODE and UNWRAP_MODE.
    KeyGenerator kg = KeyGenerator.getInstance("AES", "SunJCE");
    kg.init(128);
    SecretKey aesKey = kg.generateKey();
    for (String name : new String[]{"RSA/ECB/OAEPPadding", "RSA/NONE/OAEPPADDING",
        "RSA/ECB/PKCS1Padding"}) {
      boolean oaep = name.toUpperCase().contains("OAEP");
      Cipher cipher = crypto().newCipher(name);
      byte[] encrypted;
      if (oaep) {
        cipher.init(Cipher.WRAP_MODE, kp.getPublic());
        encrypted = cipher.wrap(aesKey);
      } else {
        assertRejected(name + " in WRAP_MODE", () -> {
          cipher.init(Cipher.WRAP_MODE, kp.getPublic());
          cipher.wrap(aesKey);
        });
        Cipher jdkCipher = Cipher.getInstance(name, "SunJCE");
        jdkCipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        encrypted = jdkCipher.doFinal(aesKey.getEncoded());
      }
      assertRejected(name + " in ENCRYPT_MODE",
          () -> cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic()));

      cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
      Assert.assertArrayEquals(name, aesKey.getEncoded(),
          cipher.unwrap(encrypted, "AES", Cipher.SECRET_KEY).getEncoded());
      cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
      Assert.assertArrayEquals(name, aesKey.getEncoded(), cipher.doFinal(encrypted));
    }

    // sign again after the unwrapping: one RSA key for both, as in SCEP (RFC 8894)
    assertSignVerify("SHA256WITHRSA", kp);
  }

  @Test
  public void testXdhNotApproved() throws Exception {
    for (String name : new String[]{"X25519", "X448"}) {
      Assert.assertThrows(name, NoSuchAlgorithmException.class,
          () -> crypto().newKeyAgreement(name));
    }
    Assert.assertThrows(UnsupportedOperationException.class,
        () -> crypto().generateX25519PrivateKey());
    Assert.assertThrows(UnsupportedOperationException.class,
        () -> crypto().calculateX448Agreement(new byte[56], new byte[56]));
  }

  @FunctionalInterface
  interface Op {
    void run() throws Exception;
  }

  /**
   * BC-FIPS rejects with exceptions or with FipsUnapprovedOperationError (an AssertionError).
   */
  static void assertRejected(String what, Op op) {
    boolean accepted;
    try {
      op.run();
      accepted = true;
    } catch (Exception | Error e) {
      accepted = false;
    }
    Assert.assertFalse(what + " is accepted in the approved-only mode", accepted);
  }

}
