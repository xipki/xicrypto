// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.jdk.CryptoJdk;
import org.xipki.crypto.openssl.OpenSsl;
import org.xipki.crypto.openssl.OpensslProvider;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * ML-DSA and ML-KEM of OpenSSL, against those of the JDK (public API only), without the JVM
 * option --add-exports.
 *
 * @author Lijun Liao (xipki)
 */
public class OpensslPqcTest {

  private static final byte[] MSG = "PQC test message".getBytes(StandardCharsets.UTF_8);

  private static final String[] DSA_NAMES = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

  private static CryptoApi openssl;

  private static final CryptoApi jdk = new CryptoJdk();

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    openssl = new OpensslTestBackend();
  }

  @Test
  public void testNoAddExports() {
    // the tests of this module run without --add-exports: nothing must depend on it
    Assert.assertFalse(Object.class.getModule().isExported("sun.security.provider",
        OpensslPqcTest.class.getModule()));
  }

  @Test
  public void testMldsaCrossSignVerify() throws Exception {
    MldsaVariant[] variants = MldsaVariant.values();
    for (int i = 0; i < variants.length; i++) {
      String name = DSA_NAMES[i];
      KeyPair kp = jdk.generateKeyPair(variants[i]);

      Signature sig = openssl.newSignature(name);
      Assert.assertEquals(OpensslProvider.NAME, sig.getProvider().getName());

      // OpenSSL signs, the JDK verifies, and vice versa
      byte[] sigValue = sign(openssl, name, kp.getPrivate(), null);
      Assert.assertTrue(name, verify(jdk, name, kp.getPublic(), sigValue, null));
      sigValue = sign(jdk, name, kp.getPrivate(), null);
      Assert.assertTrue(name, verify(openssl, name, kp.getPublic(), sigValue, null));
      // the generic name
      Assert.assertTrue(name, verify(openssl, "ML-DSA", kp.getPublic(), sigValue, null));
    }
  }

  @Test
  public void testMldsaContext() throws Exception {
    KeyPair kp = jdk.generateKeyPair(MldsaVariant.ml_dsa_44);
    byte[] ctx = "my context".getBytes(StandardCharsets.US_ASCII);
    byte[] sigValue = sign(openssl, "ML-DSA-44", kp.getPrivate(), ctx);
    Assert.assertTrue(verify(openssl, "ML-DSA-44", kp.getPublic(), sigValue, ctx));
    Assert.assertFalse(verify(openssl, "ML-DSA-44", kp.getPublic(), sigValue, null));
    Assert.assertFalse(verify(openssl, "ML-DSA-44", kp.getPublic(), sigValue, new byte[1]));
    // the JDK supports only the empty context in its public API
    Assert.assertFalse(verify(jdk, "ML-DSA-44", kp.getPublic(), sigValue, null));

    // the context is reset at initSign
    Signature s = openssl.newSignature("ML-DSA-44");
    s.initSign(kp.getPrivate());
    openssl.setContext(s, ctx);
    s.initSign(kp.getPrivate());
    s.update(MSG);
    Assert.assertTrue(verify(jdk, "ML-DSA-44", kp.getPublic(), s.sign(), null));

    // at most 255 bytes
    Assert.assertThrows(InvalidAlgorithmParameterException.class,
        () -> openssl.setContext(s, new byte[256]));
  }

  @Test
  public void testMldsaWrongKey() throws Exception {
    KeyPair kp = jdk.generateKeyPair(MldsaVariant.ml_dsa_65);
    Signature s = openssl.newSignature("ML-DSA-44");
    Assert.assertThrows(InvalidKeyException.class,
        () -> s.initSign(kp.getPrivate()));
  }

  @Test
  public void testExpandMldsaSeed() throws Exception {
    int[] sizes = {2560, 4032, 4896};
    MldsaVariant[] variants = MldsaVariant.values();
    for (int i = 0; i < variants.length; i++) {
      KeyPair kp = jdk.generateKeyPair(variants[i]);
      MldsaPrivateKey sk = MldsaPrivateKey.fromEncoded(
          PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()).privateKey());
      Assume.assumeNotNull(sk.seed());

      byte[] expanded = openssl.expandMldsaSeed(variants[i], sk.seed());
      Assert.assertEquals(DSA_NAMES[i], sizes[i], expanded.length);
      if (sk.expandedKey() != null) {
        Assert.assertArrayEquals(DSA_NAMES[i], sk.expandedKey(), expanded);
      }
    }

    Assert.assertThrows(IllegalArgumentException.class,
        () -> openssl.expandMldsaSeed(MldsaVariant.ml_dsa_44, new byte[31]));
  }

  @Test
  public void testMlkem() throws Exception {
    int[] dkSizes = {1632, 2400, 3168};
    MlkemVariant[] variants = MlkemVariant.values();
    for (int i = 0; i < variants.length; i++) {
      MlkemVariant variant = variants[i];
      KeyPair kp = jdk.generateKeyPair(variant);
      byte[] ek = SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded())
          .subjectPublicKey();
      MlkemPrivateKey sk = MlkemPrivateKey.fromEncoded(
          PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()).privateKey());
      Assume.assumeNotNull(sk.seed());

      byte[] dk = openssl.expandMlkemSeed(variant, sk.seed());
      Assert.assertEquals(variant.name(), dkSizes[i], dk.length);
      if (sk.expandedKey() != null) {
        Assert.assertArrayEquals(variant.name(), sk.expandedKey(), dk);
      }

      // the JDK encapsulates, OpenSSL decapsulates with the seed and with the expanded key
      SecretWithEncap se = jdk.encapsulateKey(variant, ek);
      Assert.assertArrayEquals(variant.name(), se.secret(),
          openssl.decapsulateKey(variant, sk.seed(), se.encap()));
      Assert.assertArrayEquals(variant.name(), se.secret(),
          openssl.decapsulateKey(variant, dk, se.encap()));

      // OpenSSL encapsulates
      se = openssl.encapsulateKey(variant, ek);
      Assert.assertEquals(32, se.secret().length);
      Assert.assertArrayEquals(variant.name(), se.secret(),
          openssl.decapsulateKey(variant, dk, se.encap()));
    }

    // invalid public key
    Assert.assertThrows(IllegalArgumentException.class,
        () -> openssl.encapsulateKey(MlkemVariant.ml_kem_768, new byte[10]));
  }

  private static byte[] sign(CryptoApi crypto, String alg, PrivateKey key, byte[] ctx)
      throws Exception {
    Signature s = crypto.newSignature(alg);
    s.initSign(key);
    crypto.setContext(s, ctx);
    s.update(MSG);
    return s.sign();
  }

  private static boolean verify(CryptoApi crypto, String alg, PublicKey key, byte[] sig,
                                byte[] ctx) throws Exception {
    Signature s = crypto.newSignature(alg);
    s.initVerify(key);
    crypto.setContext(s, ctx);
    s.update(MSG);
    return s.verify(sig);
  }

}
