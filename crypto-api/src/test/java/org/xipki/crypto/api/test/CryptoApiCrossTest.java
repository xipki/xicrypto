// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api.test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Set;

/**
 * Cross tests of two CryptoApi backends: the results, keys and signatures of the backend under
 * test are accepted by the reference backend, and vice versa.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CryptoApiCrossTest {

  protected static final SecureRandom RND = new SecureRandom();

  private static final byte[] DATA = "cross test data".getBytes(StandardCharsets.US_ASCII);

  private static final byte[] CTX = "COMPSIG-MLDSA44-Ed25519-SHA512".getBytes(
      StandardCharsets.US_ASCII);

  private static final byte[] OTHER_CTX = "other".getBytes(StandardCharsets.US_ASCII);

  /**
   * Returns the backend under test.
   * @return the backend under test.
   */
  protected abstract CryptoApi backend();

  /**
   * Returns the reference backend.
   * @return the reference backend.
   */
  protected abstract CryptoApi reference();

  /**
   * Returns the names of the JCA providers registered by the backend under test. The reference
   * backend must not use them.
   * @return the names of the providers.
   */
  protected Set<String> backendProviders() {
    return Collections.emptySet();
  }

  /**
   * Returns whether both backends support ML-DSA (e.g. the JDK backend requires JDK 25+).
   */
  protected boolean supportsMldsa() {
    return true;
  }

  /**
   * Returns whether both backends support the ML-DSA context string.
   */
  protected boolean supportsMldsaContext() {
    return true;
  }

  /**
   * Returns whether both backends support ML-KEM (e.g. the JDK backend requires JDK 25+).
   */
  protected boolean supportsMlkem() {
    return true;
  }

  /**
   * Returns whether both backends support Ed25519 and Ed448 (e.g. the JDK backend requires
   * JDK 15+).
   */
  protected boolean supportsEdDsa() {
    return true;
  }

  private CryptoApi[][] pairs() {
    return new CryptoApi[][]{{backend(), reference()}, {reference(), backend()}};
  }

  @Test
  public void testReferenceIsolation() throws Exception {
    Set<String> providers = backendProviders();
    Assume.assumeFalse("no providers registered by the backend", providers.isEmpty());

    CryptoApi ref = reference();
    KeyPairGenerator rsaGen = ref.newKeyPairGenerator("RSA");
    rsaGen.initialize(2048, RND);
    KeyPair rsa = rsaGen.generateKeyPair();

    KeyPairGenerator ecGen = ref.newKeyPairGenerator("EC");
    ecGen.initialize(new ECGenParameterSpec(CurveOIDs.secp256r1.getId()), RND);
    KeyPair ec = ecGen.generateKeyPair();

    String[] names = {
        name(ref.newMessageDigest("SHA-256").getProvider()),
        name(ref.newMessageDigest("SM3").getProvider()),
        name(ref.newMac("HmacSHA256").getProvider()),
        signatureProvider(ref, "SHA256WITHRSA", rsa),
        signatureProvider(ref, "SHA256WITHRSAANDMGF1", rsa),
        signatureProvider(ref, "SHA256WITHECDSA", ec),
        signatureProvider(ref, "SHAKE128WITHECDSA", ec),
        name(ref.newCipher("AES/GCM/NoPadding").getProvider()),
        name(rsaGen.getProvider()),
        name(ecGen.getProvider())};
    for (String name : names) {
      Assert.assertFalse(ref.name() + " uses the provider " + name + " of " + backend().name(),
          name != null && providers.contains(name));
    }

    // the keys of the routing implementations (without provider)
    for (KeyPair kp : new KeyPair[]{rsa, ec}) {
      for (java.security.Key key : new java.security.Key[]{kp.getPublic(), kp.getPrivate()}) {
        Assert.assertFalse(ref.name() + " generates the key " + key.getClass().getName(),
            key.getClass().getName().startsWith(backend().getClass().getPackage().getName())
            || key.getClass().getName().startsWith("org.bouncycastle."));
      }
    }
  }

  /**
   * Returns the name of the provider, or null if the object is implemented by the backend
   * itself (e.g. one that routes to different providers) and has no provider.
   */
  private static String name(java.security.Provider provider) {
    return provider == null ? null : provider.getName();
  }

  /**
   * Returns the provider of the signature. A JCA Signature may select its provider only when
   * it is initialized with a key. A Signature implemented by the backend itself (e.g. one that
   * routes to different providers) has no provider: then null is returned.
   */
  private static String signatureProvider(CryptoApi api, String alg, KeyPair kp)
      throws Exception {
    Signature sig = api.newSignature(alg);
    sig.initVerify(kp.getPublic());
    return name(sig.getProvider());
  }

  @Test
  public void testDigests() throws Exception {
    for (String alg : new String[]{"SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-512", "SM3"}) {
      Assert.assertArrayEquals(alg, backend().newMessageDigest(alg).digest(DATA),
          reference().newMessageDigest(alg).digest(DATA));
    }

    for (String alg : new String[]{"SHAKE128", "SHAKE256"}) {
      Assert.assertArrayEquals(alg, backend().xof(alg, DATA, 100),
          reference().xof(alg, DATA, 100));
    }
  }

  @Test
  public void testMacs() throws Exception {
    byte[] key = new byte[32];
    RND.nextBytes(key);
    for (String alg : new String[]{"HmacSHA1", "HmacSHA256", "HmacSHA512", "HmacSHA3-256"}) {
      Assert.assertArrayEquals(alg, mac(backend(), alg, key, null),
          mac(reference(), alg, key, null));
    }

    byte[] nonce = new byte[12];
    RND.nextBytes(nonce);
    Assert.assertArrayEquals("AES-GMAC", mac(backend(), "AES-GMAC", key, nonce),
        mac(reference(), "AES-GMAC", key, nonce));
  }

  private static byte[] mac(CryptoApi api, String alg, byte[] key, byte[] gmacNonce)
      throws Exception {
    Mac mac = api.newMac(alg);
    if (gmacNonce == null) {
      mac.init(new SecretKeySpec(key, alg));
    } else {
      mac.init(new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, gmacNonce));
    }
    mac.update(DATA);
    return mac.doFinal();
  }

  @Test
  public void testKdfs() throws Exception {
    byte[] ikm = new byte[32];
    byte[] salt = new byte[16];
    RND.nextBytes(ikm);
    RND.nextBytes(salt);
    byte[] info = "info".getBytes(StandardCharsets.US_ASCII);

    for (int len : new int[]{16, 32, 100}) {
      Assert.assertArrayEquals("HKDF " + len, backend().hkdfSha256Derive(ikm, salt, info, len),
          reference().hkdfSha256Derive(ikm, salt, info, len));
    }

    char[] password = "password".toCharArray();
    for (String hmac : new String[]{"HmacSHA1", "HmacSHA256", "HmacSHA512"}) {
      Assert.assertArrayEquals("PBKDF2 " + hmac,
          backend().pbkdf2(hmac, password, salt, 1000, 32),
          reference().pbkdf2(hmac, password, salt, 1000, 32));
    }
  }

  @Test
  public void testCiphers() throws Exception {
    byte[] keyValue = new byte[32];
    RND.nextBytes(keyValue);
    SecretKey key = new SecretKeySpec(keyValue, "AES");
    byte[] iv = new byte[16];
    byte[] nonce = new byte[12];
    RND.nextBytes(iv);
    RND.nextBytes(nonce);

    for (CryptoApi[] pair : pairs()) {
      String desc = pair[0].name() + " -> " + pair[1].name();

      Cipher enc = pair[0].newCipher("AES/GCM/NoPadding");
      enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
      enc.updateAAD(CTX);
      byte[] encrypted = enc.doFinal(DATA);

      Cipher dec = pair[1].newCipher("AES/GCM/NoPadding");
      dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
      dec.updateAAD(CTX);
      Assert.assertArrayEquals("AES-GCM " + desc, DATA, dec.doFinal(encrypted));

      enc = pair[0].newCipher("AES/CBC/PKCS5Padding");
      enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      encrypted = enc.doFinal(DATA);

      dec = pair[1].newCipher("AES/CBC/PKCS5Padding");
      dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      Assert.assertArrayEquals("AES-CBC " + desc, DATA, dec.doFinal(encrypted));

      // AES key wrap (RFC 3394)
      SecretKey cek = new SecretKeySpec(keyValue, 0, 16, "AES");
      Cipher wrap = pair[0].newCipher(NistOIDs.id_aes256_wrap.getId());
      wrap.init(Cipher.WRAP_MODE, key);
      byte[] wrapped = wrap.wrap(cek);

      Cipher unwrap = pair[1].newCipher(NistOIDs.id_aes256_wrap.getId());
      unwrap.init(Cipher.UNWRAP_MODE, key);
      Assert.assertArrayEquals("AES key wrap " + desc, cek.getEncoded(),
          unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
    }
  }

  @Test
  public void testRsaSignatures() throws Exception {
    for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
      KeyPairGenerator kpGen = keyGen.newKeyPairGenerator("RSA");
      kpGen.initialize(2048, RND);
      KeyPair kp = kpGen.generateKeyPair();
      for (String alg : new String[]{"SHA256WITHRSA", "SHA512WITHRSA", "SHA3-256WITHRSA",
          "SHA256WITHRSAANDMGF1", "SHA512WITHRSAANDMGF1", "SHA3-256WITHRSAANDMGF1",
          "SHAKE128WITHRSAPSS", "SHAKE256WITHRSAPSS"}) {
        assertCrossSignVerify(alg, kp, keyGen);
      }
    }
  }

  @Test
  public void testEcSignatures() throws Exception {
    Object[][] cases = {
        {CurveOIDs.secp256r1, new String[]{"SHA256WITHECDSA", "SHA3-384WITHECDSA",
            "SHAKE128WITHECDSA", "SHAKE256WITHECDSA"}},
        {CurveOIDs.secp384r1, new String[]{"SHA384WITHECDSA"}},
        {CurveOIDs.secp521r1, new String[]{"SHA512WITHECDSA"}},
        {CurveOIDs.brainpoolP256r1, new String[]{"SHA256WITHECDSA", "SHAKE128WITHECDSA"}},
        {CurveOIDs.sm2p256v1, new String[]{"SM3WITHSM2"}}};

    for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
      for (Object[] c : cases) {
        KeyPairGenerator kpGen = keyGen.newKeyPairGenerator("EC");
        kpGen.initialize(new ECGenParameterSpec(((Asn1Oid) c[0]).getId()), RND);
        KeyPair kp = kpGen.generateKeyPair();
        for (String alg : (String[]) c[1]) {
          assertCrossSignVerify(alg, kp, keyGen);
        }
      }
    }
  }

  @Test
  public void testEdDsaSignatures() throws Exception {
    Assume.assumeTrue("EdDSA not supported", supportsEdDsa());
    for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
      for (String alg : new String[]{"ED25519", "ED448"}) {
        assertCrossSignVerify(alg, keyGen.newKeyPairGenerator(alg).generateKeyPair(), keyGen);
      }
    }
  }

  @Test
  public void testMldsaSignatures() throws Exception {
    Assume.assumeTrue("ML-DSA not supported", supportsMldsa());
    for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
      for (MldsaVariant variant : MldsaVariant.values()) {
        String alg = "ML-DSA-" + variant.name().substring("ml_dsa_".length());
        KeyPair kp = keyGen.generateKeyPair(variant, RND);
        assertCrossSignVerify(alg, kp, keyGen);
        assertCrossSignVerify("ML-DSA", kp, keyGen);
      }
    }
  }

  @Test
  public void testMldsaContext() throws Exception {
    Assume.assumeTrue("ML-DSA with context not supported",
        supportsMldsa() && supportsMldsaContext());
    for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
      for (MldsaVariant variant : MldsaVariant.values()) {
        String alg = "ML-DSA-" + variant.name().substring("ml_dsa_".length());
        KeyPair kp = keyGen.generateKeyPair(variant, RND);
        PrivateKeyInfo skInfo = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());

        for (CryptoApi[] pair : pairs()) {
          String desc = alg + ", " + keyGen.name() + " key, " + pair[0].name() + " -> "
              + pair[1].name();
          PrivateKey sk = pair[0].getPrivateKey(skInfo);
          PublicKey pk = pair[1].getPublicKey(
              SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded()));

          byte[] seed = MldsaPrivateKey.fromEncoded(skInfo.privateKey()).seed();
          PrivateKey seedSk = seed == null ? null : pair[0].getPrivateKey(new PrivateKeyInfo(
              skInfo.getPrivateKeyAlgorithm(), new MldsaPrivateKey(seed, null).getEncoded()));

          for (PrivateKey signKey : new PrivateKey[]{sk, seedSk}) {
            if (signKey == null) {
              continue;
            }

            byte[] sig = sign(pair[0], alg, signKey, CTX);
            Assert.assertTrue(desc + ": context", verify(pair[1], alg, pk, CTX, sig));
            Assert.assertFalse(desc + ": other context",
                verify(pair[1], alg, pk, OTHER_CTX, sig));
            Assert.assertFalse(desc + ": no context", verify(pair[1], alg, pk, null, sig));

            sig = sign(pair[0], alg, signKey, null);
            Assert.assertTrue(desc + ": without context", verify(pair[1], alg, pk, null, sig));
          }
        }
      }
    }
  }

  @Test
  public void testPqcSeedExpansion() {
    Assume.assumeTrue("ML-DSA / ML-KEM not supported", supportsMldsa() && supportsMlkem());
    byte[] seed = new byte[32];
    RND.nextBytes(seed);
    for (MldsaVariant variant : MldsaVariant.values()) {
      Assert.assertArrayEquals(variant.name(), backend().expandMldsaSeed(variant, seed),
          reference().expandMldsaSeed(variant, seed));
    }

    seed = new byte[64];
    RND.nextBytes(seed);
    for (MlkemVariant variant : MlkemVariant.values()) {
      Assert.assertArrayEquals(variant.name(), backend().expandMlkemSeed(variant, seed),
          reference().expandMlkemSeed(variant, seed));
    }
  }

  @Test
  public void testMlkem() throws Exception {
    Assume.assumeTrue("ML-KEM not supported", supportsMlkem());
    for (MlkemVariant variant : MlkemVariant.values()) {
      for (CryptoApi keyGen : new CryptoApi[]{backend(), reference()}) {
        KeyPair kp = keyGen.generateKeyPair(variant, RND);
        byte[] rawPk = SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded())
            .subjectPublicKey();
        MlkemPrivateKey sk = MlkemPrivateKey.fromEncoded(
            PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()).privateKey());

        byte[] seed = sk.seed();
        byte[] expanded = sk.expandedKey();
        if (expanded == null) {
          expanded = keyGen.expandMlkemSeed(variant, seed);
        }

        for (CryptoApi[] pair : pairs()) {
          SecretWithEncap encap = pair[0].encapsulateKey(variant, rawPk, RND);
          String desc = variant + ", " + keyGen.name() + " key, " + pair[0].name() + " -> "
              + pair[1].name();
          if (seed != null) {
            Assert.assertArrayEquals(desc + " (seed)", encap.secret(),
                pair[1].decapsulateKey(variant, seed, encap.encap()));
          }
          Assert.assertArrayEquals(desc + " (expanded)", encap.secret(),
              pair[1].decapsulateKey(variant, expanded, encap.encap()));
        }
      }
    }
  }

  @Test
  public void testXdh() {
    CryptoApi a = backend();
    CryptoApi b = reference();
    for (int i = 0; i < 5; i++) {
      byte[] sk1 = b.generateX25519PrivateKey(RND);
      byte[] sk2 = a.generateX25519PrivateKey(RND);
      Assert.assertArrayEquals(a.generateX25519PublicKey(sk1), b.generateX25519PublicKey(sk1));
      Assert.assertArrayEquals(
          a.calculateX25519Agreement(sk2, b.generateX25519PublicKey(sk1)),
          b.calculateX25519Agreement(sk1, a.generateX25519PublicKey(sk2)));

      sk1 = b.generateX448PrivateKey(RND);
      sk2 = a.generateX448PrivateKey(RND);
      Assert.assertArrayEquals(a.generateX448PublicKey(sk1), b.generateX448PublicKey(sk1));
      Assert.assertArrayEquals(
          a.calculateX448Agreement(sk2, b.generateX448PublicKey(sk1)),
          b.calculateX448Agreement(sk1, a.generateX448PublicKey(sk2)));
    }
  }

  @Test
  public void testXdhKeys() throws Exception {
    Assume.assumeTrue("XDH keys not supported", supportsEdDsa());
    for (CryptoApi[] pair : pairs()) {
      for (String alg : new String[]{"X25519", "X448"}) {
        KeyPair kp = pair[0].newKeyPairGenerator(alg).generateKeyPair();
        PrivateKey sk = pair[1].getPrivateKey(PrivateKeyInfo.fromEncoded(
            kp.getPrivate().getEncoded()));
        PublicKey pk = pair[1].getPublicKey(SubjectPublicKeyInfo.fromEncoded(
            kp.getPublic().getEncoded()));
        Assert.assertNotNull(sk);
        Assert.assertArrayEquals(alg + " " + pair[0].name() + " -> " + pair[1].name(),
            kp.getPublic().getEncoded(), pk.getEncoded());
      }
    }
  }

  /**
   * Converts the key pair to the keys of both backends, signs with each backend and verifies
   * with the other one.
   */
  private void assertCrossSignVerify(String alg, KeyPair kp, CryptoApi keyGen) throws Exception {
    SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded());
    PrivateKeyInfo skInfo = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());

    for (CryptoApi[] pair : pairs()) {
      String desc = alg + ", " + keyGen.name() + " key, " + pair[0].name() + " signs, "
          + pair[1].name() + " verifies";
      byte[] sig = sign(pair[0], alg, pair[0].getPrivateKey(skInfo), null);
      Assert.assertTrue(desc, verify(pair[1], alg, pair[1].getPublicKey(pkInfo), null, sig));
    }
  }

  /**
   * Signs the data. The context is set after initSign, as required by
   * {@link CryptoApi#setContext}.
   */
  private static byte[] sign(CryptoApi api, String alg, PrivateKey key, byte[] ctx)
      throws Exception {
    Signature sig = api.newSignature(alg);
    sig.initSign(key, RND);
    if (ctx != null) {
      api.setContext(sig, ctx);
    }
    sig.update(DATA);
    return sig.sign();
  }

  private static boolean verify(CryptoApi api, String alg, PublicKey key, byte[] ctx,
                                byte[] signature) throws Exception {
    Signature sig = api.newSignature(alg);
    sig.initVerify(key);
    if (ctx != null) {
      api.setContext(sig, ctx);
    }
    sig.update(DATA);
    return sig.verify(signature);
  }

}
