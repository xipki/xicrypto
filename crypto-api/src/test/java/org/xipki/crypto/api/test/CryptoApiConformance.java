// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api.test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.X9ECParameters;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

/**
 * Conformance tests every {@link CryptoApi} backend must pass. A backend test extends this
 * class and implements {@link #crypto()}.
 * <p>
 * The algorithm names are those used by the XiPKI modules.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CryptoApiConformance {

  protected static final SecureRandom RND = new SecureRandom();

  private static final byte[] ABC = "abc".getBytes(StandardCharsets.US_ASCII);

  private static final byte[] DATA = "conformance test data".getBytes(StandardCharsets.US_ASCII);

  private static final Asn1Oid[] EC_CURVES = {
      CurveOIDs.secp256r1, CurveOIDs.secp384r1, CurveOIDs.secp521r1,
      CurveOIDs.brainpoolP256r1, CurveOIDs.brainpoolP384r1, CurveOIDs.brainpoolP512r1,
      CurveOIDs.sm2p256v1, CurveOIDs.frp256v1};

  protected abstract CryptoApi crypto();

  /**
   * Returns whether the backend supports the ML-DSA context string.
   */
  protected boolean supportsMldsaContext() {
    return true;
  }

  /**
   * Returns whether the backend supports ML-DSA (e.g. the JDK backend requires JDK 25+).
   */
  protected boolean supportsMldsa() {
    return true;
  }

  /**
   * Returns whether the backend supports ML-KEM (e.g. the JDK backend requires JDK 25+).
   */
  protected boolean supportsMlkem() {
    return true;
  }

  /**
   * Returns whether the backend supports Ed25519 and Ed448 (e.g. the JDK backend requires
   * JDK 15+).
   */
  protected boolean supportsEdDsa() {
    return true;
  }

  @Test
  public void testName() {
    Assert.assertNotNull(crypto().name());
    Assert.assertFalse(crypto().name().isEmpty());
  }

  @Test
  public void testMessageDigest() throws Exception {
    assertDigest("SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d");
    assertDigest("SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assertDigest("SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    assertDigest("SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    // by OID
    assertDigest(NistOIDs.id_sha256.getId(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // name by AlgorithmIdentifier
    Assert.assertEquals("SHA-256",
        crypto().getDigestName(AlgorithmIdentifier.ofNullParams(NistOIDs.id_sha256)));
    Assert.assertEquals("SHA-1",
        crypto().getDigestName(AlgorithmIdentifier.ofNullParams(OiwOIDs.idSHA1)));
  }

  private void assertDigest(String name, String expected) throws Exception {
    MessageDigest md = crypto().newMessageDigest(name);
    Assert.assertEquals(name, expected, Hex.encode(md.digest(ABC)));
  }

  @Test
  public void testMac() throws Exception {
    // RFC 4231, test case 2
    byte[] key = "Jefe".getBytes(StandardCharsets.US_ASCII);
    byte[] data = "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII);
    String expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    for (String name : new String[]{
        "HmacSHA256", "HMACSHA256", PkcsOIDs.id_hmacWithSHA256.getId()}) {
      Mac mac = crypto().newMac(name);
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      Assert.assertEquals(name, expected, Hex.encode(mac.doFinal(data)));
    }

    Mac mac = crypto().newMac("HMACSHA3-256");
    mac.init(new SecretKeySpec(key, "HmacSHA3-256"));
    Assert.assertEquals(32, mac.doFinal(data).length);
  }

  @Test
  public void testPbkdf2() throws Exception {
    char[] password = "password".toCharArray();
    byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);

    // RFC 6070
    Assert.assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6",
        Hex.encode(crypto().pbkdf2("HmacSHA1", password, salt, 1, 20)));
    Assert.assertEquals("4b007901b765489abead49d926f721d065a429c1",
        Hex.encode(crypto().pbkdf2((AlgorithmIdentifier) null, password, salt, 4096, 20)));

    String sha256 = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b";
    Assert.assertEquals(sha256, Hex.encode(crypto().pbkdf2("HmacSHA256", password, salt, 1, 32)));
    Assert.assertEquals(sha256, Hex.encode(crypto().pbkdf2(
        AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256), password, salt, 1, 32)));

    Assert.assertNotNull(crypto().newSecretKeyFactory("PBKDF2WithHmacSHA256"));
  }

  @Test
  public void testHkdf() {
    // RFC 5869, test case 1
    byte[] ikm = new byte[22];
    Arrays.fill(ikm, (byte) 0x0b);
    byte[] salt = Hex.decode("000102030405060708090a0b0c");
    byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
    Assert.assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            + "34007208d5b887185865",
        Hex.encode(crypto().hkdfSha256Derive(ikm, salt, info, 42)));

    ikm = new byte[32];
    Arrays.fill(ikm, (byte) 0x01);
    salt = new byte[16];
    Arrays.fill(salt, (byte) 0x03);
    info = new byte[30];
    Arrays.fill(info, (byte) 0x02);
    Assert.assertEquals("8bd704cf48e04322f34c8e0f43a17216d83f2294843a36eb3aad2d88530477a8",
        Hex.encode(crypto().hkdfSha256Derive(ikm, salt, info, 32)));

    // RFC 5869, test case 2: longer inputs and outputs (3 blocks)
    ikm = new byte[80];
    salt = new byte[80];
    info = new byte[80];
    for (int i = 0; i < 80; i++) {
      ikm[i] = (byte) i;
      salt[i] = (byte) (0x60 + i);
      info[i] = (byte) (0xb0 + i);
    }
    Assert.assertEquals("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            + "cc30c58179ec3e87c14c01d5c1f3434f1d87",
        Hex.encode(crypto().hkdfSha256Derive(ikm, salt, info, 82)));

    // RFC 5869, test case 3: zero-length salt and info
    ikm = new byte[22];
    Arrays.fill(ikm, (byte) 0x0b);
    Assert.assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            + "9d201395faa4b61a96c8",
        Hex.encode(crypto().hkdfSha256Derive(ikm, new byte[0], new byte[0], 42)));
  }

  @Test
  public void testXof() {
    byte[] data = new byte[32];
    Arrays.fill(data, (byte) 0x01);

    Assert.assertEquals("a82e325157ca8387d8903305043962f131785a241527e4f48bf276f61eb75de2ddf6",
        Hex.encode(crypto().xof("SHAKE128", data, 34)));
    Assert.assertEquals("dbf77c8d79c80ad6b0763d42a3fe53f0f1dc030220c2e3fedc2aa903abfcad08330d",
        Hex.encode(crypto().xof("SHAKE256", data, 34)));
  }

  @Test
  public void testAesCipher() throws Exception {
    byte[] key = new byte[32];
    RND.nextBytes(key);
    SecretKey aesKey = new SecretKeySpec(key, "AES");
    byte[] iv = new byte[16];
    RND.nextBytes(iv);

    // AES-CBC by name and by OID must use PKCS#5 padding
    for (String name : new String[]{"AES/CBC/PKCS5Padding", NistOIDs.id_aes256_CBC.getId()}) {
      Cipher cipher = crypto().newCipher(name);
      cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
      byte[] encrypted = cipher.doFinal(new byte[5]);
      Assert.assertEquals(name, 16, encrypted.length);
      cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
      Assert.assertArrayEquals(name, new byte[5], cipher.doFinal(encrypted));
    }

    // AES-GCM by name and by OID
    byte[] nonce = new byte[12];
    RND.nextBytes(nonce);
    for (String name : new String[]{"AES/GCM/NoPadding", NistOIDs.id_aes256_GCM.getId()}) {
      Cipher cipher = crypto().newCipher(name);
      cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
      byte[] encrypted = cipher.doFinal(DATA);
      Assert.assertEquals(name, DATA.length + 16, encrypted.length);
      cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, nonce));
      Assert.assertArrayEquals(name, DATA, cipher.doFinal(encrypted));
    }

    // AES-CBC without padding (used by the RFC 3211 key wrap)
    Cipher cipher = crypto().newCipher("AES/CBC/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
    Assert.assertEquals(32, cipher.doFinal(new byte[32]).length);

    javax.crypto.KeyGenerator kg = crypto().newKeyGenerator("AES");
    kg.init(128, RND);
    Assert.assertEquals(16, kg.generateKey().getEncoded().length);
  }

  @Test
  public void testAesKeyWrap() throws Exception {
    // RFC 3394, section 4.1
    SecretKey kek = new SecretKeySpec(Hex.decode("000102030405060708090a0b0c0d0e0f"), "AES");
    SecretKey key = new SecretKeySpec(Hex.decode("00112233445566778899aabbccddeeff"), "AES");
    String expected = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";

    Cipher cipher = crypto().newCipher(NistOIDs.id_aes128_wrap.getId());
    cipher.init(Cipher.WRAP_MODE, kek);
    byte[] wrapped = cipher.wrap(key);
    Assert.assertEquals(expected, Hex.encode(wrapped));

    cipher.init(Cipher.UNWRAP_MODE, kek);
    Assert.assertArrayEquals(key.getEncoded(),
        cipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
  }

  @Test
  public void testDesedeCipher() throws Exception {
    SecretKey key = crypto().newKeyGenerator("DESede").generateKey();
    byte[] iv = new byte[8];
    RND.nextBytes(iv);
    for (String name : new String[]{"DESede/CBC/PKCS5Padding", "DESede/CBC/NoPadding"}) {
      Cipher cipher = crypto().newCipher(name);
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] encrypted = cipher.doFinal(new byte[16]);
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      Assert.assertArrayEquals(name, new byte[16], cipher.doFinal(encrypted));
    }
  }

  @Test
  public void testRsa() throws Exception {
    KeyPairGenerator kpGen = crypto().newKeyPairGenerator("RSA");
    kpGen.initialize(2048);
    KeyPair kp = kpGen.generateKeyPair();

    for (String name : new String[]{"SHA256WITHRSA", "SHA3-256WITHRSA",
        "SHA256WITHRSAANDMGF1", "SHA384WITHRSAANDMGF1", "SHA3-256WITHRSAANDMGF1",
        PkcsOIDs.sha256WithRSAEncryption.getId()}) {
      assertSignVerify(name, kp);
    }

    assertKeyConversion(kp, "SHA256WITHRSA");

    // PKCS#1 v1.5 and OAEP encryption, with the signing key: SCEP (RFC 8894) uses one RSA key
    // for both decryption and signing.
    for (String name : new String[]{"RSA/ECB/PKCS1Padding", "RSA/NONE/PKCS1PADDING",
        "RSA/NONE/OAEPPADDING"}) {
      Cipher cipher = crypto().newCipher(name);
      cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
      byte[] encrypted = cipher.doFinal(DATA);
      cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
      Assert.assertArrayEquals(name, DATA, cipher.doFinal(encrypted));
    }

    OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1",
        new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
    Cipher cipher = crypto().newCipher("RSA/ECB/OAEPPadding");
    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic(), oaep);
    byte[] encrypted = cipher.doFinal(DATA);
    cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate(), oaep);
    Assert.assertArrayEquals(DATA, cipher.doFinal(encrypted));

    // sign again after the decryption
    assertSignVerify("SHA256WITHRSA", kp);

    // raw RSA
    cipher = crypto().newCipher("RSA/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
    Assert.assertEquals(256, cipher.doFinal(new byte[]{1, 2, 3}).length);

    Assert.assertNotNull(crypto().newKeyFactory("RSA"));
  }

  @Test
  public void testEc() throws Exception {
    for (String curve : new String[]{"1.2.840.10045.3.1.7", "secp256r1", "1.3.132.0.34"}) {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec(curve));
      KeyPair kp = kpGen.generateKeyPair();

      for (String name : new String[]{"SHA256WITHECDSA", "SHA384WITHECDSA", "SHA3-256WITHECDSA"}) {
        assertSignVerify(name, kp);
      }
      assertKeyConversion(kp, "SHA256WITHECDSA");

      // ECDH
      KeyPair kp2 = kpGen.generateKeyPair();
      KeyAgreement ka = crypto().newKeyAgreement("ECDH");
      ka.init(kp.getPrivate());
      ka.doPhase(kp2.getPublic(), true);
      byte[] z1 = ka.generateSecret();
      ka.init(kp2.getPrivate());
      ka.doPhase(kp.getPublic(), true);
      Assert.assertArrayEquals(z1, ka.generateSecret());
    }
  }

  /**
   * All backends must provide the arithmetic of the Weierstrass curves of xipki.
   */
  @Test
  public void testEcCurveParameters() {
    X9ECParameters params = crypto().getByOID(CurveOIDs.secp256r1);
    Assert.assertNotNull("secp256r1", params);
    Assert.assertEquals("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        params.getG().normalize().getXCoordBigInt().toString(16));

    for (Asn1Oid oid : EC_CURVES) {
      params = crypto().getByOID(oid);
      Assert.assertNotNull(oid.getId(), params);

      ECPoint p = params.getG().multiply(BigInteger.valueOf(2)).normalize();
      ECPoint q = params.getG().add(params.getG()).normalize();
      Assert.assertArrayEquals(oid.getId(), p.getEncoded(false), q.getEncoded(false));
      Assert.assertArrayEquals(oid.getId(), p.getEncoded(false),
          params.getCurve().decodePoint(p.getEncoded(true)).normalize().getEncoded(false));

      // u1·G + u2·Q
      BigInteger n = params.getCurve().getOrder();
      BigInteger u1 = new BigInteger(n.bitLength() - 1, RND);
      BigInteger u2 = new BigInteger(n.bitLength() - 1, RND);
      ECPoint expected = params.getG().multiply(u1).add(p.multiply(u2)).normalize();
      Assert.assertArrayEquals(oid.getId(), expected.getEncoded(false),
          params.sumOfTwoMultiplies(u1, u2, p).normalize().getEncoded(false));
    }
  }

  @Test
  public void testSm3() throws Exception {
    // GB/T 32905-2016, example 1
    assertDigest("SM3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
  }

  /**
   * EC keys and signatures on the curves brainpool, SM2 and FRP256v1.
   */
  @Test
  public void testEcCurves() throws Exception {
    for (Asn1Oid oid : new Asn1Oid[]{CurveOIDs.brainpoolP256r1, CurveOIDs.brainpoolP384r1,
        CurveOIDs.brainpoolP512r1, CurveOIDs.frp256v1, CurveOIDs.sm2p256v1}) {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec(oid.getId()), RND);
      KeyPair kp = kpGen.generateKeyPair();

      String sigAlg = CurveOIDs.sm2p256v1.equals(oid) ? "SM3WITHSM2" : "SHA256WITHECDSA";
      assertKeyConversion(kp, sigAlg);
      assertSignVerify(sigAlg, kp);
      if (!CurveOIDs.sm2p256v1.equals(oid)) {
        assertSignVerify("SHA3-256WITHECDSA", kp);
      }
    }
  }

  @Test
  public void testEcdsaWithShake() throws Exception {
    for (Asn1Oid oid : new Asn1Oid[]{CurveOIDs.secp256r1, CurveOIDs.brainpoolP256r1}) {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec(oid.getId()), RND);
      KeyPair kp = kpGen.generateKeyPair();
      assertSignVerify("SHAKE128WITHECDSA", kp);
      assertSignVerify("SHAKE256WITHECDSA", kp);
    }
  }

  @Test
  public void testRsaPssWithShake() throws Exception {
    KeyPairGenerator kpGen = crypto().newKeyPairGenerator("RSA");
    kpGen.initialize(2048, RND);
    KeyPair kp = kpGen.generateKeyPair();
    assertSignVerify("SHAKE128WITHRSAPSS", kp);
    assertSignVerify("SHAKE256WITHRSAPSS", kp);
  }

  @Test
  public void testAesGmac() throws Exception {
    // GCM test case 1 (McGrew, Viega): K = 0^128, IV = 0^96, no data
    Mac mac = crypto().newMac("AES-GMAC");
    mac.init(new SecretKeySpec(new byte[16], "AES"), new GCMParameterSpec(128, new byte[12]));
    Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", Hex.encode(mac.doFinal()));

    // with data: equals the GCM tag over the data as AAD
    byte[] key = new byte[32];
    byte[] nonce = new byte[12];
    RND.nextBytes(key);
    RND.nextBytes(nonce);
    mac.init(new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    mac.update(DATA);
    byte[] tag = mac.doFinal();

    Cipher cipher = crypto().newCipher("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
        new GCMParameterSpec(128, nonce));
    cipher.updateAAD(DATA);
    Assert.assertArrayEquals(cipher.doFinal(), tag);
  }

  @Test
  public void testEdDsa() throws Exception {
    Assume.assumeTrue("EdDSA not supported", supportsEdDsa());
    for (String[] alg : new String[][]{{"ED25519", "1.3.101.112"}, {"ED448", "1.3.101.113"}}) {
      for (String name : alg) {
        KeyPairGenerator kpGen = crypto().newKeyPairGenerator(name);
        // as in xihsm: the generator obtained by OID is initialized with the key size
        kpGen.initialize(alg[0].equals("ED25519") ? 255 : 448, RND);
        KeyPair kp = kpGen.generateKeyPair();
        assertSignVerify(alg[0], kp);
        assertKeyConversion(kp, alg[0]);
      }
    }
  }

  @Test
  public void testX25519() {
    // RFC 7748, section 6.1
    byte[] skA = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    byte[] pkB = Hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    Assert.assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        Hex.encode(crypto().generateX25519PublicKey(skA)));
    Assert.assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        Hex.encode(crypto().calculateX25519Agreement(skA, pkB)));

    byte[] sk1 = crypto().generateX25519PrivateKey(RND);
    byte[] sk2 = crypto().generateX25519PrivateKey(RND);
    Assert.assertEquals(32, sk1.length);
    Assert.assertArrayEquals(
        crypto().calculateX25519Agreement(sk1, crypto().generateX25519PublicKey(sk2)),
        crypto().calculateX25519Agreement(sk2, crypto().generateX25519PublicKey(sk1)));
  }

  @Test
  public void testX448() {
    // RFC 7748, section 6.2
    byte[] skA = Hex.decode("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
        + "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    byte[] pkB = Hex.decode("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
        + "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    Assert.assertEquals("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
            + "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        Hex.encode(crypto().generateX448PublicKey(skA)));
    Assert.assertEquals("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
            + "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        Hex.encode(crypto().calculateX448Agreement(skA, pkB)));

    byte[] sk1 = crypto().generateX448PrivateKey(RND);
    byte[] sk2 = crypto().generateX448PrivateKey(RND);
    Assert.assertEquals(56, sk1.length);
    Assert.assertArrayEquals(
        crypto().calculateX448Agreement(sk1, crypto().generateX448PublicKey(sk2)),
        crypto().calculateX448Agreement(sk2, crypto().generateX448PublicKey(sk1)));
  }

  @Test
  public void testXdhKeyAgreement() throws Exception {
    for (String name : new String[]{"X25519", "X448"}) {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator(name);
      KeyPair kp1 = kpGen.generateKeyPair();
      KeyPair kp2 = kpGen.generateKeyPair();

      KeyAgreement ka = crypto().newKeyAgreement(name);
      ka.init(kp1.getPrivate());
      ka.doPhase(kp2.getPublic(), true);
      byte[] z1 = ka.generateSecret();
      ka.init(kp2.getPrivate());
      ka.doPhase(kp1.getPublic(), true);
      Assert.assertArrayEquals(name, z1, ka.generateSecret());

      PublicKey pk = crypto().getPublicKey(SubjectPublicKeyInfo.fromEncoded(
          kp1.getPublic().getEncoded()));
      Assert.assertArrayEquals(name, kp1.getPublic().getEncoded(), pk.getEncoded());
    }
  }

  @Test
  public void testMldsa() throws Exception {
    Assume.assumeTrue("ML-DSA not supported", supportsMldsa());
    String[] names = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    MldsaVariant[] variants = MldsaVariant.values();
    for (int i = 0; i < variants.length; i++) {
      KeyPair kp = crypto().generateKeyPair(variants[i], i == 0 ? null : RND);
      assertSignVerify(names[i], kp);
      assertKeyConversion(kp, names[i]);

      PrivateKeyInfo skInfo = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());
      MldsaPrivateKey sk = MldsaPrivateKey.fromEncoded(skInfo.privateKey());
      Assert.assertTrue(sk.seed() != null || sk.expandedKey() != null);
    }

    // context
    KeyPair kp = crypto().generateKeyPair(MldsaVariant.ml_dsa_65, RND);
    Signature sig = crypto().newSignature("ML-DSA-65");
    sig.initSign(kp.getPrivate());
    crypto().setContext(sig, null);
    crypto().setContext(sig, new byte[0]);

    byte[] context = "ctx".getBytes(StandardCharsets.US_ASCII);
    try {
      crypto().setContext(sig, context);
    } catch (InvalidAlgorithmParameterException e) {
      Assert.assertFalse("context must be supported", supportsMldsaContext());
      return;
    }

    Assert.assertTrue("context must not be supported", supportsMldsaContext());
    sig.update(DATA);
    byte[] sigValue = sig.sign();

    sig.initVerify(kp.getPublic());
    crypto().setContext(sig, context);
    sig.update(DATA);
    Assert.assertTrue(sig.verify(sigValue));

    sig.initVerify(kp.getPublic());
    crypto().setContext(sig, "other".getBytes(StandardCharsets.US_ASCII));
    sig.update(DATA);
    Assert.assertFalse(sig.verify(sigValue));
  }

  /**
   * expandMldsaSeed / expandMlkemSeed: the raw private keys of FIPS 204 / 203 from the seed.
   */
  @Test
  public void testExpandPqcSeed() throws Exception {
    Assume.assumeTrue("ML-DSA / ML-KEM not supported", supportsMldsa() && supportsMlkem());
    int[] skSizes = {2560, 4032, 4896};
    String[] names = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    MldsaVariant[] dsaVariants = MldsaVariant.values();
    for (int i = 0; i < dsaVariants.length; i++) {
      KeyPair kp = crypto().generateKeyPair(dsaVariants[i], RND);
      PrivateKeyInfo skInfo = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());
      MldsaPrivateKey sk = MldsaPrivateKey.fromEncoded(skInfo.privateKey());

      byte[] expanded;
      try {
        expanded = crypto().expandMldsaSeed(dsaVariants[i], sk.seed());
      } catch (UnsupportedOperationException e) {
        return;
      }

      Assert.assertEquals(names[i], skSizes[i], expanded.length);
      if (sk.expandedKey() != null) {
        Assert.assertArrayEquals(names[i], sk.expandedKey(), expanded);
      }

      // the key with expandedKey only signs, the public key verifies
      PrivateKey expandedSk = crypto().getPrivateKey(new PrivateKeyInfo(
          skInfo.getPrivateKeyAlgorithm(), new MldsaPrivateKey(null, expanded).getEncoded()));
      Signature sig = crypto().newSignature(names[i]);
      sig.initSign(expandedSk);
      sig.update(DATA);
      byte[] sigValue = sig.sign();
      sig.initVerify(kp.getPublic());
      sig.update(DATA);
      Assert.assertTrue(names[i], sig.verify(sigValue));
    }

    int[] dkSizes = {1632, 2400, 3168};
    MlkemVariant[] kemVariants = MlkemVariant.values();
    for (int i = 0; i < kemVariants.length; i++) {
      KeyPair kp = crypto().generateKeyPair(kemVariants[i], RND);
      MlkemPrivateKey sk = MlkemPrivateKey.fromEncoded(
          PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()).privateKey());

      byte[] dk;
      try {
        dk = crypto().expandMlkemSeed(kemVariants[i], sk.seed());
      } catch (UnsupportedOperationException e) {
        return;
      }

      Assert.assertEquals(kemVariants[i].name(), dkSizes[i], dk.length);
      if (sk.expandedKey() != null) {
        Assert.assertArrayEquals(kemVariants[i].name(), sk.expandedKey(), dk);
      }

      byte[] ek = SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded()).subjectPublicKey();
      SecretWithEncap se = crypto().encapsulateKey(kemVariants[i], ek, RND);
      Assert.assertArrayEquals(kemVariants[i].name(), se.secret(),
          crypto().decapsulateKey(kemVariants[i], dk, se.encap()));
    }
  }

  @Test
  public void testMlkem() throws Exception {
    Assume.assumeTrue("ML-KEM not supported", supportsMlkem());
    for (MlkemVariant variant : MlkemVariant.values()) {
      KeyPair kp = crypto().generateKeyPair(variant, RND);

      PublicKey pk = crypto().getPublicKey(
          SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded()));
      Assert.assertArrayEquals(variant.name(), kp.getPublic().getEncoded(), pk.getEncoded());
      Assert.assertNotNull(crypto().getPrivateKey(
          PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded())));

      byte[] rawPk = SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded())
          .subjectPublicKey();
      MlkemPrivateKey sk = MlkemPrivateKey.fromEncoded(
          PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()).privateKey());

      SecretWithEncap encap = crypto().encapsulateKey(variant, rawPk, RND);
      Assert.assertEquals(32, encap.secret().length);

      boolean tested = false;
      for (byte[] rawSk : new byte[][]{sk.seed(), sk.expandedKey()}) {
        if (rawSk != null) {
          Assert.assertArrayEquals(variant.name(), encap.secret(),
              crypto().decapsulateKey(variant, rawSk, encap.encap()));
          tested = true;
        }
      }
      Assert.assertTrue(tested);
    }
  }

  @Test
  public void testMisc() throws Exception {
    Assert.assertNotNull(crypto().getSecureRandom(null));
    SecureRandom rnd = new SecureRandom();
    Assert.assertNotNull(crypto().getSecureRandom(rnd));
    Assert.assertNotNull(crypto().newKeyStore("PKCS12"));
  }

  protected void assertSignVerify(String name, KeyPair kp) throws Exception {
    Signature sig = crypto().newSignature(name);
    sig.initSign(kp.getPrivate());
    sig.update(DATA);
    byte[] sigValue = sig.sign();

    sig = crypto().newSignature(name);
    sig.initVerify(kp.getPublic());
    sig.update(DATA);
    Assert.assertTrue(name, sig.verify(sigValue));

    sig.initVerify(kp.getPublic());
    sig.update(ABC);
    Assert.assertFalse(name, sig.verify(sigValue));
  }

  /**
   * Converts the keys with {@link CryptoApi#getPublicKey} and {@link CryptoApi#getPrivateKey}
   * and checks that they work together with the original keys.
   */
  protected void assertKeyConversion(KeyPair kp, String sigAlg) throws Exception {
    PublicKey pk = crypto().getPublicKey(
        SubjectPublicKeyInfo.fromEncoded(kp.getPublic().getEncoded()));
    PrivateKey sk = crypto().getPrivateKey(
        PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded()));

    Assert.assertArrayEquals(sigAlg, kp.getPublic().getEncoded(), pk.getEncoded());

    Signature sig = crypto().newSignature(sigAlg);
    sig.initSign(sk);
    sig.update(DATA);
    byte[] sigValue = sig.sign();

    sig.initVerify(kp.getPublic());
    sig.update(DATA);
    Assert.assertTrue(sigAlg, sig.verify(sigValue));
  }

}
