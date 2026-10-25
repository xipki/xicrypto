// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.asn1.AbstractCollection;
import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1GeneralizedTime;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1UtcTime;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.crypto.DHParameter;
import org.xipki.codec.asn1.crypto.DSAParameter;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.asn1.crypto.ECParameters;
import org.xipki.codec.asn1.crypto.ECPrivateKey;
import org.xipki.codec.asn1.crypto.ElGamalParameter;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.PBEParameter;
import org.xipki.codec.asn1.crypto.PBES2Parameters;
import org.xipki.codec.asn1.crypto.PBKDF2Params;
import org.xipki.codec.asn1.crypto.PBMAC1Params;
import org.xipki.codec.asn1.crypto.PqcPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.crypto.RSAPrivateKey;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.RSASSAPSSParams;
import org.xipki.codec.asn1.crypto.ScryptParams;
import org.xipki.codec.asn1.Time;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Tests {@code toString(StringBuilder, int)} of the classes in {@code org.xipki.codec.asn1.crypto}:
 * the field names, the same text for built and decoded objects, and that the private key
 * material is not printed.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptToStringTest {

  private interface Parser {
    Asn1Encodable parse(byte[] encoded) throws CodecException;
  }

  private static final SecureRandom RND = new SecureRandom();

  private static final BigInteger P = new BigInteger(1, Hex.decode(
      "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
      + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"));

  private static final BigInteger Q = new BigInteger("1234567890123456789012345678901");

  @Test
  public void testAlgorithmParameters() throws Exception {
    BigInteger g = BigInteger.TWO;
    assertFields("DHParameter", new DHParameter(P, g, 160),
        e -> DHParameter.fromAsn1(Asn1Sequence.fromEncoded(e)), "p", "g", "l");
    assertFields("DSAParameter", new DSAParameter(P, Q, g),
        e -> DSAParameter.fromAsn1(Asn1Sequence.fromEncoded(e)), "p", "q", "g");
    assertFields("ElGamalParameter", new ElGamalParameter(P, g),
        e -> ElGamalParameter.fromAsn1(Asn1Sequence.fromEncoded(e)), "p", "g");
    assertFields("DssSigValue", new DssSigValue(P, Q),
        e -> DssSigValue.fromAsn1(Asn1Sequence.fromEncoded(e)), "r", "s");

    String text = assertFields("RSAPublicKey", new RSAPublicKey(P, BigInteger.valueOf(65537)),
        e -> RSAPublicKey.fromAsn1(Asn1Sequence.fromEncoded(e)), "modulus", "publicExponent");
    // big numbers in hex, small numbers in decimal
    Assert.assertTrue(text, text.contains("ff:ff:ff:ff:ff:ff:ff:ff:c9:0f:da:a2"));
    Assert.assertTrue(text, text.contains("publicExponent: 65537"));
  }

  @Test
  public void testPasswordBasedParameters() throws Exception {
    byte[] salt = new byte[16];
    AlgorithmIdentifier hmacSha256 = new AlgorithmIdentifier(AlgorithmOIDs.id_hmacWithSHA256);

    assertFields("PBEParameter", new PBEParameter(new byte[8], 2048),
        e -> PBEParameter.fromAsn1(Asn1Sequence.fromEncoded(e)), "salt", "iterations");

    PBKDF2Params pbkdf2 = new PBKDF2Params(salt, 10000, hmacSha256);
    assertFields("PBKDF2Params", pbkdf2,
        e -> PBKDF2Params.fromAsn1(Asn1Sequence.fromEncoded(e)),
        "salt", "iterationCount", "prf");
    // prf DEFAULT hmacWithSHA1: printed, though not encoded
    assertFields("PBKDF2Params with default prf", new PBKDF2Params(salt, 10000, 32),
        e -> PBKDF2Params.fromAsn1(Asn1Sequence.fromEncoded(e)),
        "salt", "iterationCount", "keyLength", "prf");

    AlgorithmIdentifier kdf =
        new AlgorithmIdentifier(AlgorithmOIDs.id_PBKDF2, pbkdf2.toAsn1Primitive());
    assertFields("PBES2Parameters",
        new PBES2Parameters(kdf, new AlgorithmIdentifier(NistOIDs.id_aes128_CBC,
            new Asn1OctetString(new byte[16]))),
        e -> PBES2Parameters.fromAsn1(Asn1Sequence.fromEncoded(e)), "func", "scheme");
    assertFields("PBMAC1Params", new PBMAC1Params(kdf, hmacSha256),
        e -> PBMAC1Params.fromAsn1(Asn1Sequence.fromEncoded(e)), "func", "scheme");

    assertFields("ScryptParams", new ScryptParams(salt, 16384, 8, 1),
        e -> ScryptParams.fromAsn1(Asn1Sequence.fromEncoded(e)),
        "salt", "costParameter", "blockSize", "parallelizationParameter");
  }

  @Test
  public void testRsaParameters() throws Exception {
    // all fields DEFAULT: printed, though not encoded
    assertFields("RSAESOAEPParams", new RSAESOAEPParams(),
        e -> RSAESOAEPParams.fromAsn1(Asn1Sequence.fromEncoded(e)),
        "hashAlgorithm", "maskGenAlgorithm", "pSourceAlgorithm");
    assertFields("RSASSAPSSParams", new RSASSAPSSParams(),
        e -> RSASSAPSSParams.fromAsn1(Asn1Sequence.fromEncoded(e)),
        "hashAlgorithm", "maskGenAlgorithm", "saltLength", "trailerField");
  }

  @Test
  public void testTimeAndEcParameters() throws Exception {
    Instant instant = Instant.parse("2030-12-31T23:59:59Z");
    Assert.assertEquals("UTCTime", "Time:\n  301231235959Z",
        new Time(new Asn1UtcTime(instant)).toString());
    Assert.assertEquals("GeneralizedTime", "Time:\n  20301231235959Z",
        new Time(new Asn1GeneralizedTime(instant)).toString());
    Assert.assertEquals("ECParameters", "ECParameters:\n  secp256r1",
        ECParameters.ofNamedCurve(CurveOIDs.secp256r1).toString());
  }

  @Test
  public void testRsaPrivateKey() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(2048);
    RSAPrivateCrtKey jdkKey = (RSAPrivateCrtKey) kpGen.generateKeyPair().getPrivate();

    PrivateKeyInfo pki = PrivateKeyInfo.fromEncoded(jdkKey.getEncoded());
    byte[] rsaKeyBytes = pki.getPrivateKey().getOctets();

    // the encoding of RSAPrivateKey must be the one of the JDK
    RSAPrivateKey built = new RSAPrivateKey(jdkKey.getModulus(), jdkKey.getPublicExponent(),
        jdkKey.getPrivateExponent(), jdkKey.getPrimeP(), jdkKey.getPrimeQ(),
        jdkKey.getPrimeExponentP(), jdkKey.getPrimeExponentQ(), jdkKey.getCrtCoefficient());
    Assert.assertArrayEquals("RSAPrivateKey encoding", rsaKeyBytes, built.getEncoded());

    assertFields("RSAPrivateKey", built, RSAPrivateKey::fromEncoded, "version", "modulus",
        "publicExponent", "privateExponent", "prime1", "prime2", "exponent1", "exponent2",
        "coefficient");
    RSAPrivateKey rsaKey = RSAPrivateKey.fromEncoded(rsaKeyBytes);

    BigInteger[] secrets = {jdkKey.getPrivateExponent(), jdkKey.getPrimeP(),
        jdkKey.getPrimeQ(), jdkKey.getPrimeExponentP(), jdkKey.getPrimeExponentQ(),
        jdkKey.getCrtCoefficient()};
    String text = rsaKey.toString();
    for (BigInteger secret : secrets) {
      assertNotPrinted("RSAPrivateKey", text, BigIntegers.asUnsignedByteArray(secret));
      Assert.assertFalse("decimal secret printed", text.contains(secret.toString()));
    }
    // the length of the random key's values may be less than the modulus or prime length
    Assert.assertTrue(text, text.contains("privateExponent: <"
        + BigIntegers.asUnsignedByteArray(jdkKey.getPrivateExponent()).length
        + " bytes, not printed>"));
    Assert.assertTrue(text, text.contains("prime1: <"
        + BigIntegers.asUnsignedByteArray(jdkKey.getPrimeP()).length + " bytes, not printed>"));

    assertPrivateKeyInfo("RSA", jdkKey.getEncoded());
  }

  @Test
  public void testEcPrivateKey() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
    kpGen.initialize(new ECGenParameterSpec("secp256r1"));
    java.security.interfaces.ECPrivateKey jdkKey =
        (java.security.interfaces.ECPrivateKey) kpGen.generateKeyPair().getPrivate();

    PrivateKeyInfo pki = PrivateKeyInfo.fromEncoded(jdkKey.getEncoded());
    ECPrivateKey ecKey = ECPrivateKey.fromEncoded(pki.getPrivateKey().getOctets());
    assertFields("ECPrivateKey", ecKey, ECPrivateKey::fromEncoded, "version", "privateKey");

    String text = ecKey.toString();
    assertNotPrinted("ECPrivateKey", text, ecKey.getPrivateKey().getOctets());
    assertNotPrinted("ECPrivateKey", text, BigIntegers.asUnsignedByteArray(jdkKey.getS()));
    Assert.assertTrue(text, text.contains("privateKey: <32 bytes, not printed>"));

    assertPrivateKeyInfo("EC", jdkKey.getEncoded());
  }

  @Test
  public void testEdDsaPrivateKey() throws Exception {
    KeyPairGenerator kpGen;
    try {
      kpGen = KeyPairGenerator.getInstance("Ed25519");
    } catch (NoSuchAlgorithmException e) {
      Assume.assumeNoException("Ed25519 requires JDK 15+", e);
      return;
    }

    byte[] encoded = kpGen.generateKeyPair().getPrivate().getEncoded();
    String text = assertPrivateKeyInfo("Ed25519", encoded);
    // CurvePrivateKey ::= OCTET STRING, inside the privateKey OCTET STRING
    byte[] privateKey = Arrays.copyOfRange(PrivateKeyInfo.fromEncoded(encoded)
        .getPrivateKey().getOctets(), 2, 34);
    assertNotPrinted("Ed25519", text, privateKey);
  }

  @Test
  public void testPqcPrivateKey() throws Exception {
    byte[] seed = random(32);
    byte[] expandedKey = random(2560);

    PqcPrivateKey[] keys = {new MldsaPrivateKey(seed, null),
        new MldsaPrivateKey(null, expandedKey), new MldsaPrivateKey(seed, expandedKey)};
    for (PqcPrivateKey key : keys) {
      byte[] encoded = key.getEncoded();
      String text = roundTrip("MldsaPrivateKey", key, MldsaPrivateKey::fromEncoded);
      assertNotPrinted("ML-DSA seed", text, seed);
      assertNotPrinted("ML-DSA expandedKey", text, expandedKey);
      Assert.assertTrue(text, key.getSeed() == null
          || text.contains("seed: <32 bytes, not printed>"));
      Assert.assertTrue(text, key.getExpandedKey() == null
          || text.contains("expandedKey: <2560 bytes, not printed>"));

      PrivateKeyInfo pki = new PrivateKeyInfo(
          new AlgorithmIdentifier(AlgorithmOIDs.id_ml_dsa_44), encoded);
      String pkiText = assertPrivateKeyInfo("ML-DSA", pki.getEncoded());
      assertNotPrinted("ML-DSA PrivateKeyInfo", pkiText, seed);
      assertNotPrinted("ML-DSA PrivateKeyInfo", pkiText, expandedKey);
    }
  }

  @Test
  public void testAllClassesHaveToString() throws Exception {
    Path root = Paths.get(AlgorithmIdentifier.class.getProtectionDomain().getCodeSource()
        .getLocation().toURI());
    Path dir = root.resolve("org/xipki/codec/asn1/crypto");
    Assert.assertTrue("crypt classes must be a directory: " + dir, Files.isDirectory(dir));

    List<String> missing = new ArrayList<>();
    int checked = 0;
    try (Stream<Path> paths = Files.list(dir)) {
      for (Path p : (Iterable<Path>) paths::iterator) {
        String fileName = p.getFileName().toString();
        if (!fileName.endsWith(".class") || fileName.equals("package-info.class")) {
          continue;
        }

        Class<?> clazz = Class.forName("org.xipki.codec.asn1.crypto."
            + fileName.substring(0, fileName.length() - ".class".length()));
        if (!Asn1Encodable.class.isAssignableFrom(clazz)
            || AbstractCollection.class.isAssignableFrom(clazz)) {
          continue;
        }

        checked++;
        if (!hasToString(clazz)) {
          missing.add(clazz.getName());
        }
      }
    }

    Assert.assertTrue("no classes checked", checked > 15);
    Assert.assertTrue("classes without toString(StringBuilder, int):\n"
        + String.join("\n", missing), missing.isEmpty());
  }

  private static boolean hasToString(Class<?> clazz) {
    for (Class<?> c = clazz; c != Asn1Encodable.class; c = c.getSuperclass()) {
      try {
        c.getDeclaredMethod("toString", StringBuilder.class, int.class);
        return true;
      } catch (NoSuchMethodException e) {
        // check the superclass
      }
    }
    return false;
  }

  private static String assertPrivateKeyInfo(String name, byte[] encoded) throws Exception {
    PrivateKeyInfo pki = PrivateKeyInfo.fromEncoded(encoded);
    String text = roundTrip(name + " PrivateKeyInfo", pki, PrivateKeyInfo::fromEncoded);
    for (String field : new String[]{"version", "privateKeyAlgorithm", "privateKey"}) {
      Assert.assertTrue(name + ": missing " + field + " in\n" + text, text.contains(field + ":"));
    }
    assertNotPrinted(name + " PrivateKeyInfo", text, pki.getPrivateKey().getOctets());
    Assert.assertTrue(text, text.contains("privateKey: <"
        + pki.getPrivateKey().getOctetsLength() + " bytes, not printed>"));
    return text;
  }

  private static String assertFields(String name, Asn1Encodable obj, Parser parser,
                                     String... fieldNames) throws Exception {
    String text = roundTrip(name, obj, parser);
    for (String fieldName : fieldNames) {
      Assert.assertTrue(name + ": missing field '" + fieldName + "' in\n" + text,
          text.contains(fieldName + ":"));
    }
    return text;
  }

  private static String roundTrip(String name, Asn1Encodable obj, Parser parser)
      throws Exception {
    byte[] encoded = obj.getEncoded();
    Asn1Encodable decoded = parser.parse(encoded);
    Assert.assertArrayEquals(name + ": re-encoded", encoded, decoded.getEncoded());

    String text = obj.toString();
    Assert.assertEquals(name + ": built and decoded", text, decoded.toString());

    String generic = obj.toAsn1Primitive().toString(new StringBuilder(), 0).toString();
    String own = obj.toString(new StringBuilder(), 0).toString();
    Assert.assertNotEquals(name + ": printed as generic ASN.1 dump", generic, own);
    return text;
  }

  /**
   * Asserts that no 8-byte window of the secret occurs in the text, neither as plain hex nor in
   * the colon-separated form of {@link ToStringUtil}.
   */
  private static void assertNotPrinted(String name, String text, byte[] secret) {
    String compact = text.replace(":", "").replace("\n", "").replace(" ", "");
    for (int i = 0; i + 8 <= secret.length; i += 8) {
      String hex = Hex.encode(Arrays.copyOfRange(secret, i, i + 8));
      Assert.assertFalse(name + ": private key material printed:\n" + text,
          compact.contains(hex));
    }
  }

  private static byte[] random(int len) {
    byte[] bytes = new byte[len];
    RND.nextBytes(bytes);
    return bytes;
  }

}
