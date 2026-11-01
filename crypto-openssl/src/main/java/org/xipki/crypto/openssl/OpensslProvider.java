// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.crypto.openssl.OpenSsl.Kind;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * JCA provider on libcrypto of OpenSSL 3.5+. All algorithms are those of OpenSSL; the ones
 * OpenSSL does not support as such are composed of its primitives (ECDSA and RSASSA-PSS with
 * SHAKE). Not registered in {@link java.security.Security}: it is used by
 * {@link OpensslCryptoApi}.
 * <p>
 * A service is registered only if OpenSSL can fetch the algorithms it needs with the default
 * properties. In the FIPS mode (see {@link OpenSsl}), the algorithms which the provider fips
 * does not have (e.g. SM2 and SM3) are therefore absent, and the composed algorithms (ECDSA and
 * RSASSA-PSS with SHAKE) are disabled.
 *
 * @author Lijun Liao (xipki)
 */
public final class OpensslProvider extends Provider {

  /** The name of the provider. */
  public static final String NAME = "XiPKI-OpenSSL";

  /** The name of the SecureRandom. */
  public static final String SECURE_RANDOM = "OPENSSL-DRBG";

  @FunctionalInterface
  private interface SpiFactory {
    Object create() throws NoSuchAlgorithmException;
  }

  /**
   * Constructor.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available.
   */
  public OpensslProvider() {
    super(NAME, "1.0", "XiPKI provider on " + versionText());
    OpenSsl.ensureAvailable();

    addDigests();
    addMacs();
    addSignatures();
    addCiphers();
    addKeys();
    addSecrets();
  }

  private static String versionText() {
    if (!OpenSsl.isAvailable()) {
      return "OpenSSL (not available)";
    }
    return OpenSsl.version() + (OpenSsl.isFipsEnabled() ? " (FIPS mode)" : "");
  }

  private void addDigests() {
    digest("SHA-1", "SHA1", 0, "SHA1", "SHA", AlgorithmOIDs.id_sha1);
    digest("SHA-224", "SHA2-224", 0, "SHA224", AlgorithmOIDs.id_sha224);
    digest("SHA-256", "SHA2-256", 0, "SHA256", AlgorithmOIDs.id_sha256);
    digest("SHA-384", "SHA2-384", 0, "SHA384", AlgorithmOIDs.id_sha384);
    digest("SHA-512", "SHA2-512", 0, "SHA512", AlgorithmOIDs.id_sha512);
    digest("SHA-512/224", "SHA2-512/224", 0, "SHA512/224", NistOIDs.id_sha512_224);
    digest("SHA-512/256", "SHA2-512/256", 0, "SHA512/256", NistOIDs.id_sha512_256);
    digest("SHA3-224", "SHA3-224", 0, AlgorithmOIDs.id_sha3_224);
    digest("SHA3-256", "SHA3-256", 0, AlgorithmOIDs.id_sha3_256);
    digest("SHA3-384", "SHA3-384", 0, AlgorithmOIDs.id_sha3_384);
    digest("SHA3-512", "SHA3-512", 0, AlgorithmOIDs.id_sha3_512);
    digest("SM3", "SM3", 0, AlgorithmOIDs.id_sm3);
    // the XOFs with the output length of their use as digest (RFC 8702)
    digest("SHAKE128-256", "SHAKE128", 32, "SHAKE128", AlgorithmOIDs.id_shake128);
    digest("SHAKE256-512", "SHAKE256", 64, "SHAKE256", AlgorithmOIDs.id_shake256);
  }

  private void digest(String name, String opensslName, int xofLen, Object... aliases) {
    if (has(Kind.DIGEST, opensslName)) {
      service("MessageDigest", name, () -> new OpensslDigest(opensslName, xofLen), aliases);
    }
  }

  private void addMacs() {
    hmac("HmacSHA1", "SHA1", AlgorithmOIDs.id_hmacWithSHA1);
    hmac("HmacSHA224", "SHA2-224", AlgorithmOIDs.id_hmacWithSHA224);
    hmac("HmacSHA256", "SHA2-256", AlgorithmOIDs.id_hmacWithSHA256);
    hmac("HmacSHA384", "SHA2-384", AlgorithmOIDs.id_hmacWithSHA384);
    hmac("HmacSHA512", "SHA2-512", AlgorithmOIDs.id_hmacWithSHA512);
    hmac("HmacSHA512/224", "SHA2-512/224", PkcsOIDs.id_hmacWithSHA512_224);
    hmac("HmacSHA512/256", "SHA2-512/256", PkcsOIDs.id_hmacWithSHA512_256);
    hmac("HmacSHA3-224", "SHA3-224", AlgorithmOIDs.id_hmacWithSHA3_224);
    hmac("HmacSHA3-256", "SHA3-256", AlgorithmOIDs.id_hmacWithSHA3_256);
    hmac("HmacSHA3-384", "SHA3-384", AlgorithmOIDs.id_hmacWithSHA3_384);
    hmac("HmacSHA3-512", "SHA3-512", AlgorithmOIDs.id_hmacWithSHA3_512);
    hmac("HmacSM3", "SM3");
    if (has(Kind.MAC, "GMAC") && has(Kind.CIPHER, "AES-256-GCM")) {
      service("Mac", "AES-GMAC", () -> new OsslMac(null), "AESGMAC", "GMAC",
          AlgorithmOIDs.AES128_GMAC, AlgorithmOIDs.AES192_GMAC, AlgorithmOIDs.AES256_GMAC);
    }
  }

  private void hmac(String name, String md, Object... aliases) {
    if (has(Kind.MAC, "HMAC") && has(Kind.DIGEST, md)) {
      service("Mac", name, () -> new OsslMac(md), aliases);
    }
  }

  private void addSignatures() {
    String[] rsa = keyTypes("RSA", "RSA-PSS");
    String[] ec = keyTypes("EC");
    boolean hasRsa = rsa != null && has(Kind.SIGNATURE, "RSA");
    boolean hasEcdsa = ec != null && has(Kind.SIGNATURE, "ECDSA");

    // RSA PKCS#1 v1.5
    Object[][] rsaAlgs = {
        {"SHA1WITHRSA", "SHA1", AlgorithmOIDs.sha1WithRSAEncryption},
        {"SHA224WITHRSA", "SHA2-224", AlgorithmOIDs.sha224WithRSAEncryption},
        {"SHA256WITHRSA", "SHA2-256", AlgorithmOIDs.sha256WithRSAEncryption},
        {"SHA384WITHRSA", "SHA2-384", AlgorithmOIDs.sha384WithRSAEncryption},
        {"SHA512WITHRSA", "SHA2-512", AlgorithmOIDs.sha512WithRSAEncryption},
        {"SHA3-224WITHRSA", "SHA3-224", AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_224},
        {"SHA3-256WITHRSA", "SHA3-256", AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_256},
        {"SHA3-384WITHRSA", "SHA3-384", AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_384},
        {"SHA3-512WITHRSA", "SHA3-512", AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_512}};
    for (Object[] a : rsaAlgs) {
      if (hasRsa && has(Kind.DIGEST, (String) a[1])) {
        NativeKey.SigOp op = OpensslSignature.Fixed.rsa((String) a[1]);
        service("Signature", (String) a[0], () -> new OpensslSignature.Fixed(op, rsa), a[2]);
      }
    }

    // RSA PSS, MGF1 with the same digest, salt length = digest length
    String[][] pssAlgs = {{"SHA1", "SHA1"}, {"SHA224", "SHA2-224"}, {"SHA256", "SHA2-256"},
        {"SHA384", "SHA2-384"}, {"SHA512", "SHA2-512"}, {"SHA3-224", "SHA3-224"},
        {"SHA3-256", "SHA3-256"}, {"SHA3-384", "SHA3-384"}, {"SHA3-512", "SHA3-512"}};
    for (String[] a : pssAlgs) {
      if (hasRsa && has(Kind.DIGEST, a[1])) {
        NativeKey.SigOp op = OpensslSignature.Fixed.rsaPss(a[1]);
        service("Signature", a[0] + "WITHRSAANDMGF1",
            () -> new OpensslSignature.Fixed(op, rsa), a[0] + "WITHRSA/PSS");
      }
    }
    if (hasRsa) {
      service("Signature", "RSASSA-PSS", OpensslSignature.RsaPss::new,
          "RSAPSS", AlgorithmOIDs.id_RSASSA_PSS);
    }

    // RSA PSS with SHAKE (RFC 8702)
    if (OsslRsaPssShake.isEnabled() && hasRsa) {
      if (has(Kind.DIGEST, "SHAKE128")) {
        service("Signature", "SHAKE128WITHRSAPSS", () -> new OsslRsaPssShake("SHAKE128"),
            AlgorithmOIDs.id_RSASSA_PSS_SHAKE128);
      }
      if (has(Kind.DIGEST, "SHAKE256")) {
        service("Signature", "SHAKE256WITHRSAPSS", () -> new OsslRsaPssShake("SHAKE256"),
            AlgorithmOIDs.id_RSASSA_PSS_SHAKE256);
      }
    }

    // ECDSA
    Object[][] ecdsaAlgs = {
        {"SHA1WITHECDSA", "SHA1", AlgorithmOIDs.ecdsa_with_SHA1},
        {"SHA224WITHECDSA", "SHA2-224", AlgorithmOIDs.ecdsa_with_SHA224},
        {"SHA256WITHECDSA", "SHA2-256", AlgorithmOIDs.ecdsa_with_SHA256},
        {"SHA384WITHECDSA", "SHA2-384", AlgorithmOIDs.ecdsa_with_SHA384},
        {"SHA512WITHECDSA", "SHA2-512", AlgorithmOIDs.ecdsa_with_SHA512},
        {"SHA3-224WITHECDSA", "SHA3-224", AlgorithmOIDs.id_ecdsa_with_sha3_224},
        {"SHA3-256WITHECDSA", "SHA3-256", AlgorithmOIDs.id_ecdsa_with_sha3_256},
        {"SHA3-384WITHECDSA", "SHA3-384", AlgorithmOIDs.id_ecdsa_with_sha3_384},
        {"SHA3-512WITHECDSA", "SHA3-512", AlgorithmOIDs.id_ecdsa_with_sha3_512}};
    for (Object[] a : ecdsaAlgs) {
      if (hasEcdsa && has(Kind.DIGEST, (String) a[1])) {
        NativeKey.SigOp op = OpensslSignature.Fixed.ecdsa((String) a[1]);
        service("Signature", (String) a[0], () -> new OpensslSignature.Fixed(op, ec), a[2]);
      }
    }
    // ECDSA with SHAKE is composed (the hash is signed): not in the FIPS mode, as in the backend
    // bc-fips, since it is not clear that the FIPS validation covers the signing of the hash
    boolean ecdsaShake = hasEcdsa && !OpenSsl.isFipsEnabled();
    if (ecdsaShake && has(Kind.DIGEST, "SHAKE128")) {
      service("Signature", "SHAKE128WITHECDSA",
          () -> new OpensslSignature.EcdsaShake("SHAKE128"),
          AlgorithmOIDs.id_ecdsa_with_shake128);
    }
    if (ecdsaShake && has(Kind.DIGEST, "SHAKE256")) {
      service("Signature", "SHAKE256WITHECDSA",
          () -> new OpensslSignature.EcdsaShake("SHAKE256"),
          AlgorithmOIDs.id_ecdsa_with_shake256);
    }

    // SM2
    if (keyTypes("SM2") != null && has(Kind.SIGNATURE, "SM2") && has(Kind.DIGEST, "SM3")) {
      NativeKey.SigOp sm2 = OpensslSignature.Fixed.sm2();
      service("Signature", "SM3WITHSM2", () -> new OpensslSignature.Fixed(sm2, "SM2"),
          "SM2WITHSM3", AlgorithmOIDs.sm2sign_with_sm3);
    }

    // EdDSA
    String[] eddsaTypes = signatureKeyTypes("ED25519", "ED448");
    if (eddsaTypes != null) {
      NativeKey.SigOp eddsa = OpensslSignature.Fixed.eddsa();
      service("Signature", "EdDSA", () -> new OpensslSignature.Fixed(eddsa, eddsaTypes));
      if (Arrays.asList(eddsaTypes).contains("ED25519")) {
        service("Signature", "Ed25519", () -> new OpensslSignature.Fixed(eddsa, "ED25519"),
            AlgorithmOIDs.id_Ed25519);
      }
      if (Arrays.asList(eddsaTypes).contains("ED448")) {
        service("Signature", "Ed448", () -> new OpensslSignature.Fixed(eddsa, "ED448"),
            AlgorithmOIDs.id_Ed448);
      }
    }

    // ML-DSA
    String[] mldsa = signatureKeyTypes("ML-DSA-44", "ML-DSA-65", "ML-DSA-87");
    if (mldsa != null) {
      service("Signature", "ML-DSA", () -> new OpensslSignature.Mldsa(mldsa));
      for (String[] v : mldsaVariants()) {
        if (Arrays.asList(mldsa).contains(v[0])) {
          service("Signature", v[0], () -> new OpensslSignature.Mldsa(v[0]), v[1]);
        }
      }
    }
  }

  private void addCiphers() {
    for (String mode : new String[]{"CBC", "ECB"}) {
      if (has(Kind.CIPHER, "AES-256-" + mode)) {
        service("Cipher", "AES/" + mode + "/PKCS5Padding",
            () -> new OsslSymCipher("AES", mode, true));
        service("Cipher", "AES/" + mode + "/NoPadding",
            () -> new OsslSymCipher("AES", mode, false));
      }
    }
    if (has(Kind.CIPHER, "AES-256-CTR")) {
      service("Cipher", "AES/CTR/NoPadding", () -> new OsslSymCipher("AES", "CTR", false));
    }
    if (has(Kind.CIPHER, "AES-256-GCM")) {
      service("Cipher", "AES/GCM/NoPadding", () -> new OsslSymCipher("AES", "GCM", false));
    }
    if (has(Kind.CIPHER, "AES-256-WRAP")) {
      service("Cipher", "AESWrap", () -> new OsslSymCipher("AES", "WRAP", false), "AESKW");
    }
    if (has(Kind.CIPHER, "AES-256-WRAP-PAD")) {
      service("Cipher", "AESWrapPad", () -> new OsslSymCipher("AES", "WRAP-PAD", false),
          "AESKWP");
    }
    if (has(Kind.CIPHER, "DES-EDE3-CBC")) {
      service("Cipher", "DESede/CBC/PKCS5Padding",
          () -> new OsslSymCipher("DES-EDE3", "CBC", true));
      service("Cipher", "DESede/CBC/NoPadding",
          () -> new OsslSymCipher("DES-EDE3", "CBC", false));
    }

    if (keyTypes("RSA") != null && has(Kind.ASYM_CIPHER, "RSA")) {
      service("Cipher", "RSA/ECB/PKCS1Padding", () -> new OsslRsaCipher("pkcs1"), "RSA");
      service("Cipher", "RSA/ECB/OAEPPadding", () -> new OsslRsaCipher("oaep"));
      service("Cipher", "RSA/ECB/NoPadding", () -> new OsslRsaCipher("none"));
    }
  }

  private void addKeys() {
    String[] rsa = keyTypes("RSA", "RSA-PSS");
    keyService("RSA", OsslKeyPairGenerator.Family.RSA, null, rsa, PkcsOIDs.rsaEncryption);
    if (rsa != null) {
      service("KeyFactory", "RSASSA-PSS", () -> new OsslKeyFactory(rsa), "RSAPSS",
          AlgorithmOIDs.id_RSASSA_PSS);
    }
    keyService("EC", OsslKeyPairGenerator.Family.EC, null, keyTypes("EC", "SM2"),
        AlgorithmOIDs.id_ecPublicKey);

    String[] eddsa = keyTypes("ED25519", "ED448");
    keyService("EdDSA", OsslKeyPairGenerator.Family.EDDSA, null, eddsa);
    keyService("Ed25519", OsslKeyPairGenerator.Family.EDDSA, "ED25519",
        keyTypes("ED25519"), AlgorithmOIDs.id_Ed25519);
    keyService("Ed448", OsslKeyPairGenerator.Family.EDDSA, "ED448",
        keyTypes("ED448"), AlgorithmOIDs.id_Ed448);
    keyService("XDH", OsslKeyPairGenerator.Family.XDH, null, keyTypes("X25519", "X448"));
    keyService("X25519", OsslKeyPairGenerator.Family.XDH, "X25519",
        keyTypes("X25519"), AlgorithmOIDs.id_X25519);
    keyService("X448", OsslKeyPairGenerator.Family.XDH, "X448",
        keyTypes("X448"), AlgorithmOIDs.id_X448);

    keyService("ML-DSA", OsslKeyPairGenerator.Family.MLDSA, null,
        keyTypes("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"));
    for (String[] v : mldsaVariants()) {
      keyService(v[0], OsslKeyPairGenerator.Family.MLDSA, v[0], keyTypes(v[0]), v[1]);
    }
    keyService("ML-KEM", OsslKeyPairGenerator.Family.MLKEM, null,
        keyTypes("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"));
    for (String[] v : mlkemVariants()) {
      keyService(v[0], OsslKeyPairGenerator.Family.MLKEM, v[0], keyTypes(v[0]), v[1]);
    }

    if (keyTypes("EC") != null && has(Kind.KEYEXCH, "ECDH")) {
      service("KeyAgreement", "ECDH", () -> new OsslKeyAgreement("EC"));
    }
    String[] xdh = keyExchangeKeyTypes("X25519", "X448");
    if (xdh != null) {
      service("KeyAgreement", "XDH", () -> new OsslKeyAgreement(xdh));
      if (Arrays.asList(xdh).contains("X25519")) {
        service("KeyAgreement", "X25519", () -> new OsslKeyAgreement("X25519"),
            AlgorithmOIDs.id_X25519);
      }
      if (Arrays.asList(xdh).contains("X448")) {
        service("KeyAgreement", "X448", () -> new OsslKeyAgreement("X448"),
            AlgorithmOIDs.id_X448);
      }
    }
  }

  /**
   * KeyFactory and KeyPairGenerator.
   * @param keyTypes the key types, nothing is registered if null.
   */
  private void keyService(String name, OsslKeyPairGenerator.Family family, String fixedType,
                          String[] keyTypes, Object... aliases) {
    if (keyTypes == null) {
      return;
    }
    service("KeyFactory", name, () -> new OsslKeyFactory(keyTypes), aliases);
    service("KeyPairGenerator", name, () -> new OsslKeyPairGenerator(family, fixedType),
        aliases);
  }

  private void addSecrets() {
    service("KeyGenerator", "AES", () -> new OsslSecretSpis.KeyGen("AES", 256, 128, 192, 256));
    // DESede: 112 (two keys) and 168 (three keys) as in the JDK, 192 as alias of 168
    if (has(Kind.CIPHER, "DES-EDE3-CBC")) {
      service("KeyGenerator", "DESede",
          () -> new OsslSecretSpis.KeyGen("DESede", 168, 112, 168, 192), "TripleDES");
    }

    // HMAC keys: the default size is the output size of the digest
    Object[][] hmacs = {{"HmacSHA1", "SHA1", 160}, {"HmacSHA224", "SHA2-224", 224},
        {"HmacSHA256", "SHA2-256", 256}, {"HmacSHA384", "SHA2-384", 384},
        {"HmacSHA512", "SHA2-512", 512}, {"HmacSHA3-224", "SHA3-224", 224},
        {"HmacSHA3-256", "SHA3-256", 256}, {"HmacSHA3-384", "SHA3-384", 384},
        {"HmacSHA3-512", "SHA3-512", 512}, {"HmacSM3", "SM3", 256}};
    for (Object[] h : hmacs) {
      String name = (String) h[0];
      int bits = (Integer) h[2];
      if (has(Kind.DIGEST, (String) h[1])) {
        service("KeyGenerator", name, () -> new OsslSecretSpis.KeyGen(name, bits));
      }
    }

    String[][] pbkdf2 = {{"SHA1", "SHA1"}, {"SHA224", "SHA2-224"}, {"SHA256", "SHA2-256"},
        {"SHA384", "SHA2-384"}, {"SHA512", "SHA2-512"}, {"SHA512/224", "SHA2-512/224"},
        {"SHA512/256", "SHA2-512/256"}, {"SHA3-224", "SHA3-224"}, {"SHA3-256", "SHA3-256"},
        {"SHA3-384", "SHA3-384"}, {"SHA3-512", "SHA3-512"}, {"SM3", "SM3"}};
    for (String[] p : pbkdf2) {
      String name = "PBKDF2WithHmac" + p[0];
      if (has(Kind.KDF, "PBKDF2") && has(Kind.DIGEST, p[1])) {
        service("SecretKeyFactory", name, () -> new OsslSecretSpis.Pbkdf2(name, p[1]));
      }
    }

    service("SecureRandom", SECURE_RANDOM, OsslSecretSpis.Random::new);
  }

  private static String[][] mldsaVariants() {
    return new String[][]{{"ML-DSA-44", NistOIDs.id_ml_dsa_44.getId()},
        {"ML-DSA-65", NistOIDs.id_ml_dsa_65.getId()},
        {"ML-DSA-87", NistOIDs.id_ml_dsa_87.getId()}};
  }

  private static String[][] mlkemVariants() {
    return new String[][]{{"ML-KEM-512", NistOIDs.id_ml_kem_512.getId()},
        {"ML-KEM-768", NistOIDs.id_ml_kem_768.getId()},
        {"ML-KEM-1024", NistOIDs.id_ml_kem_1024.getId()}};
  }

  private static boolean has(Kind kind, String name) {
    return OpenSsl.hasAlgorithm(kind, name);
  }

  /**
   * Returns the key types which OpenSSL has.
   * @return the available key types, or null if none.
   */
  private static String[] keyTypes(String... types) {
    return filter(types, Kind.KEYMGMT, Kind.KEYMGMT);
  }

  /**
   * Returns the key types which OpenSSL has, with a signature algorithm of the same name.
   * @return the available key types, or null if none.
   */
  private static String[] signatureKeyTypes(String... types) {
    return filter(types, Kind.KEYMGMT, Kind.SIGNATURE);
  }

  /**
   * Returns the key types which OpenSSL has, with a key exchange of the same name.
   * @return the available key types, or null if none.
   */
  private static String[] keyExchangeKeyTypes(String... types) {
    return filter(types, Kind.KEYMGMT, Kind.KEYEXCH);
  }

  private static String[] filter(String[] names, Kind kind1, Kind kind2) {
    String[] res = Arrays.stream(names)
        .filter(n -> has(kind1, n) && has(kind2, n)).toArray(String[]::new);
    return res.length == 0 ? null : res;
  }

  /**
   * Registers the service.
   * @param aliases the aliases: names ({@link String}) or OIDs ({@link Asn1Oid} or
   *                {@link String}).
   */
  private void service(String type, String algorithm, SpiFactory factory, Object... aliases) {
    List<String> names = new ArrayList<>(aliases.length);
    for (Object alias : aliases) {
      names.add(alias instanceof Asn1Oid oid ? oid.getId() : (String) alias);
    }
    putService(new Service(this, type, algorithm, OpensslProvider.class.getName(), names,
        Map.of()) {
      @Override
      public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
        return factory.create();
      }
    });
  }

}
