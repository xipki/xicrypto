// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.api.AlgorithmNames;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.SecretWithEncapImpl;
import org.xipki.crypto.api.X9ECParameters;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import java.lang.foreign.MemorySegment;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Crypto backend on libcrypto of OpenSSL 3.5+, via the Foreign Function &amp; Memory API
 * (JDK 25+). All cryptographic operations are those of OpenSSL ({@link OpensslProvider}).
 * <p>
 * Exceptions:
 * <ul>
 *   <li>Composed of OpenSSL's primitives: ECDSA with SHAKE (the hash is signed), and RSASSA-PSS
 *       with SHAKE (the EMSA-PSS encoding in Java, see {@link OsslRsaPssShake}).</li>
 * </ul>
 * The randomness comes from the DRBG of OpenSSL: the {@code SecureRandom} arguments of the JCA
 * objects are not used for the operations of OpenSSL, and {@link #getSecureRandom()} returns
 * the DRBG of OpenSSL.
 * <p>
 * See {@link OpenSsl} for how libcrypto is found and how the FIPS mode is configured. Only
 * the algorithms which OpenSSL has are registered, see {@link OpensslProvider}.
 * <p>
 * The backends are the subclasses {@code CryptoOpenssl} (module crypto-be-openssl, OpenSSL must
 * not be in the FIPS mode) and {@code CryptoOpensslFips} (module crypto-be-openssl-fips, OpenSSL
 * must be in the FIPS mode).
 *
 * @author Lijun Liao (xipki)
 */
public abstract class OpensslCryptoApi implements CryptoApi {

  /** OIDs and further names of ciphers to the transformations of {@link OpensslProvider}. */
  private static final Map<String, String> CIPHER_NAMES = new HashMap<>();

  /** Upper bound of the expanded private keys (ML-DSA-87: 4896 bytes). */
  private static final int MAX_EXPANDED_KEY_LEN = 8192;

  static {
    for (Asn1Oid oid : new Asn1Oid[]{NistOIDs.id_aes128_CBC, NistOIDs.id_aes192_CBC,
        NistOIDs.id_aes256_CBC}) {
      CIPHER_NAMES.put(oid.getId(), "AES/CBC/PKCS5Padding");
    }
    for (Asn1Oid oid : new Asn1Oid[]{NistOIDs.id_aes128_ECB, NistOIDs.id_aes192_ECB,
        NistOIDs.id_aes256_ECB}) {
      CIPHER_NAMES.put(oid.getId(), "AES/ECB/PKCS5Padding");
    }
    for (Asn1Oid oid : new Asn1Oid[]{NistOIDs.id_aes128_GCM, NistOIDs.id_aes192_GCM,
        NistOIDs.id_aes256_GCM}) {
      CIPHER_NAMES.put(oid.getId(), "AES/GCM/NoPadding");
    }
    for (Asn1Oid oid : new Asn1Oid[]{NistOIDs.id_aes128_wrap, NistOIDs.id_aes192_wrap,
        NistOIDs.id_aes256_wrap}) {
      CIPHER_NAMES.put(oid.getId(), "AESWrap");
    }
    for (Asn1Oid oid : new Asn1Oid[]{NistOIDs.id_aes128_wrap_pad, NistOIDs.id_aes192_wrap_pad,
        NistOIDs.id_aes256_wrap_pad}) {
      CIPHER_NAMES.put(oid.getId(), "AESWrapPad");
    }
    CIPHER_NAMES.put(PkcsOIDs.des_EDE3_CBC.getId(), "DESede/CBC/PKCS5Padding");
    CIPHER_NAMES.put(PkcsOIDs.rsaEncryption.getId(), "RSA/ECB/PKCS1Padding");
    CIPHER_NAMES.put(PkcsOIDs.id_RSAES_OAEP.getId(), "RSA/ECB/OAEPPadding");
  }

  private static final class Holder {
    private static final OpensslProvider PROVIDER = new OpensslProvider();

    private static final SecureRandom RANDOM;

    static {
      try {
        RANDOM = SecureRandom.getInstance(OpensslProvider.SECURE_RANDOM, PROVIDER);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  /**
   * Constructor.
   * @param fips whether OpenSSL must be in the FIPS mode (true) or must not be in it (false).
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available, or if the FIPS
   *         mode of OpenSSL is not the required one.
   */
  protected OpensslCryptoApi(boolean fips) {
    OpenSsl.ensureAvailable();
    OpenSsl.ensureFipsMode(fips, name());
  }

  /**
   * Returns the provider on OpenSSL. It is not registered in {@link Security}.
   * @return the provider.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available.
   */
  public static OpensslProvider provider() {
    return Holder.PROVIDER;
  }

  @Override
  public KeyAgreement newKeyAgreement(String algorithm) throws NoSuchAlgorithmException {
    return KeyAgreement.getInstance(algorithm, provider());
  }

  @Override
  public MessageDigest newMessageDigest(String algorithm) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algorithm, provider());
  }

  @Override
  public Mac newMac(String algorithm) throws NoSuchAlgorithmException {
    return Mac.getInstance(normalizeMacName(algorithm), provider());
  }

  /**
   * Returns the JCA name of the MAC: OIDs are mapped to names, and the BouncyCastle-style names
   * such as HMAC-SHA256 and HmacSHA-256 to HmacSHA256.
   */
  static String normalizeMacName(String algorithm) {
    if (!algorithm.isEmpty() && Character.isDigit(algorithm.charAt(0))) {
      try {
        String name = AlgorithmNames.getHmacName(new Asn1Oid(algorithm));
        if (name != null) {
          return name;
        }
      } catch (RuntimeException e) {
        // not an OID
      }
      return algorithm;
    }

    String upper = algorithm.toUpperCase(Locale.ROOT);
    if (upper.startsWith("HMAC-") || upper.startsWith("HMAC/")) {
      algorithm = "HMAC" + algorithm.substring(5);
      upper = algorithm.toUpperCase(Locale.ROOT);
    }

    int index = upper.indexOf("SHA-");
    if (index != -1) {
      algorithm = algorithm.substring(0, index + 3) + algorithm.substring(index + 4);
    }
    return algorithm;
  }

  @Override
  public Signature newSignature(String algorithm) throws NoSuchAlgorithmException {
    return Signature.getInstance(algorithm, provider());
  }

  @Override
  public Cipher newCipher(String algorithm)
      throws NoSuchPaddingException, NoSuchAlgorithmException {
    String name = CIPHER_NAMES.get(algorithm);
    if (name == null) {
      name = algorithm;
      // RSA/NONE/... -> RSA/ECB/...
      if (algorithm.toUpperCase(Locale.ROOT).startsWith("RSA/NONE/")) {
        name = "RSA/ECB/" + algorithm.substring("RSA/NONE/".length());
      }
    }
    return Cipher.getInstance(name, provider());
  }

  @Override
  public KeyFactory newKeyFactory(String algorithm) throws NoSuchAlgorithmException {
    return KeyFactory.getInstance(algorithm, provider());
  }

  @Override
  public KeyPairGenerator newKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(algorithm, provider());
  }

  @Override
  public KeyGenerator newKeyGenerator(String algorithm) throws NoSuchAlgorithmException {
    return KeyGenerator.getInstance(algorithm, provider());
  }

  @Override
  public SecretKeyFactory newSecretKeyFactory(String algorithm) throws NoSuchAlgorithmException {
    return SecretKeyFactory.getInstance(algorithm, provider());
  }

  @Override
  public PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    MemorySegment pkey = OpenSsl.d2iPublicKey(publicKeyInfo.getEncoded());
    if (OpenSsl.isNull(pkey)) {
      throw new InvalidKeySpecException("invalid or unsupported public key "
          + publicKeyInfo.getAlgorithm().getAlgorithm().getId() + ": " + OpenSsl.errors());
    }
    try {
      return (PublicKey) OsslKey.wrap(pkey, false);
    } catch (InvalidKeyException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }
  }

  @Override
  public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws InvalidKeySpecException {
    byte[] encoded = privateKeyInfo.getEncoded();
    MemorySegment pkey;
    try {
      pkey = OpenSsl.d2iPrivateKey(encoded);
    } finally {
      XiArrays.clear(encoded);
    }
    if (OpenSsl.isNull(pkey)) {
      throw new InvalidKeySpecException("invalid or unsupported private key "
          + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId() + ": "
          + OpenSsl.errors());
    }
    try {
      return (PrivateKey) OsslKey.wrap(pkey, true);
    } catch (InvalidKeyException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }
  }

  @Override
  public byte[] pbkdf2(String hmacAlgorithm, char[] password, byte[] salt, int iterationCount,
                       int keyLength) throws GeneralSecurityException {
    String hmac = normalizeMacName(hmacAlgorithm);
    String md = hmac.regionMatches(true, 0, "Hmac", 0, 4)
        ? OsslNames.digest(hmac.substring(4)) : null;
    if (md == null) {
      throw new NoSuchAlgorithmException("unsupported PBKDF2 PRF " + hmacAlgorithm);
    }
    try {
      return OsslSecretSpis.pbkdf2(password, salt, iterationCount, keyLength, md);
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException(e.getMessage(), e);
    }
  }

  /**
   * Sets the context string of the ML-DSA signatures of {@link #newSignature(String)}. It is
   * reset at initSign and initVerify, so set it after these.
   */
  @Override
  public void setContext(Signature sig, byte[] context) throws InvalidAlgorithmParameterException {
    if (sig.getProvider() == provider() && sig.getAlgorithm().toUpperCase(Locale.ROOT)
        .startsWith("ML-DSA")) {
      sig.setParameter(new OpensslSignature.ContextSpec(context));
    } else if (context != null && context.length > 0) {
      throw new InvalidAlgorithmParameterException(
          "signature context is not supported for " + sig.getAlgorithm());
    }
  }

  @Override
  public byte[] xof(String algorithm, byte[] data, int length) {
    String upper = algorithm.toUpperCase(Locale.ROOT);
    String name = ("SHAKE128".equals(upper) || "SHAKE128-256".equals(upper)) ? "SHAKE128"
        : ("SHAKE256".equals(upper) || "SHAKE256-512".equals(upper)) ? "SHAKE256" : null;
    if (name == null) {
      throw new UnsupportedOperationException("unsupported XOF " + algorithm);
    }
    return OpenSsl.digest(OpenSsl.md(name), MemorySegment.ofArray(data), length, true);
  }

  /**
   * HKDF-SHA256 (RFC 5869) of OpenSSL. An absent salt is a string of 32 zeros.
   */
  @Override
  public byte[] hkdfSha256Derive(byte[] ikm, byte[] salt, byte[] info, int outputKeyLen) {
    if (outputKeyLen < 0 || outputKeyLen > 255 * 32) {
      throw new IllegalArgumentException("invalid outputKeyLen " + outputKeyLen);
    }
    if (outputKeyLen == 0) {
      return new byte[0];
    }

    byte[] key = OpenSsl.kdfDerive("HKDF", new OsslParams().utf8("digest", "SHA2-256")
        .secretOctets("key", ikm == null ? new byte[0] : ikm.clone())
        .octets("salt", (salt == null || salt.length == 0) ? new byte[32] : salt)
        .octets("info", info == null ? new byte[0] : info), outputKeyLen);
    if (key == null) {
      throw new IllegalStateException("HKDF-SHA256 failed: " + OpenSsl.errors());
    }
    return key;
  }

  /** Returns the DRBG of OpenSSL. */
  @Override
  public SecureRandom getSecureRandom() {
    return Holder.RANDOM;
  }

  /**
   * Returns the arithmetic of OpenSSL for the curve.
   * @return the parameters, or null if the curve is not supported.
   */
  @Override
  public X9ECParameters getByOID(Asn1Oid oid) {
    return OsslEcParameters.of(oid);
  }

  // ---------- X25519, X448 ----------

  /** Whether OpenSSL has X25519 and X448, e.g. not in the FIPS mode of OpenSSL 3.5. */
  private static final class Xdh {
    private static final boolean X25519 = has("X25519");

    private static final boolean X448 = has("X448");

    private static boolean has(String type) {
      return OpenSsl.hasAlgorithm(OpenSsl.Kind.KEYMGMT, type)
          && OpenSsl.hasAlgorithm(OpenSsl.Kind.KEYEXCH, type);
    }
  }

  /**
   * {@inheritDoc}
   * @throws UnsupportedOperationException if OpenSSL does not have X25519 (FIPS mode).
   */
  @Override
  public byte[] generateX25519PrivateKey() {
    checkXdhSupported("X25519");
    return generateXdhPrivateKey(32);
  }

  @Override
  public byte[] generateX25519PublicKey(byte[] sk) {
    return xdhPublicKey("X25519", sk);
  }

  @Override
  public byte[] calculateX25519Agreement(byte[] sk, byte[] peerPk) {
    return xdhAgreement("X25519", sk, peerPk);
  }

  /**
   * {@inheritDoc}
   * @throws UnsupportedOperationException if OpenSSL does not have X448 (FIPS mode).
   */
  @Override
  public byte[] generateX448PrivateKey() {
    checkXdhSupported("X448");
    return generateXdhPrivateKey(56);
  }

  private static void checkXdhSupported(String type) {
    if (!("X25519".equals(type) ? Xdh.X25519 : Xdh.X448)) {
      throw new UnsupportedOperationException(OpenSsl.version() + (OpenSsl.isFipsEnabled()
          ? " in the FIPS mode" : "") + " does not support " + type);
    }
  }

  @Override
  public byte[] generateX448PublicKey(byte[] sk) {
    return xdhPublicKey("X448", sk);
  }

  @Override
  public byte[] calculateX448Agreement(byte[] sk, byte[] peerPk) {
    return xdhAgreement("X448", sk, peerPk);
  }

  /** The random private key, clamped as in RFC 7748, section 5. */
  private static byte[] generateXdhPrivateKey(int len) {
    byte[] k = new byte[len];
    OpenSsl.randomBytes(k, true);
    if (len == 32) {
      k[0] &= (byte) 0xF8;
      k[31] &= 0x7F;
      k[31] |= 0x40;
    } else {
      k[0] &= (byte) 0xFC;
      k[55] |= (byte) 0x80;
    }
    return k;
  }

  private static byte[] xdhPublicKey(String type, byte[] sk) {
    checkXdhSupported(type);
    checkXdhLength(type, sk);
    MemorySegment pkey = OpenSsl.newRawPrivateKey(type, sk);
    if (OpenSsl.isNull(pkey)) {
      throw new IllegalArgumentException("invalid " + type + " private key: "
          + OpenSsl.errors());
    }
    try {
      byte[] pk = OpenSsl.pkeyRawKey(pkey, false);
      if (pk == null) {
        throw new IllegalStateException(type + " failed: " + OpenSsl.errors());
      }
      return pk;
    } finally {
      OpenSsl.pkeyFree(pkey);
    }
  }

  private static byte[] xdhAgreement(String type, byte[] sk, byte[] peerPk) {
    checkXdhSupported(type);
    checkXdhLength(type, sk);
    checkXdhLength(type, peerPk);
    MemorySegment priv = OpenSsl.newRawPrivateKey(type, sk);
    MemorySegment pub = OpenSsl.newRawPublicKey(type, peerPk);
    try {
      if (OpenSsl.isNull(priv) || OpenSsl.isNull(pub)) {
        throw new IllegalArgumentException("invalid " + type + " key: " + OpenSsl.errors());
      }
      byte[] z = OpenSsl.derive(priv, pub);
      if (z == null) {
        throw new IllegalArgumentException(type + " failed: " + OpenSsl.errors());
      }
      return z;
    } finally {
      if (!OpenSsl.isNull(priv)) {
        OpenSsl.pkeyFree(priv);
      }
      if (!OpenSsl.isNull(pub)) {
        OpenSsl.pkeyFree(pub);
      }
    }
  }

  private static void checkXdhLength(String type, byte[] key) {
    if (key.length != ("X25519".equals(type) ? 32 : 56)) {
      throw new IllegalArgumentException("invalid key length");
    }
  }

  // ---------- ML-DSA, ML-KEM ----------

  @Override
  public KeyPair generateKeyPair(MldsaVariant variant) throws NoSuchAlgorithmException {
    return newKeyPairGenerator(mldsaName(variant)).generateKeyPair();
  }

  @Override
  public KeyPair generateKeyPair(MlkemVariant variant) throws NoSuchAlgorithmException {
    return newKeyPairGenerator(mlkemName(variant)).generateKeyPair();
  }

  @Override
  public SecretWithEncap encapsulateKey(MlkemVariant pqcVariant, byte[] publicKeyData) {
    String keyType = mlkemName(pqcVariant);
    MemorySegment pkey = OpenSsl.newRawPublicKey(keyType, publicKeyData);
    if (OpenSsl.isNull(pkey)) {
      throw new IllegalArgumentException("invalid " + keyType + " public key: "
          + OpenSsl.errors());
    }

    try {
      byte[][] wrappedAndSecret = OpenSsl.encapsulate(pkey);
      if (wrappedAndSecret == null) {
        throw new IllegalArgumentException("ML-KEM encapsulation failed: " + OpenSsl.errors());
      }
      return new SecretWithEncapImpl(wrappedAndSecret[1], wrappedAndSecret[0]);
    } finally {
      OpenSsl.pkeyFree(pkey);
    }
  }

  /**
   * Decapsulates with OpenSSL.
   * @param pqcVariant the ML-KEM variant.
   * @param privateKeyValue the 64-byte seed or the expanded private key.
   * @param encapsulatedKey the encapsulated key.
   * @return the shared secret.
   */
  @Override
  public byte[] decapsulateKey(
      MlkemVariant pqcVariant, byte[] privateKeyValue, byte[] encapsulatedKey) {
    String keyType = mlkemName(pqcVariant);
    MemorySegment pkey = (privateKeyValue.length == 64)
        ? OpenSsl.generateKey(keyType, new OsslParams().secretOctets("seed",
            privateKeyValue.clone()))
        : OpenSsl.newRawPrivateKey(keyType, privateKeyValue);
    if (OpenSsl.isNull(pkey)) {
      throw new IllegalArgumentException("invalid " + keyType + " private key: "
          + OpenSsl.errors());
    }

    try {
      byte[] secret = OpenSsl.decapsulate(pkey, encapsulatedKey);
      if (secret == null) {
        throw new IllegalArgumentException("ML-KEM decapsulation failed: " + OpenSsl.errors());
      }
      return secret;
    } finally {
      OpenSsl.pkeyFree(pkey);
    }
  }

  @Override
  public byte[] expandMldsaSeed(MldsaVariant variant, byte[] seed) {
    if (seed == null || seed.length != 32) {
      throw new IllegalArgumentException("seed must be 32 bytes");
    }
    return expandSeed(mldsaName(variant), seed);
  }

  @Override
  public byte[] expandMlkemSeed(MlkemVariant variant, byte[] seed) {
    if (seed == null || seed.length != 64) {
      throw new IllegalArgumentException("seed must be 64 bytes");
    }
    return expandSeed(mlkemName(variant), seed);
  }

  /**
   * Generates the key from the seed, and returns its expanded private key ("priv").
   */
  private static byte[] expandSeed(String keyType, byte[] seed) {
    MemorySegment pkey = OpenSsl.generateKey(keyType,
        new OsslParams().secretOctets("seed", seed.clone()));
    if (OpenSsl.isNull(pkey)) {
      throw new IllegalStateException(keyType + " seed expansion failed: " + OpenSsl.errors());
    }

    try {
      byte[] expanded = OpenSsl.pkeyOctetStringParam(pkey, "priv", MAX_EXPANDED_KEY_LEN);
      if (expanded == null) {
        throw new IllegalStateException(keyType + " seed expansion failed: "
            + OpenSsl.errors());
      }
      return expanded;
    } finally {
      OpenSsl.pkeyFree(pkey);
    }
  }

  private static String mldsaName(MldsaVariant variant) {
    if (variant == null) {
      throw new IllegalArgumentException("invalid variant null");
    }
    return switch (variant) {
      case ml_dsa_44 -> "ML-DSA-44";
      case ml_dsa_65 -> "ML-DSA-65";
      case ml_dsa_87 -> "ML-DSA-87";
    };
  }

  private static String mlkemName(MlkemVariant variant) {
    if (variant == null) {
      throw new IllegalArgumentException("invalid pqcVariant null");
    }
    return switch (variant) {
      case ml_kem_512 -> "ML-KEM-512";
      case ml_kem_768 -> "ML-KEM-768";
      case ml_kem_1024 -> "ML-KEM-1024";
    };
  }

}
