// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
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
import org.xipki.crypto.jdk.internal.Primitives;
import org.xipki.crypto.jdk.internal.XiPKIProvider;
import org.xipki.crypto.jdk.internal.digest.Shake;
import org.xipki.crypto.jdk.internal.ec.XiEcParameters;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Crypto backend using only the providers of the JDK (SunJCE, SunEC, SunRsaSign, SUN).
 * Requires JDK 25 or later.
 * <p>
 * Not supported, the callers provide a fallback or the feature is unavailable:
 * <ul>
 *   <li>ECDH with the curves brainpool and SM2.</li>
 * </ul>
 * <p>
 * Non-empty ML-DSA context strings ({@link #setContext(Signature, byte[])}) are supported with
 * the internals of the JDK, and require the JVM option
 * {@code --add-exports java.base/sun.security.provider=ALL-UNNAMED}.
 * <p>
 * The algorithms the JDK does not support are provided by an own instance of the XiPKI
 * provider (module xicrypto, not registered in {@link Security}), with the primitives of the
 * JDK providers: SM3, SM3withSM2, RSA-PSS and ECDSA with SHAKE, AES-GMAC, the XOF SHAKE and the
 * EC arithmetic ({@link #getByOID(Asn1Oid)}). For the EC curves the JDK lacks (brainpool, SM2),
 * the EC KeyFactory, KeyPairGenerator and the ECDSA signatures choose per curve
 * between SunEC and XiPKI (see {@link EcRouting}); these objects have no provider
 * ({@code getProvider()} returns null).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdk implements CryptoApi {

  /** SHA1WITHRSAANDMGF1, or the hash (SHA, SHA3-) and its size in group 1 and 2. */
  private static final Pattern RSA_PSS_NAME =
      Pattern.compile("SHA1WITHRSAANDMGF1|(SHA(?:3-)?)(224|256|384|512)WITHRSAANDMGF1");

  private static final Map<String, String> CIPHER_NAMES = new HashMap<>();

  private static final byte[] X25519_BASE = new byte[32];

  private static final byte[] X448_BASE = new byte[56];

  /** The random of this backend, see {@link #getSecureRandom()}. */
  static final SecureRandom DEFAULT_RANDOM = new SecureRandom();

  private static final Map<String, Provider> PROVIDERS = new ConcurrentHashMap<>();


  /**
   * The XiPKIProvider (module xicrypto) for the algorithms the JDK does not support, with the
   * primitives of the JDK providers. Not registered in {@link Security}.
   */
  private static final XiPKIProvider XIPKI = new XiPKIProvider(new Primitives(jdkProviders()));

  static {
    // The JDK maps the AES-CBC OIDs to NoPadding, PKCS#5 padding is expected.
    CIPHER_NAMES.put(NistOIDs.id_aes128_CBC.getId(), "AES/CBC/PKCS5Padding");
    CIPHER_NAMES.put(NistOIDs.id_aes192_CBC.getId(), "AES/CBC/PKCS5Padding");
    CIPHER_NAMES.put(NistOIDs.id_aes256_CBC.getId(), "AES/CBC/PKCS5Padding");
    CIPHER_NAMES.put(PkcsOIDs.des_EDE3_CBC.getId(),  "DESede/CBC/PKCS5Padding");

    X25519_BASE[0] = 9;
    X448_BASE[0] = 5;
  }

  @Override
  public String name() {
    return "jdk";
  }

  @Override
  public KeyAgreement newKeyAgreement(String algorithm) throws NoSuchAlgorithmException {
    return getInstance("KeyAgreement", algorithm, p -> KeyAgreement.getInstance(algorithm, p));
  }

  @Override
  public MessageDigest newMessageDigest(String algorithm) throws NoSuchAlgorithmException {
    return getInstance("MessageDigest", algorithm, p -> MessageDigest.getInstance(algorithm, p));
  }

  @Override
  public Mac newMac(String algorithm) throws NoSuchAlgorithmException {
    String name = normalizeMacName(algorithm);
    return getInstance("Mac", name, p -> Mac.getInstance(name, p));
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
    Matcher m = RSA_PSS_NAME.matcher(algorithm.toUpperCase(Locale.ROOT));
    if (m.matches()) {
      // e.g. SHA256WITHRSAANDMGF1: RSASSA-PSS with MGF1 of the same hash, salt length = hash
      // length, trailer field 1.
      String hash;
      int saltLen;
      if (m.group(1) == null) {
        hash = "SHA-1";
        saltLen = 20;
      } else {
        hash = m.group(1).equals("SHA") ? "SHA-" + m.group(2) : "SHA3-" + m.group(2);
        saltLen = Integer.parseInt(m.group(2)) / 8;
      }
      PSSParameterSpec spec = new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash),
          saltLen, PSSParameterSpec.TRAILER_FIELD_BC);
      Signature sig = getInstance("Signature", "RSASSA-PSS",
          p -> Signature.getInstance("RSASSA-PSS", p));
      try {
        sig.setParameter(spec);
        return sig;
      } catch (InvalidAlgorithmParameterException e) {
        throw new NoSuchAlgorithmException("unsupported " + algorithm, e);
      }
    }

    if (MldsaSignature.isMldsa(algorithm)) {
      // supports the context string, see setContext()
      return new MldsaSignature(algorithm,
          getInstance("Signature", algorithm, p -> Signature.getInstance(algorithm, p)));
    }

    if (EcRouting.isEnabled() && EcRouting.isJdkEcdsa(algorithm)) {
      // the curve decides at initSign/initVerify between SunEC and XiPKI
      return new EcRouting.SignatureImpl(algorithm);
    }

    return getInstance("Signature", algorithm, p -> Signature.getInstance(algorithm, p));
  }

  @Override
  public Cipher newCipher(String algorithm)
      throws NoSuchPaddingException, NoSuchAlgorithmException {
    String name = CIPHER_NAMES.get(algorithm);
    if (name == null) {
      name = algorithm;
      // RSA/NONE/... -> RSA/ECB/...
      String upper = algorithm.toUpperCase(Locale.ROOT);
      if (upper.startsWith("RSA/NONE/")) {
        name = "RSA/ECB/" + algorithm.substring("RSA/NONE/".length());
      }
    }
    String transformation = name;
    return getInstance("Cipher", transformation, p -> Cipher.getInstance(transformation, p));
  }

  @Override
  public KeyFactory newKeyFactory(String algorithm) throws NoSuchAlgorithmException {
    if (EcRouting.isEnabled() && EcRouting.isEcKeyAlgorithm(algorithm)) {
      return new EcRouting.KeyFactoryImpl();
    }
    return getInstance("KeyFactory", algorithm, p -> KeyFactory.getInstance(algorithm, p));
  }

  @Override
  public KeyPairGenerator newKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
    if (EcRouting.isEnabled() && EcRouting.isEcKeyAlgorithm(algorithm)) {
      return new EcRouting.KeyPairGeneratorImpl();
    }
    return getInstance("KeyPairGenerator", algorithm,
        p -> KeyPairGenerator.getInstance(algorithm, p));
  }

  @Override
  public KeyGenerator newKeyGenerator(String algorithm) throws NoSuchAlgorithmException {
    return getInstance("KeyGenerator", algorithm, p -> KeyGenerator.getInstance(algorithm, p));
  }

  @Override
  public SecretKeyFactory newSecretKeyFactory(String algorithm) throws NoSuchAlgorithmException {
    return getInstance("SecretKeyFactory", algorithm,
        p -> SecretKeyFactory.getInstance(algorithm, p));
  }

  @Override
  public PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    Asn1Oid oid = publicKeyInfo.getAlgorithm().getAlgorithm();
    try {
      return newKeyFactory(oid.getId())
          .generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidKeySpecException("unsupported key algorithm " + oid.getId()
          + ": " + e.getMessage(), e);
    }
  }

  @Override
  public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws InvalidKeySpecException {
    Asn1Oid oid = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
    byte[] encoded = privateKeyInfo.getEncoded();
    try {
      return newKeyFactory(oid.getId()).generatePrivate(new PKCS8EncodedKeySpec(encoded));
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidKeySpecException("unsupported key algorithm " + oid.getId()
          + ": " + e.getMessage(), e);
    } finally {
      XiArrays.clear(encoded);
    }
  }

  /**
   * The public API of the JDK does not support the context string of ML-DSA. For the ML-DSA
   * signatures of {@link #newSignature(String)}, a non-empty context is supported with the
   * internals of the JDK, which requires the JVM option
   * {@code --add-exports java.base/sun.security.provider=ALL-UNNAMED}.
   */
  @Override
  public void setContext(Signature sig, byte[] context) throws InvalidAlgorithmParameterException {
    if (sig instanceof MldsaSignature) {
      ((MldsaSignature) sig).setContext(context);
    } else if (context != null && context.length > 0) {
      throw new InvalidAlgorithmParameterException(
          "signature context is not supported for " + sig.getAlgorithm());
    }
  }

  /**
   * The JDK has no public XOF API.
   * @throws UnsupportedOperationException always.
   */
  @Override
  public byte[] xof(String algorithm, byte[] data, int length) {
    String upper = algorithm.toUpperCase(Locale.ROOT);
    if ("SHAKE128".equals(upper) || "SHAKE128-256".equals(upper)) {
      return Shake.shake(128, data, length);
    } else if ("SHAKE256".equals(upper) || "SHAKE256-512".equals(upper)) {
      return Shake.shake(256, data, length);
    }
    throw new UnsupportedOperationException("unsupported XOF " + algorithm);
  }

  /**
   * HKDF-SHA256 (RFC 5869) on the HmacSHA256 of the JDK.
   */
  @Override
  public byte[] hkdfSha256Derive(byte[] ikm, byte[] salt, byte[] info, int outputKeyLen) {
    final int hashLen = 32;
    if (outputKeyLen < 0 || outputKeyLen > 255 * hashLen) {
      throw new IllegalArgumentException("invalid outputKeyLen " + outputKeyLen);
    }

    try {
      Mac mac = newMac("HmacSHA256");
      // extract: an absent salt is a string of HashLen zeros (RFC 5869, section 2.2)
      byte[] saltValue = (salt == null || salt.length == 0) ? new byte[hashLen] : salt;
      mac.init(new SecretKeySpec(saltValue, "HmacSHA256"));
      byte[] prk = mac.doFinal(ikm == null ? new byte[0] : ikm);

      // expand
      byte[] okm = new byte[outputKeyLen];
      byte[] t = new byte[0];
      try {
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        for (int i = 1, off = 0; off < outputKeyLen; i++) {
          mac.update(t);
          if (info != null) {
            mac.update(info);
          }
          mac.update((byte) i);
          XiArrays.clear(t);
          t = mac.doFinal();
          int n = Math.min(hashLen, outputKeyLen - off);
          System.arraycopy(t, 0, okm, off, n);
          off += n;
        }
      } finally {
        XiArrays.clear(prk);
        XiArrays.clear(t);
      }
      return okm;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HKDF-SHA256 failed: " + e.getMessage(), e);
    }
  }

  @Override
  public SecureRandom getSecureRandom() {
    return DEFAULT_RANDOM;
  }

  /**
   * The JDK has no public EC point arithmetic.
   * @return null always.
   */
  @Override
  public X9ECParameters getByOID(Asn1Oid oid) {
    return XiEcParameters.of(oid);
  }

  @Override
  public byte[] generateX25519PrivateKey() {
    byte[] k = new byte[32];
    DEFAULT_RANDOM.nextBytes(k);
    // clamping, as in RFC 7748, section 5
    k[0] &= (byte) 0xF8;
    k[31] &= 0x7F;
    k[31] |= 0x40;
    return k;
  }

  @Override
  public byte[] generateX25519PublicKey(byte[] sk) {
    return xdh(NamedParameterSpec.X25519, sk, X25519_BASE);
  }

  @Override
  public byte[] calculateX25519Agreement(byte[] sk, byte[] peerPk) {
    return xdh(NamedParameterSpec.X25519, sk, peerPk);
  }

  @Override
  public byte[] generateX448PrivateKey() {
    byte[] k = new byte[56];
    DEFAULT_RANDOM.nextBytes(k);
    // clamping, as in RFC 7748, section 5
    k[0] &= (byte) 0xFC;
    k[55] |= (byte) 0x80;
    return k;
  }

  @Override
  public byte[] generateX448PublicKey(byte[] sk) {
    return xdh(NamedParameterSpec.X448, sk, X448_BASE);
  }

  @Override
  public byte[] calculateX448Agreement(byte[] sk, byte[] peerPk) {
    return xdh(NamedParameterSpec.X448, sk, peerPk);
  }

  private byte[] xdh(NamedParameterSpec curve, byte[] sk, byte[] peerU) {
    int len = curve == NamedParameterSpec.X25519 ? 32 : 56;
    if (sk.length != len || peerU.length != len) {
      throw new IllegalArgumentException("invalid key length");
    }

    // u-coordinate: little-endian; for X25519 the most significant bit is masked
    byte[] be = new byte[len];
    for (int i = 0; i < len; i++) {
      be[i] = peerU[len - 1 - i];
    }
    if (len == 32) {
      be[0] &= 0x7F;
    }

    try {
      KeyFactory kf = newKeyFactory("XDH");
      PrivateKey privateKey = kf.generatePrivate(new XECPrivateKeySpec(curve, sk));
      PublicKey publicKey = kf.generatePublic(new XECPublicKeySpec(curve, new BigInteger(1, be)));
      KeyAgreement ka = newKeyAgreement("XDH");
      ka.init(privateKey);
      ka.doPhase(publicKey, true);
      return ka.generateSecret();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("XDH failed: " + e.getMessage(), e);
    }
  }

  @Override
  public KeyPair generateKeyPair(MldsaVariant variant) throws NoSuchAlgorithmException {
    NamedParameterSpec spec = variant == MldsaVariant.ml_dsa_44 ? NamedParameterSpec.ML_DSA_44
        : variant == MldsaVariant.ml_dsa_65 ? NamedParameterSpec.ML_DSA_65
        : NamedParameterSpec.ML_DSA_87;
    return generateKeyPair("ML-DSA", spec);
  }

  @Override
  public KeyPair generateKeyPair(MlkemVariant variant) throws NoSuchAlgorithmException {
    NamedParameterSpec spec = variant == MlkemVariant.ml_kem_512 ? NamedParameterSpec.ML_KEM_512
        : variant == MlkemVariant.ml_kem_768 ? NamedParameterSpec.ML_KEM_768
        : NamedParameterSpec.ML_KEM_1024;
    return generateKeyPair("ML-KEM", spec);
  }

  private static KeyPair generateKeyPair(String algorithm, NamedParameterSpec spec)
      throws NoSuchAlgorithmException {
    KeyPairGenerator kpGen = getInstance("KeyPairGenerator", algorithm,
        p -> KeyPairGenerator.getInstance(algorithm, p));
    try {
      kpGen.initialize(spec);
    } catch (InvalidAlgorithmParameterException e) {
      throw new NoSuchAlgorithmException(e.getMessage(), e);
    }
    return kpGen.generateKeyPair();
  }

  @Override
  public SecretWithEncap encapsulateKey(MlkemVariant pqcVariant, byte[] publicKeyData) {
    AlgorithmIdentifier algId = mlkemAlgId(pqcVariant);
    try {
      PublicKey publicKey = newKeyFactory("ML-KEM").generatePublic(
          new X509EncodedKeySpec(new SubjectPublicKeyInfo(algId, publicKeyData).getEncoded()));
      KEM.Encapsulated encapsulated = newKem().newEncapsulator(publicKey).encapsulate();
      return new SecretWithEncapImpl(encapsulated.key().getEncoded(),
          encapsulated.encapsulation());
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("ML-KEM encapsulation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Decapsulates the key.
   * @param pqcVariant the ML-KEM variant.
   * @param privateKeyValue the 64-byte seed or the expanded private key.
   * @param encapsulatedKey the encapsulated key.
   * @return the shared secret.
   */
  @Override
  public byte[] decapsulateKey(
      MlkemVariant pqcVariant, byte[] privateKeyValue, byte[] encapsulatedKey) {
    AlgorithmIdentifier algId = mlkemAlgId(pqcVariant);
    MlkemPrivateKey mlkemSk = (privateKeyValue.length == 64)
        ? new MlkemPrivateKey(privateKeyValue, null)
        : new MlkemPrivateKey(null, privateKeyValue);

    byte[] encoded = new PrivateKeyInfo(algId, mlkemSk.getEncoded()).getEncoded();
    try {
      PrivateKey privateKey = newKeyFactory("ML-KEM")
          .generatePrivate(new PKCS8EncodedKeySpec(encoded));
      return newKem().newDecapsulator(privateKey).decapsulate(encapsulatedKey).getEncoded();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("ML-KEM decapsulation failed: " + e.getMessage(), e);
    } finally {
      XiArrays.clear(encoded);
    }
  }

  /**
   * Uses the internals of the JDK, requires the JVM option
   * {@code --add-exports java.base/sun.security.provider=ALL-UNNAMED}.
   */
  @Override
  public byte[] expandMldsaSeed(MldsaVariant variant, byte[] seed) {
    String reason = JdkInternals.Mldsa.seedUnavailableReason();
    if (reason != null) {
      throw new UnsupportedOperationException(reason);
    }
    if (seed == null || seed.length != 32) {
      throw new IllegalArgumentException("seed must be 32 bytes");
    }

    String paramSet = variant == MldsaVariant.ml_dsa_44 ? "ML-DSA-44"
        : variant == MldsaVariant.ml_dsa_65 ? "ML-DSA-65" : "ML-DSA-87";
    return JdkInternals.Mldsa.seedToExpanded(paramSet, seed);
  }

  /**
   * Uses the internals of the JDK, requires the JVM option
   * {@code --add-exports java.base/com.sun.crypto.provider=ALL-UNNAMED}.
   */
  @Override
  public byte[] expandMlkemSeed(MlkemVariant variant, byte[] seed) {
    if (seed == null || seed.length != 64) {
      throw new IllegalArgumentException("seed must be 64 bytes");
    }

    String paramSet = variant == MlkemVariant.ml_kem_512 ? "ML-KEM-512"
        : variant == MlkemVariant.ml_kem_768 ? "ML-KEM-768" : "ML-KEM-1024";
    return JdkInternals.Mlkem.seedToExpanded(paramSet, seed);
  }

  private static AlgorithmIdentifier mlkemAlgId(MlkemVariant variant) {
    Asn1Oid oid = variant == MlkemVariant.ml_kem_512 ? NistOIDs.id_ml_kem_512
        : variant == MlkemVariant.ml_kem_768 ? NistOIDs.id_ml_kem_768
        : variant == MlkemVariant.ml_kem_1024 ? NistOIDs.id_ml_kem_1024
        : null;
    if (oid == null) {
      throw new IllegalArgumentException("invalid pqcVariant " + variant);
    }
    return new AlgorithmIdentifier(oid);
  }

  /**
   * Returns whether the registered provider may be used: only the providers of the JDK. Other
   * providers, such as BouncyCastle if registered by the application, are not used.
   */
  static boolean isAllowed(Provider provider) {
    String module = provider.getClass().getModule().getName();
    return module != null && (module.startsWith("java.") || module.startsWith("jdk."));
  }

  /**
   * Returns the XiPKIProvider instance of this backend.
   * @return the XiPKIProvider instance.
   */
  static XiPKIProvider xipki() {
    return XIPKI;
  }

  private static Provider[] jdkProviders() {
    List<Provider> list = new ArrayList<>();
    for (Provider p : Security.getProviders()) {
      if (isAllowed(p)) {
        list.add(p);
      }
    }
    return list.toArray(new Provider[0]);
  }

  @FunctionalInterface
  private interface Factory<T> {
    T get(Provider provider) throws GeneralSecurityException;
  }

  /**
   * Returns the instance from the first allowed provider supporting it. The provider is
   * cached per type and algorithm.
   */
  private static <T> T getInstance(String type, String algorithm, Factory<T> factory)
      throws NoSuchAlgorithmException {
    String key = type + "/" + algorithm;
    Provider cached = PROVIDERS.get(key);
    if (cached != null) {
      try {
        return factory.get(cached);
      } catch (GeneralSecurityException e) {
        PROVIDERS.remove(key);
      }
    }

    GeneralSecurityException cause = null;
    for (Provider provider : Security.getProviders()) {
      if (!isAllowed(provider)) {
        continue;
      }

      try {
        T instance = factory.get(provider);
        PROVIDERS.put(key, provider);
        return instance;
      } catch (GeneralSecurityException e) {
        if (cause == null) {
          cause = e;
        }
      }
    }

    // the algorithms the JDK does not support
    try {
      T instance = factory.get(XIPKI);
      PROVIDERS.put(key, XIPKI);
      return instance;
    } catch (GeneralSecurityException e) {
      if (cause == null) {
        cause = e;
      }
    }

    throw new NoSuchAlgorithmException(type + " " + algorithm + " not available", cause);
  }

  private static KEM newKem() throws NoSuchAlgorithmException {
    return getInstance("KEM", "ML-KEM", p -> KEM.getInstance("ML-KEM", p));
  }

}
