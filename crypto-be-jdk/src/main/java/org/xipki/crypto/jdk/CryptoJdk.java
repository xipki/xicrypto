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
import org.xipki.codec.util.Arrays;
import org.xipki.crypto.api.AlgorithmNames;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.X9ECParameters;
import org.xipki.crypto.extra.Primitives;
import org.xipki.crypto.extra.Shake;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.math.EcCurve;
import org.xipki.crypto.extra.ec.math.WeierstrassCurve;
import org.xipki.crypto.extra.ec.math.WeierstrassPoint;

import javax.crypto.Cipher;
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
import java.security.KeyStore;
import java.security.KeyStoreException;
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
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Crypto backend using only the providers of the JDK (SunJCE, SunEC, SunRsaSign, SUN).
 * Runs on JDK 11 or later; ML-DSA and ML-KEM require JDK 25+, EdDSA JDK 15+, HmacSHA3 and SHA3
 * with RSA JDK 16+ ({@link JdkCompat}).
 * <p>
 * Not supported, the callers provide a fallback or the feature is unavailable:
 * <ul>
 *   <li>ECDH with the curves brainpool, SM2 and FRP256v1.</li>
 * </ul>
 * <p>
 * Non-empty ML-DSA context strings ({@link #setContext(Signature, byte[])}) are supported with
 * the internals of the JDK, and require the JVM option
 * {@code --add-exports java.base/sun.security.provider=ALL-UNNAMED}.
 * <p>
 * The algorithms the JDK does not support are provided by an own instance of the XiPKI
 * provider (module xicrypto, not registered in {@link Security}), with the primitives of the
 * JDK providers: SM3, SM3withSM2, RSA-PSS and ECDSA with SHAKE, AES-GMAC, the XOF SHAKE and the
 * EC arithmetic ({@link #getByOID(Asn1Oid)}). For the EC curves the JDK lacks (brainpool, SM2,
 * FRP256v1), the EC KeyFactory, KeyPairGenerator and the ECDSA signatures choose per curve
 * between SunEC and XiPKI (see {@link EcRouting}); these objects have no provider
 * ({@code getProvider()} returns null).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdk implements CryptoApi {

  private static final Pattern RSA_PSS_NAME =
      Pattern.compile("(SHA(?:3-)?)(224|256|384|512)WITHRSAANDMGF1");

  private static final Map<String, String> CIPHER_NAMES = new HashMap<>();

  private static final byte[] X25519_BASE = new byte[32];

  private static final byte[] X448_BASE = new byte[56];

  private static final SecureRandom DEFAULT_RANDOM = new SecureRandom();

  private static final Map<String, Provider> PROVIDERS = new ConcurrentHashMap<>();

  private static final Map<Asn1Oid, X9ECParameters> XI_CURVES = new ConcurrentHashMap<>();

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
  public KeyStore newKeyStore(String algorithm) throws KeyStoreException {
    try {
      return getInstance("KeyStore", algorithm, p -> KeyStore.getInstance(algorithm, p));
    } catch (NoSuchAlgorithmException e) {
      throw new KeyStoreException(e.getMessage(), e);
    }
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
      String hash = m.group(1).equals("SHA") ? "SHA-" + m.group(2) : "SHA3-" + m.group(2);
      int saltLen = Integer.parseInt(m.group(2)) / 8;
      PSSParameterSpec spec = new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash),
          saltLen, PSSParameterSpec.TRAILER_FIELD_BC);
      Signature sig = getInstance("Signature", "RSASSA-PSS",
          p -> Signature.getInstance("RSASSA-PSS", p));
      // JDK 11 to 15: RSASSA-PSS of the JDK accepts the SHA3 parameters at setParameter, but
      // fails at initSign / initVerify. SHA3 for RSASSA-PSS came together with SHA3-*withRSA
      // (SunRsaSign, JDK 16): without the latter, the RSASSA-PSS of xicrypto is used.
      boolean jdkSupportsHash = !hash.startsWith("SHA3-")
          || sig.getProvider().getService("Signature", hash + "withRSA") != null;
      try {
        if (!jdkSupportsHash) {
          throw new InvalidAlgorithmParameterException("RSASSA-PSS of "
              + sig.getProvider().getName() + " does not support " + hash);
        }
        sig.setParameter(spec);
        return sig;
      } catch (InvalidAlgorithmParameterException e) {
        // RSASSA-PSS of the JDK without the hash: use the one of xicrypto
        try {
          Signature xiSig = Signature.getInstance("RSASSA-PSS", XIPKI);
          xiSig.setParameter(spec);
          return xiSig;
        } catch (InvalidAlgorithmParameterException e2) {
          e.addSuppressed(e2);
          throw new NoSuchAlgorithmException("unsupported " + algorithm, e);
        }
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
    KeyFactory kf = getInstance("KeyFactory", algorithm,
        p -> KeyFactory.getInstance(algorithm, p));
    // JDK 11: the encoding of XDH keys is not that of RFC 8410 (JDK-8213363)
    return Jdk11Xdh.isNeeded(algorithm) ? new Jdk11Xdh.Rfc8410KeyFactory(kf) : kf;
  }

  @Override
  public KeyPairGenerator newKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException {
    if (EcRouting.isEnabled() && EcRouting.isEcKeyAlgorithm(algorithm)) {
      return new EcRouting.KeyPairGeneratorImpl();
    }
    KeyPairGenerator kpGen = getInstance("KeyPairGenerator", algorithm,
        p -> KeyPairGenerator.getInstance(algorithm, p));
    // JDK 11: the encoding of XDH keys is not that of RFC 8410 (JDK-8213363)
    return Jdk11Xdh.isNeeded(algorithm) ? new Jdk11Xdh.Rfc8410KeyPairGenerator(kpGen) : kpGen;
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
    if (isEdecKey(oid) && (privateKeyInfo.version() != 0 || privateKeyInfo.hasPublicKey())) {
      // OneAsymmetricKey (RFC 5958, version 1, with the public key), as written e.g. by
      // BouncyCastle: JDK 11 to 15 accept only version 0. The public key is derived from the
      // private key anyway.
      privateKeyInfo = new PrivateKeyInfo(privateKeyInfo.getPrivateKeyAlgorithm(),
          privateKeyInfo.privateKey());
    }

    byte[] encoded = privateKeyInfo.getEncoded();
    try {
      return newKeyFactory(oid.getId()).generatePrivate(new PKCS8EncodedKeySpec(encoded));
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidKeySpecException("unsupported key algorithm " + oid.getId()
          + ": " + e.getMessage(), e);
    } finally {
      Arrays.clear(encoded);
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
   * HKDF-SHA256 (RFC 5869) on the HmacSHA256 of the JDK. The KDF API of the JDK
   * ({@code javax.crypto.KDF}) is not used, because it requires JDK 25 at compile time.
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
          Arrays.clear(t);
          t = mac.doFinal();
          int n = Math.min(hashLen, outputKeyLen - off);
          System.arraycopy(t, 0, okm, off, n);
          off += n;
        }
      } finally {
        Arrays.clear(prk);
        Arrays.clear(t);
      }
      return okm;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HKDF-SHA256 failed: " + e.getMessage(), e);
    }
  }

  @Override
  public SecureRandom getSecureRandom(SecureRandom random) {
    return random != null ? random : DEFAULT_RANDOM;
  }

  /**
   * The JDK has no public EC point arithmetic.
   * @return null always.
   */
  @Override
  public X9ECParameters getByOID(Asn1Oid oid) {
    EcCurve curve = EcCurve.ofOid(oid);
    return (curve == null) ? null : XI_CURVES.computeIfAbsent(oid, k -> new XiEcParameters(curve));
  }

  @Override
  public byte[] generateX25519PrivateKey(SecureRandom rnd) {
    byte[] k = new byte[32];
    getSecureRandom(rnd).nextBytes(k);
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
  public byte[] generateX448PrivateKey(SecureRandom rnd) {
    byte[] k = new byte[56];
    getSecureRandom(rnd).nextBytes(k);
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
  public KeyPair generateKeyPair(MldsaVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException {
    // the constants NamedParameterSpec.ML_DSA_* require JDK 24 at compile time
    NamedParameterSpec spec = new NamedParameterSpec(variant == MldsaVariant.ml_dsa_44
        ? "ML-DSA-44" : variant == MldsaVariant.ml_dsa_65 ? "ML-DSA-65" : "ML-DSA-87");
    return generateKeyPair("ML-DSA", spec, random);
  }

  @Override
  public KeyPair generateKeyPair(MlkemVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException {
    // the constants NamedParameterSpec.ML_KEM_* require JDK 24 at compile time
    NamedParameterSpec spec = new NamedParameterSpec(variant == MlkemVariant.ml_kem_512
        ? "ML-KEM-512" : variant == MlkemVariant.ml_kem_768 ? "ML-KEM-768" : "ML-KEM-1024");
    return generateKeyPair("ML-KEM", spec, random);
  }

  private static KeyPair generateKeyPair(
      String algorithm, NamedParameterSpec spec, SecureRandom random)
      throws NoSuchAlgorithmException {
    KeyPairGenerator kpGen = getInstance("KeyPairGenerator", algorithm,
        p -> KeyPairGenerator.getInstance(algorithm, p));
    try {
      if (random == null) {
        kpGen.initialize(spec);
      } else {
        kpGen.initialize(spec, random);
      }
    } catch (InvalidAlgorithmParameterException e) {
      throw new NoSuchAlgorithmException(e.getMessage(), e);
    }
    return kpGen.generateKeyPair();
  }

  @Override
  public SecretWithEncap encapsulateKey(
      MlkemVariant pqcVariant, byte[] publicKeyData, SecureRandom rnd) {
    AlgorithmIdentifier algId = mlkemAlgId(pqcVariant);
    try {
      PublicKey publicKey = newKeyFactory("ML-KEM").generatePublic(
          new X509EncodedKeySpec(new SubjectPublicKeyInfo(algId, publicKeyData).getEncoded()));
      return JdkCompat.Kem.encapsulate(newKem(), publicKey, rnd);
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
      return JdkCompat.Kem.decapsulate(newKem(), privateKey, encapsulatedKey);
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("ML-KEM decapsulation failed: " + e.getMessage(), e);
    } finally {
      Arrays.clear(encoded);
    }
  }

  /**
   * Uses the internals of the JDK, requires JDK 25+ and the JVM option
   * {@code --add-exports java.base/sun.security.provider=ALL-UNNAMED}.
   */
  @Override
  public byte[] expandMldsaSeed(MldsaVariant variant, byte[] seed) {
    if (!JdkCompat.isPqcAvailable()) {
      throw new UnsupportedOperationException(JdkCompat.pqcMessage("ML-DSA seed expansion"));
    }
    String reason = JdkInternals.Mldsa.unavailableReason();
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
   * Uses the internals of the JDK, requires JDK 25+ and the JVM option
   * {@code --add-exports java.base/com.sun.crypto.provider=ALL-UNNAMED}.
   */
  @Override
  public byte[] expandMlkemSeed(MlkemVariant variant, byte[] seed) {
    if (!JdkCompat.isPqcAvailable()) {
      throw new UnsupportedOperationException(JdkCompat.pqcMessage("ML-KEM seed expansion"));
    }
    if (seed == null || seed.length != 64) {
      throw new IllegalArgumentException("seed must be 64 bytes");
    }

    String paramSet = variant == MlkemVariant.ml_kem_512 ? "ML-KEM-512"
        : variant == MlkemVariant.ml_kem_768 ? "ML-KEM-768" : "ML-KEM-1024";
    return JdkInternals.Mlkem.seedToExpanded(paramSet, seed);
  }

  /**
   * Returns whether the key is an X25519, X448, Ed25519 or Ed448 key (RFC 8410).
   */
  private static boolean isEdecKey(Asn1Oid oid) {
    return AlgorithmOIDs.id_X25519.equals(oid) || AlgorithmOIDs.id_X448.equals(oid)
        || AlgorithmOIDs.id_Ed25519.equals(oid) || AlgorithmOIDs.id_Ed448.equals(oid);
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
    java.util.List<Provider> list = new java.util.ArrayList<>();
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
    // ML-DSA and ML-KEM require JDK 25+: fail with a clear message
    JdkCompat.checkPqc(type, algorithm);

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

    throw new NoSuchAlgorithmException(type + " " + algorithm + " not available"
        + JdkCompat.hint(type, algorithm, JdkCompat.FEATURE), cause);
  }

  /**
   * Returns a {@code javax.crypto.KEM} instance for ML-KEM, see {@link JdkCompat.Kem}.
   */
  private static Object newKem() throws NoSuchAlgorithmException {
    return getInstance("KEM", "ML-KEM", p -> JdkCompat.Kem.getInstance("ML-KEM", p));
  }

  /**
   * Adapter of the curve arithmetic of xicrypto to {@link X9ECParameters} and
   * {@link ECCurve}: the JDK has no public EC arithmetic.
   *
   * @author Lijun Liao (xipki)
   */
  private static final class XiEcParameters implements X9ECParameters, ECCurve {

    private final EcCurve curve;

    private final WeierstrassCurve wc;

    XiEcParameters(EcCurve curve) {
      this.curve = curve;
      this.wc = curve.weierstrassCurve();
    }

    @Override
    public ECCurve getCurve() {
      return this;
    }

    @Override
    public ECPoint getG() {
      return new Point(wc.getG());
    }

    @Override
    public BigInteger getOrder() {
      return wc.getOrder();
    }

    @Override
    public int getFieldSize() {
      return wc.getFieldSize();
    }

    @Override
    public ECPoint decodePoint(byte[] bytes) {
      return new Point(wc.decodePoint(bytes));
    }

    /**
     * Variable-time u1·G + u2·Q of xicrypto.
     */
    @Override
    public ECPoint sumOfTwoMultiplies(BigInteger u1, BigInteger u2, ECPoint q) {
      ECPoint nq = q.normalize();
      java.security.spec.ECPoint r = curve.sumOfTwoMultiplies(u1, u2,
          new java.security.spec.ECPoint(nq.getXCoordBigInt(), nq.getYCoordBigInt()));
      if (java.security.spec.ECPoint.POINT_INFINITY.equals(r)) {
        return new Point(wc.infinity());
      }
      return decodePoint(curve.encodePoint(r));
    }

    private final class Point implements ECPoint {

      private final WeierstrassPoint p;

      Point(WeierstrassPoint p) {
        this.p = p;
      }

      @Override
      public ECPoint multiply(BigInteger k) {
        return new Point(p.multiply(k));
      }

      @Override
      public ECPoint add(ECPoint other) {
        if (!(other instanceof Point)) {
          throw new IllegalArgumentException("point is not on the same curve");
        }
        return new Point(p.add(((Point) other).p));
      }

      @Override
      public ECPoint normalize() {
        return new Point(p.normalize());
      }

      @Override
      public BigInteger getXCoordBigInt() {
        return p.getXCoordBigInt();
      }

      @Override
      public BigInteger getYCoordBigInt() {
        return p.getYCoordBigInt();
      }

      @Override
      public byte[] getEncoded(boolean compressed) {
        return p.getEncoded(compressed);
      }

    }

  }

}
