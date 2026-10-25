// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.bcfips;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsOutputXOFCalculator;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsXOFOperatorFactory;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.util.Properties;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.X9ECParameters;
import org.xipki.crypto.extra.Primitives;
import org.xipki.crypto.extra.XiPKIProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.Objects;

/**
 * @author Lijun Liao (xipki)
 */
public class CryptoBcFips implements CryptoApi {

  private static final String PROVIDER = BouncyCastleFipsProvider.PROVIDER_NAME;

  private static final String PQC_PROVIDER = BouncyCastlePQCProvider.PROVIDER_NAME;

  private static final String PROP_RSA_ALLOW_MULTI_USE = "org.bouncycastle.rsa.allow_multi_use";

  private static final FipsXOFOperatorFactory<FipsSHS.Parameters> xofFactory
      = new FipsSHS.XOFOperatorFactory<>();

  /**
   * XiPKIProvider (module xicrypto) for the algorithms BC-FIPS does not support (SM3,
   * SM3withSM2, RSA-PSS and ECDSA with SHAKE), with the primitives of BC-FIPS. Not registered in
   * {@link Security}.
   */
  private final XiPKIProvider xipki;

  public CryptoBcFips() {
    init();
    this.xipki = new BcFipsXiPKIProvider(Security.getProvider(PROVIDER));
  }

  @Override
  public String name() {
    return "bcfips";
  }

  private static boolean isPqcAlgo(String algorithm) {
    if (algorithm.isEmpty()) {
      return false;
    }

    String c14Algorithm = algorithm.toUpperCase(Locale.ROOT).replace("-", "");
    if (c14Algorithm.contains("MLDSA") || c14Algorithm.contains("FNDSA")
        || c14Algorithm.contains("MLKEM") || c14Algorithm.contains("LMS")
        || c14Algorithm.contains("DILITHIUM") || c14Algorithm.contains("KYBER")
        || c14Algorithm.contains("SLHDSA") || c14Algorithm.contains("SPHINCS")
        || OIDs.isPqcAlgorithm(algorithm)) {
      return true;
    }

    char c = algorithm.charAt(0);
    if (c >= '0' && c <= '9') {
      Asn1Oid oid;
      try {
        oid = new Asn1Oid(algorithm);
      } catch (Exception e) {
        return false;
      }
      return OIDs.isPqcAlgorithm(oid);
    }

    // not sure
    return false;
  }

  private void init() {
    // BC-FIPS forbids by default to use an RSA key for both signing and encryption. SCEP
    // (RFC 8894) requires it: the RA/CA key decrypts the request and signs the response, and the
    // client key signs the request and decrypts the response. An explicit configuration (security
    // or system property) of the user is kept.
    if (Properties.getPropertyValue(PROP_RSA_ALLOW_MULTI_USE) == null) {
      System.setProperty(PROP_RSA_ALLOW_MULTI_USE, "true");
    }

    if (Security.getProvider(PROVIDER) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    if (Security.getProvider(PQC_PROVIDER) == null) {
      Security.addProvider(new BouncyCastlePQCProvider());
    }

    SecureRandom rnd = null;
    try {
      rnd = CryptoServicesRegistrar.getSecureRandom();
    } catch (RuntimeException e) {
    }

    if (rnd == null) {
      CryptoServicesRegistrar.setSecureRandom(newDefaultSecureRandom());
    }
  }

  /**
   * Returns the default SecureRandom of BC-FIPS: an approved DRBG (Hash_DRBG with SHA-512,
   * 256-bit security strength), seeded from the platform SecureRandom. Approved in both modes,
   * so it may also be set in the approved-only mode of BC-FIPS, where a plain SecureRandom is
   * rejected.
   */
  private static SecureRandom newDefaultSecureRandom() {
    SecureRandom seedSource = new SecureRandom();
    byte[] nonce = new byte[16];
    seedSource.nextBytes(nonce);
    return FipsDRBG.SHA512.fromEntropySource(new BasicEntropySourceProvider(seedSource, true))
        .setSecurityStrength(256).setEntropyBitsRequired(256)
        .build(nonce, false);
  }

  @Override
  public KeyStore newKeyStore(String algorithm) throws KeyStoreException, NoSuchProviderException {
    try {
      return KeyStore.getInstance(algorithm, PROVIDER);
    } catch (KeyStoreException e) {
      return KeyStore.getInstance(algorithm);
    }
  }

  @Override
  public KeyAgreement newKeyAgreement(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyAgreement.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      if (isPqcAlgo(algorithm)) {
        try {
          return KeyAgreement.getInstance(algorithm, PQC_PROVIDER);
        } catch (NoSuchAlgorithmException e2) {
          return KeyAgreement.getInstance(algorithm);
        }
      } else {
        return KeyAgreement.getInstance(algorithm);
      }
    }
  }

  @Override
  public MessageDigest newMessageDigest(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return MessageDigest.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      try {
        return MessageDigest.getInstance(algorithm, xipki);
      } catch (NoSuchAlgorithmException e2) {
        return MessageDigest.getInstance(algorithm);
      }
    }
  }

  @Override
  public Mac newMac(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return Mac.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return Mac.getInstance(algorithm);
    }
  }

  @Override
  public Signature newSignature(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return Signature.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      if (isPqcAlgo(algorithm)) {
        try {
          return Signature.getInstance(algorithm, PQC_PROVIDER);
        } catch (NoSuchAlgorithmException e2) {
          return Signature.getInstance(algorithm);
        }
      }

      try {
        return Signature.getInstance(algorithm, xipki);
      } catch (NoSuchAlgorithmException e2) {
        return Signature.getInstance(algorithm);
      }
    }
  }

  @Override
  public Cipher newCipher(String algorithm) throws NoSuchPaddingException,
      NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return Cipher.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      if (isPqcAlgo(algorithm)) {
        try {
          return Cipher.getInstance(algorithm, PQC_PROVIDER);
        } catch (NoSuchAlgorithmException e2) {
          return Cipher.getInstance(algorithm);
        }
      } else {
        return Cipher.getInstance(algorithm);
      }
    }
  }

  @Override
  public KeyFactory newKeyFactory(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyFactory.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      if (isPqcAlgo(algorithm)) {
        try {
          return KeyFactory.getInstance(algorithm, PQC_PROVIDER);
        } catch (NoSuchAlgorithmException e2) {
          return KeyFactory.getInstance(algorithm);
        }
      } else {
        return KeyFactory.getInstance(algorithm);
      }
    }
  }

  @Override
  public KeyPairGenerator newKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyPairGenerator.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      if (isPqcAlgo(algorithm)) {
        try {
          return KeyPairGenerator.getInstance(algorithm, PQC_PROVIDER);
        } catch (NoSuchAlgorithmException e2) {
          return KeyPairGenerator.getInstance(algorithm);
        }
      } else {
        return KeyPairGenerator.getInstance(algorithm);
      }
    }
  }

  @Override
  public KeyGenerator newKeyGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyGenerator.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return KeyGenerator.getInstance(algorithm);
    }
  }

  @Override
  public SecretKeyFactory newSecretKeyFactory(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return SecretKeyFactory.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return SecretKeyFactory.getInstance(algorithm);
    }
  }

  @Override
  public PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    byte[] encodedPk = publicKeyInfo.getEncoded();
    Asn1Oid oid = publicKeyInfo.getAlgorithm().getAlgorithm();
    try {
      if (OIDs.isPqcAlgorithm(oid)) {
        return BouncyCastlePQCProvider.getPublicKey(
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(encodedPk));
      } else {
        KeyFactory kf = getTradKeyFactory(oid);
        return kf.generatePublic(new X509EncodedKeySpec(encodedPk));
      }
    } catch (IOException | NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  @Override
  public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws InvalidKeySpecException {
    byte[] encodedSkInfo = privateKeyInfo.getEncoded();

    Asn1Oid oid = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
    try {
      if (OIDs.isPqcAlgorithm(oid)) {
        return BouncyCastlePQCProvider.getPrivateKey(
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(encodedSkInfo));
      } else {
        KeyFactory kf = getTradKeyFactory(oid);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encodedSkInfo));
      }
    } catch (IOException | NoSuchAlgorithmException ex) {
      throw new InvalidKeySpecException(ex.getMessage(), ex);
    }
  }

  private static KeyFactory getTradKeyFactory(Asn1Oid oid) throws NoSuchAlgorithmException {
    String name = oid.getId();
    try {
      return KeyFactory.getInstance(name, PROVIDER);
    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
      return KeyFactory.getInstance(name);
    }
  }

  @Override
  public void setContext(Signature sig, byte[] context) throws InvalidAlgorithmParameterException {
    if (context != null && context.length > 0) {
      sig.setParameter(new ContextParameterSpec(context));
    }
  }

  @Override
  public byte[] xof(String algorithm, byte[] data, int length) {
    String upAlgo = algorithm.toUpperCase(Locale.ROOT);
    if ("SHAKE128".equals(upAlgo) || "SHAKE128-256".equals(upAlgo)) {
      return shake(FipsSHS.SHAKE128, length, data);
    } else if ("SHAKE256".equals(upAlgo) || "SHAKE256-512".equals(upAlgo)) {
      return shake(FipsSHS.SHAKE256, length, data);
    } else {
      throw new IllegalArgumentException("invalid algorithm " + upAlgo);
    }
  }

  /**
   * Derives a key using HKDF-SHA-256 (RFC 5869).
   *
   * @param ikm    input keying material
   * @param salt   optional salt; empty array if absent
   * @param info   application/context-specific information
   * @param outputKeyLen desired output key size in bytes
   * @return derived key
   */
  @Override
  public byte[] hkdfSha256Derive(byte[] ikm, byte[] salt, byte[] info, int outputKeyLen) {
    if (ikm == null || salt == null || info == null) {
      throw new IllegalArgumentException("Inputs must not be null");
    }

    Args.range(outputKeyLen, "outputKeyLen", 1, 255 * 32);

    // HKDF-SHA-256: output length <= 255 * HashLen (32 bytes).

    // HKDF-Extract
    FipsKDF.HKDFKeyBuilder keyBuilder =
        FipsKDF.HKDF_KEY_BUILDER.withPrf(FipsKDF.AgreementKDFPRF.SHA256_HMAC).withSalt(salt);

    byte[] prk = keyBuilder.build(ikm).getKey();

    // HKDF-Expand
    FipsKDF.AgreementOperatorFactory factory = new FipsKDF.AgreementOperatorFactory();

    KDFCalculator<FipsKDF.AgreementKDFParameters> calculator = factory.createKDFCalculator(
        FipsKDF.HKDF.withPRF(FipsKDF.AgreementKDFPRF.SHA256_HMAC).using(prk).withIV(info));

    byte[] result = new byte[outputKeyLen];
    calculator.generateBytes(result);

    return result;
  }

  @Override
  public SecureRandom getSecureRandom(SecureRandom random) {
    return CryptoServicesRegistrar.getSecureRandom(random);
  }

  private static byte[] shake(FipsSHS.Parameters param, int outputSize, byte[] input) {
    FipsOutputXOFCalculator<FipsSHS.Parameters> calculator =
        xofFactory.createOutputXOFCalculator(param);

    try (OutputStream out = calculator.getFunctionStream()) {
      out.write(input);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    return calculator.getFunctionOutput(outputSize);
  }

  @Override
  public X9ECParameters getByOID(Asn1Oid oid) {
    org.bouncycastle.asn1.x9.X9ECParameters x =
        org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(
            ASN1ObjectIdentifier.getInstance(oid.getEncoded(Asn1Encoding.DER)));
    return (x == null) ? null : new X9ECParametersW(x);
  }

  @Override
  public byte[] generateX25519PrivateKey(SecureRandom rnd) {
    byte[] k = new byte[32];
    X25519.generatePrivateKey(rnd, k);
    return k;
  }

  @Override
  public byte[] generateX25519PublicKey(byte[] sk) {
    byte[] pk = new byte[32];
    X25519.generatePublicKey(sk, 0, pk, 0);
    return pk;
  }

  @Override
  public byte[] calculateX25519Agreement(byte[] sk, byte[] peerPk) {
    byte[] agreed = new byte[32];
    X25519.calculateAgreement(sk, 0, peerPk, 0, agreed, 0);
    return agreed;
  }

  @Override
  public byte[] generateX448PrivateKey(SecureRandom rnd) {
    byte[] k = new byte[56];
    X448.generatePrivateKey(rnd, k);
    return k;
  }

  @Override
  public byte[] generateX448PublicKey(byte[] sk) {
    byte[] pk = new byte[56];
    X448.generatePublicKey(sk, 0, pk, 0);
    return pk;
  }

  @Override
  public byte[] calculateX448Agreement(byte[] sk, byte[] peerPk) {
    byte[] agreed = new byte[56];
    X448.calculateAgreement(sk, 0, peerPk, 0, agreed, 0);
    return agreed;
  }

  /**
   * Generate MLDSA keypair.
   * @param variant the ML-DSA variant.
   * @param random may be null
   * @return the generated keypair
   */
  @Override
  public KeyPair generateKeyPair(MldsaVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException {
    AlgorithmParameterSpec spec;
    switch (variant) {
      case ml_dsa_44:
        spec = MLDSAParameterSpec.ml_dsa_44;
        break;
      case ml_dsa_65:
        spec = MLDSAParameterSpec.ml_dsa_65;
        break;
      // case ml_dsa_87:
      default:
        spec = MLDSAParameterSpec.ml_dsa_87;
        break;
    }

    return generateKeyPair("ML-DSA", spec, random);
  }

  /**
   * Generate MLKEM keypair.
   * @param variant the ML-KEM variant.
   * @param random may be null
   * @return the generated keypair
   */
  @Override
  public KeyPair generateKeyPair(MlkemVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException {
    AlgorithmParameterSpec spec;
    switch (variant) {
      case ml_kem_512:
        spec = MLKEMParameterSpec.ml_kem_512;
        break;
      case ml_kem_768:
        spec = MLKEMParameterSpec.ml_kem_768;
        break;
      // case ml_kem_1024:
      default:
        spec = MLKEMParameterSpec.ml_kem_1024;
    }

    return generateKeyPair("ML-KEM", spec, random);
  }

  private static KeyPair generateKeyPair(
      String algo, AlgorithmParameterSpec spec, SecureRandom random)
      throws NoSuchAlgorithmException {
    // the provider must be given: since JDK 24, the JDK provides ML-DSA and ML-KEM as well, but
    // does not accept the parameter specs of BouncyCastle.
    KeyPairGenerator kpGen;
    try {
      kpGen = KeyPairGenerator.getInstance(algo, PQC_PROVIDER);
    } catch (NoSuchProviderException e) {
      throw new NoSuchAlgorithmException(e.getMessage(), e);
    }

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
    MLKEMParameters params =
          pqcVariant == MlkemVariant.ml_kem_512 ? MLKEMParameters.ml_kem_512
        : pqcVariant == MlkemVariant.ml_kem_768 ? MLKEMParameters.ml_kem_768
        : pqcVariant == MlkemVariant.ml_kem_1024 ? MLKEMParameters.ml_kem_1024
        : null;
    if (params == null) {
      throw new IllegalArgumentException("invalid pqcVariant " + pqcVariant);
    }

    MLKEMGenerator gen = new MLKEMGenerator(rnd);
    MLKEMPublicKeyParameters pkParams = new MLKEMPublicKeyParameters(params, publicKeyData);
    return new SecretWithEncapsulationW(gen.generateEncapsulated(pkParams));
  }

  @Override
  public byte[] decapsulateKey(
      MlkemVariant pqcVariant, byte[] privateKeyValue, byte[] encapsulatedKey) {
    MLKEMParameters params =
          pqcVariant == MlkemVariant.ml_kem_512 ? MLKEMParameters.ml_kem_512
        : pqcVariant == MlkemVariant.ml_kem_768 ? MLKEMParameters.ml_kem_768
        : pqcVariant == MlkemVariant.ml_kem_1024 ? MLKEMParameters.ml_kem_1024
        : null;

    if (params == null) {
      throw new IllegalArgumentException("invalid pqcVariant " + pqcVariant);
    }

    MLKEMExtractor extractor = new MLKEMExtractor(
        new MLKEMPrivateKeyParameters(params, privateKeyValue));
    return extractor.extractSecret(encapsulatedKey);
  }

  @Override
  public byte[] expandMldsaSeed(MldsaVariant variant, byte[] seed) {
    MLDSAParameters params =
          variant == MldsaVariant.ml_dsa_44 ? MLDSAParameters.ml_dsa_44
        : variant == MldsaVariant.ml_dsa_65 ? MLDSAParameters.ml_dsa_65
        : variant == MldsaVariant.ml_dsa_87 ? MLDSAParameters.ml_dsa_87
        : null;
    if (params == null) {
      throw new IllegalArgumentException("invalid variant " + variant);
    }
    if (seed == null || seed.length != 32) {
      throw new IllegalArgumentException("seed must be 32 bytes");
    }

    return new MLDSAPrivateKeyParameters(params, seed).getEncoded();
  }

  @Override
  public byte[] expandMlkemSeed(MlkemVariant variant, byte[] seed) {
    MLKEMParameters params =
          variant == MlkemVariant.ml_kem_512 ? MLKEMParameters.ml_kem_512
        : variant == MlkemVariant.ml_kem_768 ? MLKEMParameters.ml_kem_768
        : variant == MlkemVariant.ml_kem_1024 ? MLKEMParameters.ml_kem_1024
        : null;
    if (params == null) {
      throw new IllegalArgumentException("invalid variant " + variant);
    }
    if (seed == null || seed.length != 64) {
      throw new IllegalArgumentException("seed must be 64 bytes");
    }

    return new MLKEMPrivateKeyParameters(params, seed).getEncoded();
  }

  private static class ECCurveW implements ECCurve {

    private final org.bouncycastle.math.ec.ECCurve underlying;

    public ECCurveW(org.bouncycastle.math.ec.ECCurve underlying) {
      this.underlying = Objects.requireNonNull(underlying, "underlying must not be null");
    }

    @Override
    public BigInteger getOrder() {
      return underlying.getOrder();
    }

    @Override
    public int getFieldSize() {
      return underlying.getFieldSize();
    }

    @Override
    public ECPoint decodePoint(byte[] bytes) {
      return new ECPointW(underlying.decodePoint(bytes));
    }

  }

  private static class ECPointW implements ECPoint {

    private final org.bouncycastle.math.ec.ECPoint underlying;

    public ECPointW(org.bouncycastle.math.ec.ECPoint underlying) {
      this.underlying = Objects.requireNonNull(underlying, "underlying must not be null");
    }

    @Override
    public ECPoint multiply(BigInteger x) {
      return new ECPointW(underlying.multiply(x));
    }

    @Override
    public ECPoint add(ECPoint x) {
      return new ECPointW(underlying.add(((ECPointW) x).underlying));
    }

    @Override
    public ECPoint normalize() {
      return new ECPointW(underlying.normalize());
    }

    @Override
    public BigInteger getXCoordBigInt() {
      return underlying.getXCoord().toBigInteger();
    }

    @Override
    public BigInteger getYCoordBigInt() {
      return underlying.getYCoord().toBigInteger();
    }

    @Override
    public byte[] getEncoded(boolean compressed) {
      return underlying.getEncoded(compressed);
    }

  }

  private static class SecretWithEncapsulationW implements SecretWithEncap {

    private final org.bouncycastle.crypto.SecretWithEncapsulation underlying;

    public SecretWithEncapsulationW(org.bouncycastle.crypto.SecretWithEncapsulation underlying) {
      this.underlying = Objects.requireNonNull(underlying, "underlying must not be null");
    }

    @Override
    public byte[] secret() {
      return underlying.getSecret();
    }

    @Override
    public byte[] encap() {
      return underlying.getEncapsulation();
    }

  }

  private static class X9ECParametersW implements X9ECParameters {

    private final ECCurveW curve;

    private final ECPointW G;

    public X9ECParametersW(org.bouncycastle.asn1.x9.X9ECParameters underlying) {
      this.curve = new ECCurveW(underlying.getCurve());
      this.G = new ECPointW(underlying.getG());
    }

    @Override
    public ECCurve getCurve() {
      return curve;
    }

    @Override
    public ECPoint getG() {
      return G;
    }

  }

  /**
   * {@link XiPKIProvider} of the BC-FIPS backend, with the primitives of BC-FIPS. It is used for
   * the algorithms BC-FIPS does not support: SM3, SM3withSM2, SHAKE128/256withRSAPSS (from
   * xicrypto), and SHAKE128/256withECDSA, which this class replaces with
   * {@link ShakeEcdsaSignatureSpi} (SHAKE and ECDSA of BC-FIPS, random nonce).
   * <p>
   * Not registered in {@link java.security.Security}.
   *
   * @author Lijun Liao (xipki)
   */
  static final class BcFipsXiPKIProvider extends XiPKIProvider {

    private static final long serialVersionUID = 1L;

    /**
     * The name of this provider: "{@value}".
     */
    static final String PROVIDER_NAME = "XiPKI-BCFIPS";

    /**
     * Constructor.
     * @param bcFips the BC-FIPS provider, the source of the primitives.
     */
    BcFipsXiPKIProvider(Provider bcFips) {
      super(PROVIDER_NAME, "XiPKI JCA provider on BC-FIPS", new Primitives(bcFips));

      ecdsa("SHAKE128WITHECDSA", ShakeEcdsaSignatureSpi.class,
          p -> new ShakeEcdsaSignatureSpi("SHAKE128"),
          AlgorithmOIDs.id_ecdsa_with_shake128);
      ecdsa("SHAKE256WITHECDSA", ShakeEcdsaSignatureSpi.class,
          p -> new ShakeEcdsaSignatureSpi("SHAKE256"),
          AlgorithmOIDs.id_ecdsa_with_shake256);
    }

  }

}
