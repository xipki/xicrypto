// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.X9ECParameters;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;
import java.util.Objects;

/**
 * @author Lijun Liao (xipki)
 */
public class CryptoBc implements CryptoApi {

  private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

  public CryptoBc() {
    init();
  }

  @Override
  public String name() {
    return "bc";
  }

  private void init() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    SecureRandom rnd = null;
    try {
      rnd = CryptoServicesRegistrar.getSecureRandom();
    } catch (RuntimeException e) {
    }

    if (rnd == null) {
      CryptoServicesRegistrar.setSecureRandom(new SecureRandom());
    }
  }

  @Override
  public KeyStore newKeyStore(String algorithm)
      throws KeyStoreException, NoSuchProviderException {
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
      return KeyAgreement.getInstance(algorithm);
    }
  }

  @Override
  public MessageDigest newMessageDigest(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return MessageDigest.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return MessageDigest.getInstance(algorithm);
    }
  }

  @Override
  public Mac newMac(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    algorithm = algorithm.toUpperCase(Locale.ROOT);
    // removing the '-' in
    int index = algorithm.indexOf("SHA-");
    if (index != -1) {
      algorithm = algorithm.substring(0, index + 3) + algorithm.substring(index + 4);
    }

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
      return Signature.getInstance(algorithm);
    }
  }

  @Override
  public Cipher newCipher(String algorithm) throws NoSuchPaddingException,
      NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return Cipher.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return Cipher.getInstance(algorithm);
    }
  }

  @Override
  public KeyFactory newKeyFactory(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyFactory.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return KeyFactory.getInstance(algorithm);
    }
  }

  @Override
  public KeyPairGenerator newKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    try {
      return KeyPairGenerator.getInstance(algorithm, PROVIDER);
    } catch (NoSuchAlgorithmException e) {
      return KeyPairGenerator.getInstance(algorithm);
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
    byte[] encodedPkInfo = publicKeyInfo.getEncoded();
    try {
      return BouncyCastleProvider.getPublicKey(
          org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(encodedPkInfo));
    } catch (IOException e) {
      throw new InvalidKeySpecException(e);
    }
  }

  @Override
  public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws InvalidKeySpecException {
    byte[] encodedSkInfo = privateKeyInfo.getEncoded();
    try {
      return BouncyCastleProvider.getPrivateKey(
          org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(encodedSkInfo));
    } catch (IOException e) {
      throw new InvalidKeySpecException(e);
    }
  }

  @Override
  public void setContext(Signature sig, byte[] context)
      throws InvalidAlgorithmParameterException {
    if (context != null && context.length > 0) {
      sig.setParameter(new ContextParameterSpec(context));
    }
  }

  @Override
  public byte[] xof(String algorithm, byte[] data, int length) {
    String upAlgo = algorithm.toUpperCase(Locale.ROOT);
    SHAKEDigest xof;
    if ("SHAKE128".equals(upAlgo) || "SHAKE128-256".equals(upAlgo)) {
      xof = new SHAKEDigest(128);
    } else if ("SHAKE256".equals(upAlgo) || "SHAKE256-512".equals(upAlgo)) {
      xof = new SHAKEDigest(256);
    } else {
      throw new IllegalArgumentException("invalid algorithm " + algorithm);
    }

    xof.update(data, 0, data.length);
    byte[] res = new byte[length];
    xof.doFinal(res, 0, length);
    return res;
  }

  @Override
  public byte[] hkdfSha256Derive(byte[] ikm, byte[] salt, byte[] info, int outputKeyLen) {
    HKDFBytesGenerator kdf = new HKDFBytesGenerator(new SHA256Digest());
    kdf.init(new HKDFParameters(ikm, salt, info));
    byte[] r = new byte[outputKeyLen];
    kdf.generateBytes(r, 0, outputKeyLen);
    return r;
  }

  @Override
  public SecureRandom getSecureRandom(SecureRandom random) {
    return CryptoServicesRegistrar.getSecureRandom(random);
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
      kpGen = KeyPairGenerator.getInstance(algo, PROVIDER);
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

    private final SecretWithEncapsulation underlying;

    public SecretWithEncapsulationW(SecretWithEncapsulation underlying) {
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
}
