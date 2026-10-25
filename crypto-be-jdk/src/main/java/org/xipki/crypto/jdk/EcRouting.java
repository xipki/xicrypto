// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Chooses per curve between the EC implementation of the JDK (SunEC) and the one of xicrypto
 * (own instance of the backend), for the curves the JDK lacks, such as brainpool, SM2 or
 * FRP256v1.
 * <p>
 * The decision must be made by curve: SunEC still knows the brainpool curves in its curve
 * table, it accepts brainpool public keys and only fails when verifying a signature. A curve is
 * considered as supported by the JDK if SunEC can initialize a key pair generator for it. So a
 * future JDK supporting more curves is used automatically.
 *
 * @author Lijun Liao (xipki)
 */
final class EcRouting {

  static final String JDK_PROVIDER = "SunEC";

  private static final Map<String, Boolean> JDK_SUPPORT = new ConcurrentHashMap<>();

  private EcRouting() {
  }

  static Provider jdkProvider() {
    return Security.getProvider(JDK_PROVIDER);
  }

  /**
   * Returns the XiPKIProvider instance of the backend.
   * @return the XiPKIProvider instance.
   */
  static Provider xipkiProvider() {
    return CryptoJdk.xipki();
  }

  static boolean isEnabled() {
    return jdkProvider() != null;
  }

  static boolean isEcKeyAlgorithm(String algorithm) {
    String a = algorithm.toUpperCase(Locale.ROOT);
    return "EC".equals(a) || "ECDSA".equals(a)
        || AlgorithmOIDs.id_ecPublicKey.getId().equals(a)
        || CurveOIDs.sm2p256v1.getId().equals(a);
  }

  /**
   * Returns whether the algorithm is an ECDSA signature supported by SunEC.
   * @param algorithm the name or OID of the signature algorithm.
   * @return whether it is an ECDSA signature supported by SunEC.
   */
  static boolean isJdkEcdsa(String algorithm) {
    Provider jdk = jdkProvider();
    Provider.Service service = (jdk == null) ? null : jdk.getService("Signature", algorithm);
    return service != null
        && service.getAlgorithm().toUpperCase(Locale.ROOT).endsWith("WITHECDSA");
  }

  /**
   * Returns the provider for the key: the JDK if it supports the curve of the key, otherwise
   * the XiPKI provider.
   */
  static Provider providerFor(Key key) {
    if (key instanceof ECKey) {
      return providerFor(((ECKey) key).getParams());
    }
    return jdkProvider();
  }

  static Provider providerFor(ECParameterSpec params) {
    if (params == null) {
      return jdkProvider();
    }
    String cacheKey = params.getOrder().toString(16) + ":"
        + params.getGenerator().getAffineX().toString(16);
    return choose(cacheKey, params);
  }

  /**
   * Returns the provider for the curve given by the OID.
   * @param curveOid the curve OID, may be null.
   * @return the provider.
   */
  static Provider providerForCurve(String curveOid) {
    if (curveOid == null) {
      return jdkProvider();
    }
    return choose(curveOid, new ECGenParameterSpec(curveOid));
  }

  /**
   * Returns the provider for the DER encoded SubjectPublicKeyInfo.
   */
  static Provider providerForPublicKeyInfo(byte[] encoded) {
    try {
      return providerForCurve(curveOid(SubjectPublicKeyInfo.algorithmFromEncoded(encoded)));
    } catch (Exception e) {
      // let the JDK report the error
      return jdkProvider();
    }
  }

  /**
   * Returns the provider for the DER encoded PKCS#8 PrivateKeyInfo.
   */
  static Provider providerForPrivateKeyInfo(byte[] encoded) {
    try {
      return providerForCurve(curveOid(PrivateKeyInfo.algorithmFromEncoded(encoded)));
    } catch (Exception e) {
      // let the JDK report the error
      return jdkProvider();
    }
  }

  private static String curveOid(AlgorithmIdentifier keyAlgId) {
    Asn1Oid alg = keyAlgId.getAlgorithm();
    if (CurveOIDs.sm2p256v1.equals(alg)) {
      return alg.getId();
    }

    Asn1Primitive params = keyAlgId.getParameters();
    return (params instanceof Asn1Oid) ? ((Asn1Oid) params).getId() : null;
  }

  private static Provider choose(String cacheKey, AlgorithmParameterSpec spec) {
    Provider jdk = jdkProvider();
    Provider xipki = xipkiProvider();
    if (xipki == null) {
      return jdk;
    }

    Boolean supported = JDK_SUPPORT.get(cacheKey);
    if (supported == null) {
      supported = isSupportedByJdk(jdk, spec);
      JDK_SUPPORT.put(cacheKey, supported);
    }
    return supported ? jdk : xipki;
  }

  private static boolean isSupportedByJdk(Provider jdk, AlgorithmParameterSpec spec) {
    if (jdk == null) {
      return false;
    }

    try {
      KeyPairGenerator.getInstance("EC", jdk).initialize(spec);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  /**
   * EC key factory that chooses the implementation by the curve of the key (spec), see
   * {@link EcRouting}. {@link #getProvider()} returns null.
   *
   * @author Lijun Liao (xipki)
   */
  static final class KeyFactoryImpl extends KeyFactory {

    KeyFactoryImpl() {
      super(new Spi(), null, "EC");
    }

    private static final class Spi extends KeyFactorySpi {

      @Override
      protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        Provider provider;
        if (keySpec instanceof X509EncodedKeySpec) {
          provider = EcRouting.providerForPublicKeyInfo(
              ((X509EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPublicKeySpec) {
          provider = EcRouting.providerFor(((ECPublicKeySpec) keySpec).getParams());
        } else {
          provider = EcRouting.jdkProvider();
        }
        return newInstance(provider).generatePublic(keySpec);
      }

      @Override
      protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        Provider provider;
        if (keySpec instanceof PKCS8EncodedKeySpec) {
          provider = EcRouting.providerForPrivateKeyInfo(
              ((PKCS8EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof ECPrivateKeySpec) {
          provider = EcRouting.providerFor(((ECPrivateKeySpec) keySpec).getParams());
        } else {
          provider = EcRouting.jdkProvider();
        }
        return newInstance(provider).generatePrivate(keySpec);
      }

      @Override
      protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
          throws InvalidKeySpecException {
        return newInstance(EcRouting.providerFor(key)).getKeySpec(key, keySpec);
      }

      @Override
      protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        try {
          return newInstance(EcRouting.providerFor(key)).translateKey(key);
        } catch (InvalidKeySpecException e) {
          throw new InvalidKeyException(e.getMessage(), e);
        }
      }

      private static KeyFactory newInstance(Provider provider) throws InvalidKeySpecException {
        try {
          return KeyFactory.getInstance("EC", provider);
        } catch (NoSuchAlgorithmException e) {
          throw new InvalidKeySpecException("KeyFactory EC is not supported by "
              + provider.getName(), e);
        }
      }

    }

  }

  /**
   * EC key pair generator: SunEC if it supports the curve, otherwise the XiPKI provider, see
   * {@link EcRouting}. {@link #getProvider()} returns null.
   *
   * @author Lijun Liao (xipki)
   */
  static final class KeyPairGeneratorImpl extends KeyPairGenerator {

    private KeyPairGenerator delegate;

    KeyPairGeneratorImpl() {
      super("EC");
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
      KeyPairGenerator kpGen = newInstance(EcRouting.jdkProvider());
      kpGen.initialize(keysize, random);
      delegate = kpGen;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      KeyPairGenerator jdkKpGen = newInstance(EcRouting.jdkProvider());
      try {
        jdkKpGen.initialize(params, random);
        delegate = jdkKpGen;
        return;
      } catch (InvalidAlgorithmParameterException | InvalidParameterException e) {
        Provider xipki = EcRouting.xipkiProvider();
        if (xipki == null) {
          throw e;
        }

        KeyPairGenerator kpGen = newInstance(xipki);
        try {
          kpGen.initialize(params, random);
        } catch (InvalidAlgorithmParameterException e2) {
          // report the error of the JDK
          e.addSuppressed(e2);
          throw e;
        }
        delegate = kpGen;
      }
    }

    @Override
    public KeyPair generateKeyPair() {
      if (delegate == null) {
        // default parameters of the JDK
        delegate = newInstance(EcRouting.jdkProvider());
      }
      return delegate.generateKeyPair();
    }

    private static KeyPairGenerator newInstance(Provider provider) {
      try {
        return KeyPairGenerator.getInstance("EC", provider);
      } catch (NoSuchAlgorithmException e) {
        throw new ProviderException("KeyPairGenerator EC is not supported by "
            + provider.getName(), e);
      }
    }

  }

  /**
   * ECDSA signature that chooses the implementation by the curve of the key, see
   * {@link EcRouting}. {@link #getProvider()} returns null.
   *
   * @author Lijun Liao (xipki)
   */
  static final class SignatureImpl extends Signature {

    private Signature delegate;

    private AlgorithmParameterSpec params;

    SignatureImpl(String algorithm) {
      super(algorithm);
    }

    private void choose(Key key) throws InvalidKeyException {
      Provider provider = EcRouting.providerFor(key);
      if (delegate != null && delegate.getProvider() == provider) {
        return;
      }

      try {
        Signature sig = Signature.getInstance(getAlgorithm(), provider);
        if (params != null) {
          sig.setParameter(params);
        }
        delegate = sig;
      } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
        throw new InvalidKeyException("could not create " + getAlgorithm() + " of provider "
            + provider.getName() + ": " + e.getMessage(), e);
      }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      choose(publicKey);
      delegate.initVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      choose(privateKey);
      delegate.initSign(privateKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException {
      choose(privateKey);
      delegate.initSign(privateKey, random);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
      delegate.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      delegate.update(b, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
      try {
        delegate.update(input);
      } catch (SignatureException e) {
        throw new IllegalStateException(e.getMessage(), e);
      }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      return delegate.sign();
    }

    @Override
    protected int engineSign(byte[] outbuf, int offset, int len) throws SignatureException {
      return delegate.sign(outbuf, offset, len);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      return delegate.verify(sigBytes);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int length)
        throws SignatureException {
      return delegate.verify(sigBytes, offset, length);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
      if (delegate != null) {
        delegate.setParameter(params);
      }
      this.params = params;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      return (delegate == null) ? null : delegate.getParameters();
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
      throw new InvalidParameterException("parameters are not supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      throw new InvalidParameterException("parameters are not supported");
    }

  }

}
