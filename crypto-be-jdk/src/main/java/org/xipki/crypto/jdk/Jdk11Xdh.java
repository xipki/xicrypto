// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Workaround for the encoding of X25519 and X448 keys in JDK 11 (JDK-8213363, fixed in
 * JDK 12): JDK 11 reads and writes the private key raw in the privateKey field of PKCS#8,
 * instead of an OCTET STRING in it (RFC 8410, CurvePrivateKey), and writes the AlgorithmIdentifier
 * with NULL parameters instead of absent ones.
 * <p>
 * On JDK 11, crypto-be-jdk wraps the XDH key factory and key pair generator of the JDK:
 * <ul>
 *   <li>PKCS#8 input in the form of RFC 8410 is converted into the form of JDK 11;</li>
 *   <li>the keys are returned as {@link XECPrivateKey} / {@link XECPublicKey} whose
 *       {@code getEncoded()} is the form of RFC 8410; the other methods delegate to the key of
 *       the JDK. The KeyAgreement of the JDK accepts these keys (it uses the XEC interfaces).</li>
 * </ul>
 *
 * @author Lijun Liao (xipki)
 */
final class Jdk11Xdh {

  /** the JDK version that fixed the encoding (JDK-8213363). */
  static final int FIXED_IN = 12;

  private Jdk11Xdh() {
  }

  /**
   * Returns whether the workaround is needed for the algorithm on the running JDK.
   * @param algorithm the name or OID of the algorithm.
   * @return whether the workaround is needed.
   */
  static boolean isNeeded(String algorithm) {
    return JdkCompat.FEATURE < FIXED_IN && isXdh(algorithm);
  }

  static boolean isXdh(String algorithm) {
    String upper = algorithm.toUpperCase(Locale.ROOT);
    return upper.equals("XDH") || upper.equals("X25519") || upper.equals("X448")
        || AlgorithmOIDs.id_X25519.getId().equals(algorithm)
        || AlgorithmOIDs.id_X448.getId().equals(algorithm);
  }

  /**
   * Converts a PKCS#8 XDH private key into the form of JDK 11 (raw private key, version 0,
   * without parameters and public key). A key already in the form of JDK 11 is returned as it is.
   */
  static byte[] toJdk11Pkcs8(byte[] encoded) throws InvalidKeySpecException {
    try {
      PrivateKeyInfo info = PrivateKeyInfo.fromEncoded(encoded);
      byte[] content = info.privateKey();
      int keyLen = keyLength(info.getPrivateKeyAlgorithm().getAlgorithm());
      byte[] raw;
      if (content.length == keyLen) {
        // already the form of JDK 11
        raw = content;
      } else {
        raw = Asn1OctetString.fromEncoded(content).getOctets();
        if (raw.length != keyLen) {
          throw new InvalidKeySpecException("invalid length of the private key: " + raw.length);
        }
      }
      return new PrivateKeyInfo(new AlgorithmIdentifier(info.getPrivateKeyAlgorithm()
          .getAlgorithm()), raw).getEncoded();
    } catch (CodecException | RuntimeException e) {
      throw new InvalidKeySpecException("invalid XDH private key: " + e.getMessage(), e);
    }
  }

  private static int keyLength(Asn1Oid oid) throws InvalidKeySpecException {
    if (AlgorithmOIDs.id_X25519.equals(oid)) {
      return 32;
    } else if (AlgorithmOIDs.id_X448.equals(oid)) {
      return 56;
    }
    throw new InvalidKeySpecException("not an XDH key: " + oid.getId());
  }

  private static Asn1Oid oid(AlgorithmParameterSpec params) {
    String name = (params instanceof NamedParameterSpec)
        ? ((NamedParameterSpec) params).getName() : "";
    if ("X25519".equalsIgnoreCase(name)) {
      return AlgorithmOIDs.id_X25519;
    } else if ("X448".equalsIgnoreCase(name)) {
      return AlgorithmOIDs.id_X448;
    }
    throw new IllegalStateException("unknown XDH parameters " + name);
  }

  static PrivateKey wrap(PrivateKey key) {
    return (key instanceof XECPrivateKey && !(key instanceof Rfc8410PrivateKey))
        ? new Rfc8410PrivateKey((XECPrivateKey) key) : key;
  }

  static PublicKey wrap(PublicKey key) {
    return (key instanceof XECPublicKey && !(key instanceof Rfc8410PublicKey))
        ? new Rfc8410PublicKey((XECPublicKey) key) : key;
  }

  private static Key unwrap(Key key) {
    if (key instanceof Rfc8410PrivateKey) {
      return ((Rfc8410PrivateKey) key).jdkKey;
    } else if (key instanceof Rfc8410PublicKey) {
      return ((Rfc8410PublicKey) key).jdkKey;
    }
    return key;
  }

  /**
   * XDH private key of the JDK, encoded as in RFC 8410.
   */
  static final class Rfc8410PrivateKey implements XECPrivateKey {

    private static final long serialVersionUID = 1L;

    private final XECPrivateKey jdkKey;

    Rfc8410PrivateKey(XECPrivateKey jdkKey) {
      this.jdkKey = jdkKey;
    }

    @Override
    public Optional<byte[]> getScalar() {
      return jdkKey.getScalar();
    }

    @Override
    public AlgorithmParameterSpec getParams() {
      return jdkKey.getParams();
    }

    @Override
    public String getAlgorithm() {
      return jdkKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
      byte[] scalar = jdkKey.getScalar().orElse(null);
      if (scalar == null) {
        return null;
      }
      try {
        // CurvePrivateKey ::= OCTET STRING
        return new PrivateKeyInfo(new AlgorithmIdentifier(oid(getParams())),
            new Asn1OctetString(scalar)).getEncoded();
      } finally {
        Arrays.fill(scalar, (byte) 0);
      }
    }

  }

  /**
   * XDH public key of the JDK, encoded as in RFC 8410 (without parameters).
   */
  static final class Rfc8410PublicKey implements XECPublicKey {

    private static final long serialVersionUID = 1L;

    private final XECPublicKey jdkKey;

    Rfc8410PublicKey(XECPublicKey jdkKey) {
      this.jdkKey = jdkKey;
    }

    @Override
    public BigInteger getU() {
      return jdkKey.getU();
    }

    @Override
    public AlgorithmParameterSpec getParams() {
      return jdkKey.getParams();
    }

    @Override
    public String getAlgorithm() {
      return jdkKey.getAlgorithm();
    }

    @Override
    public String getFormat() {
      return "X.509";
    }

    @Override
    public byte[] getEncoded() {
      try {
        byte[] raw = SubjectPublicKeyInfo.fromEncoded(jdkKey.getEncoded()).subjectPublicKey();
        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid(getParams())), raw)
            .getEncoded();
      } catch (CodecException e) {
        throw new IllegalStateException("could not encode the XDH public key", e);
      }
    }

  }

  /**
   * XDH key factory of the JDK, with the conversions of the encodings.
   */
  static final class Rfc8410KeyFactory extends KeyFactory {

    Rfc8410KeyFactory(KeyFactory jdk) {
      super(new Spi(jdk), jdk.getProvider(), jdk.getAlgorithm());
    }

    private static final class Spi extends KeyFactorySpi {

      private final KeyFactory jdk;

      Spi(KeyFactory jdk) {
        this.jdk = jdk;
      }

      @Override
      protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        // JDK 11 reads the public key of RFC 8410 (without parameters)
        return wrap(jdk.generatePublic(keySpec));
      }

      @Override
      protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
          throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
          byte[] encoded = toJdk11Pkcs8(((PKCS8EncodedKeySpec) keySpec).getEncoded());
          try {
            keySpec = new PKCS8EncodedKeySpec(encoded);
          } finally {
            Arrays.fill(encoded, (byte) 0);
          }
        }
        return wrap(jdk.generatePrivate(keySpec));
      }

      @Override
      protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
          throws InvalidKeySpecException {
        Key k = unwrap(key);
        if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class) && k instanceof XECPrivateKey) {
          return keySpec.cast(new PKCS8EncodedKeySpec(
              new Rfc8410PrivateKey((XECPrivateKey) k).getEncoded()));
        } else if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)
            && k instanceof XECPublicKey) {
          return keySpec.cast(new X509EncodedKeySpec(
              new Rfc8410PublicKey((XECPublicKey) k).getEncoded()));
        }
        return jdk.getKeySpec(k, keySpec);
      }

      @Override
      protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        Key k = jdk.translateKey(unwrap(key));
        if (k instanceof PrivateKey) {
          return wrap((PrivateKey) k);
        } else if (k instanceof PublicKey) {
          return wrap((PublicKey) k);
        }
        return k;
      }

    }

  }

  /**
   * XDH key pair generator of the JDK, returning the keys encoded as in RFC 8410.
   */
  static final class Rfc8410KeyPairGenerator extends KeyPairGenerator {

    private final KeyPairGenerator jdk;

    Rfc8410KeyPairGenerator(KeyPairGenerator jdk) {
      super(jdk.getAlgorithm());
      this.jdk = jdk;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
      jdk.initialize(keysize, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      jdk.initialize(params, random);
    }

    @Override
    public KeyPair generateKeyPair() {
      KeyPair kp = jdk.generateKeyPair();
      return new KeyPair(wrap(kp.getPublic()), wrap(kp.getPrivate()));
    }

  }

}
