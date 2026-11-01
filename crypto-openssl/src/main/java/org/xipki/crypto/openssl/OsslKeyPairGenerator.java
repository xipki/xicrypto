// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Locale;

/**
 * KeyPairGenerator on OpenSSL. The randomness comes from the DRBG of OpenSSL, the
 * {@code SecureRandom} of {@code initialize} is not used.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslKeyPairGenerator extends KeyPairGeneratorSpi {

  /** The family of keys. */
  enum Family {
    RSA, EC, EDDSA, XDH, MLDSA, MLKEM
  }

  private final Family family;

  /** The variant fixed by the algorithm name, e.g. "ED25519" for "Ed25519"; null if not. */
  private final String fixedType;

  private String keyType;

  private OsslParams params = new OsslParams();

  /**
   * Constructor.
   * @param family the family.
   * @param fixedType the key type in OpenSSL fixed by the algorithm name (e.g. "ED25519",
   *                  "ML-DSA-65"), or null.
   */
  OsslKeyPairGenerator(Family family, String fixedType) {
    this.family = family;
    this.fixedType = fixedType;
    try {
      switch (family) {
        case RSA -> initialize(3072, null);
        case EC -> initialize(new ECGenParameterSpec("P-256"), null);
        case EDDSA -> keyType = (fixedType != null) ? fixedType : "ED25519";
        case XDH -> keyType = (fixedType != null) ? fixedType : "X25519";
        case MLDSA -> keyType = (fixedType != null) ? fixedType : "ML-DSA-65";
        case MLKEM -> keyType = (fixedType != null) ? fixedType : "ML-KEM-768";
        default -> throw new IllegalArgumentException("unknown family " + family);
      }
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void initialize(int keysize, SecureRandom random) {
    String type;
    switch (family) {
      case RSA -> {
        keyType = "RSA";
        params = new OsslParams().integer("bits", keysize);
        return;
      }
      case EC -> {
        OsslCurves.Curve curve = OsslCurves.ofKeySize(keysize);
        if (curve == null) {
          throw new InvalidParameterException("unsupported EC key size " + keysize);
        }
        setCurve(curve);
        return;
      }
      case EDDSA -> type = (keysize == 255) ? "ED25519" : (keysize == 448) ? "ED448" : null;
      case XDH -> type = (keysize == 255) ? "X25519" : (keysize == 448) ? "X448" : null;
      default -> type = null;
    }

    if (type == null || (fixedType != null && !fixedType.equals(type))) {
      throw new InvalidParameterException("unsupported key size " + keysize);
    }
    keyType = type;
    params = new OsslParams();
  }

  @Override
  public void initialize(AlgorithmParameterSpec spec, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    switch (family) {
      case RSA -> {
        if (!(spec instanceof RSAKeyGenParameterSpec rsa)) {
          throw new InvalidAlgorithmParameterException("unsupported parameters " + spec);
        }
        BigInteger e = rsa.getPublicExponent();
        keyType = "RSA";
        params = new OsslParams().integer("bits", rsa.getKeysize())
            .bigInt("e", e == null ? RSAKeyGenParameterSpec.F4 : e, false);
      }
      case EC -> setCurve(OsslCurves.of(spec));
      default -> {
        String type = (spec instanceof NamedParameterSpec n)
            ? n.getName().toUpperCase(Locale.ROOT) : null;
        boolean valid = type != null && switch (family) {
          case EDDSA -> type.equals("ED25519") || type.equals("ED448");
          case XDH -> type.equals("X25519") || type.equals("X448");
          case MLDSA -> type.matches("ML-DSA-(44|65|87)");
          case MLKEM -> type.matches("ML-KEM-(512|768|1024)");
          default -> false;
        };
        if (!valid || (fixedType != null && !fixedType.equals(type))) {
          throw new InvalidAlgorithmParameterException("unsupported parameters " + spec);
        }
        keyType = type;
        params = new OsslParams();
      }
    }
  }

  private void setCurve(OsslCurves.Curve curve) {
    keyType = curve.keyType();
    params = new OsslParams().utf8("group", curve.name());
  }

  @Override
  public KeyPair generateKeyPair() {
    MemorySegment pkey = OpenSsl.generateKey(keyType, params);
    if (OpenSsl.isNull(pkey)) {
      throw new ProviderException("generating the " + keyType + " key failed: "
          + OpenSsl.errors());
    }

    PrivateKey privateKey = (PrivateKey) OsslKey.wrapKnown(pkey, true);
    return new KeyPair(publicKey(privateKey), privateKey);
  }

  /**
   * Returns the public key of the private key, as separate EVP_PKEY: the public key does not
   * keep the private key in memory.
   */
  static PublicKey publicKey(PrivateKey privateKey) {
    byte[] spki = ((OsslKey) privateKey).nativeKey().apply(p -> OpenSsl.encodeKey(p, false));
    MemorySegment pub = (spki == null) ? MemorySegment.NULL : OpenSsl.d2iPublicKey(spki);
    if (OpenSsl.isNull(pub)) {
      throw new ProviderException("extracting the public key failed: " + OpenSsl.errors());
    }
    return (PublicKey) OsslKey.wrapKnown(pub, false);
  }

}
