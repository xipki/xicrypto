// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * Bundles a private key, public key, and derived C509 subject public key
 * representation.
 *
 * @author Lijun Liao (xipki)
 */
public class C509KeyPair {

  private final PrivateKey privateKey;

  private final PublicKey publicKey;

  private final C509SubjectPublicKey subjectPublicKey;

  public C509KeyPair(PrivateKey privateKey, PublicKey publicKey,
                     C509SubjectPublicKey subjectPublicKey) {
    this.privateKey = Args.notNull(privateKey, "privateKey");
    this.publicKey  = Args.notNull(publicKey, "publicKey");
    this.subjectPublicKey = Args.notNull(subjectPublicKey, "subjectPublicKey");
  }

  public PrivateKey privateKey() {
    return privateKey;
  }

  public PublicKey publicKey() {
    return publicKey;
  }

  public C509SubjectPublicKey subjectPublicKey() {
    return subjectPublicKey;
  }

  public static C509KeyPair generateECKeyPair(int keyAlgorithm, boolean compressed)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    return generateECKeyPair(keyAlgorithm, compressed, null);
  }

  public static C509KeyPair generateECKeyPair(
      int keyAlgorithm, boolean compressed, SecureRandom rnd)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    switch (keyAlgorithm) {
      case ConstPublicKeyAlgorithm.ec_secp256r1:
      case ConstPublicKeyAlgorithm.ec_secp384r1:
      case ConstPublicKeyAlgorithm.ec_secp521r1:
      case ConstPublicKeyAlgorithm.ec_brainpoolP256r1:
      case ConstPublicKeyAlgorithm.ec_brainpoolP384r1:
      case ConstPublicKeyAlgorithm.ec_brainpoolP512r1:
      case ConstPublicKeyAlgorithm.ec_sm2p256v1:
      case ConstPublicKeyAlgorithm.ec_frp256v1: {
        String curveName;
        int fieldSize;
        String provider = null;
        if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_secp256r1) {
          curveName = "secp256r1";
          fieldSize = 32;
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_secp384r1) {
          curveName = "secp384r1";
          fieldSize = 48;
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_secp521r1) {
          curveName = "secp521r1";
          fieldSize = 66;
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_sm2p256v1) {
          curveName = "sm2p256v1";
          fieldSize = 32;
          provider = "BC";
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_brainpoolP256r1) {
          curveName = "brainpoolP256r1";
          fieldSize = 32;
          provider = "BC";
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_brainpoolP384r1) {
          curveName = "brainpoolP384r1";
          fieldSize = 48;
          provider = "BC";
        } else if (keyAlgorithm == ConstPublicKeyAlgorithm.ec_brainpoolP512r1) {
          curveName = "brainpoolP512r1";
          fieldSize = 64;
          provider = "BC";
        } else {
          curveName = "frp256v1";
          fieldSize = 32;
          provider = "BC";
        }

        KeyPairGenerator kpGen;
        if (provider == null) {
          kpGen = KeyPairGenerator.getInstance("EC");
        } else {
          try {
            kpGen = KeyPairGenerator.getInstance("EC", provider);
          } catch (NoSuchProviderException e) {
            throw new NoSuchAlgorithmException(e);
          }
        }

        ECGenParameterSpec spec = new ECGenParameterSpec(curveName);
        try {
          if (rnd != null) {
            kpGen.initialize(spec, rnd);
          } else {
            kpGen.initialize(spec);
          }
        } catch (InvalidAlgorithmParameterException e) {
          throw new InvalidKeySpecException(e);
        }

        KeyPair keyPair = kpGen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPoint w = publicKey.getW();

        byte[] encodedW;
        if (compressed) {
          encodedW = new byte[1 + fieldSize];
          boolean odd = w.getAffineY().testBit(0);
          encodedW[0] = odd
              ? C509ECSubjectPublicKey.COMPRESSED_ODD_Y
              : C509ECSubjectPublicKey.COMPRESSED_EVEN_Y;

          copyEcCoordinate(w.getAffineX(), true,  encodedW, fieldSize);
        } else {
          encodedW = new byte[1 + 2 * fieldSize];
          encodedW[0] = 4;
          copyEcCoordinate(w.getAffineX(), true,  encodedW, fieldSize);
          copyEcCoordinate(w.getAffineY(), false, encodedW, fieldSize);
        }

        C509ECSubjectPublicKey subjectPublicKey = new C509ECSubjectPublicKey(keyAlgorithm, encodedW);
        return new C509KeyPair(keyPair.getPrivate(), keyPair.getPublic(), subjectPublicKey);
      }
      default:
        throw new IllegalArgumentException(keyAlgorithm + " is not supported yet");
    }
  }

  private static void copyEcCoordinate(
      BigInteger coordinate, boolean isX, byte[] encodedPoint, int fieldLength) {
    byte[] bytes = coordinate.toByteArray();
    int blen = bytes.length;
    int coordOff = blen > fieldLength ? 1 : 0; // remove leading zero
    int pointOff = blen < fieldLength ? fieldLength - blen : 0;

    System.arraycopy(bytes, coordOff, encodedPoint,
        isX ? 1+ pointOff : 1 + fieldLength + pointOff, fieldLength - pointOff);
  }

  public static C509KeyPair generateRSAKeyPair(int keySize)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    return generateRSAKeyPair(keySize, null, null);
  }

  public static C509KeyPair generateRSAKeyPair(int keySize, SecureRandom rnd)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    return generateRSAKeyPair(keySize, null, rnd);
  }

  public static C509KeyPair generateRSAKeyPair(int keySize, BigInteger publicExponent)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    return generateRSAKeyPair(keySize, publicExponent, null);
  }

  public static C509KeyPair generateRSAKeyPair(
      int keySize, BigInteger publicExponent, SecureRandom rnd)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    if (publicExponent == null) {
      if (rnd != null) {
        kpGen.initialize(keySize, rnd);
      } else {
        kpGen.initialize(keySize);
      }
    } else {
      RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keySize, publicExponent);
      try {
        if (rnd != null) {
          kpGen.initialize(spec, rnd);
        } else {
          kpGen.initialize(spec);
        }
      } catch (InvalidAlgorithmParameterException e) {
        throw new InvalidKeySpecException(e);
      }
    }
    return generateRSAKeyPair(kpGen);
  }

  private static C509KeyPair generateRSAKeyPair(KeyPairGenerator kpGen) {
    KeyPair keyPair = kpGen.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    C509RSASubjectPublicKey subjectPublicKey = new C509RSASubjectPublicKey(
        publicKey.getModulus(), publicKey.getPublicExponent());
    return new C509KeyPair(keyPair.getPrivate(), keyPair.getPublic(), subjectPublicKey);
  }

  public static C509KeyPair generateKeyPair(int keyAlgorithm)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    return generateKeyPair(keyAlgorithm, null);
  }

  public static C509KeyPair generateKeyPair(int keyAlgorithm, SecureRandom rnd)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    if (ConstPublicKeyAlgorithm.isWeierstrass(keyAlgorithm)) {
      return generateECKeyPair(keyAlgorithm, false, rnd);
    } else if (ConstPublicKeyAlgorithm.rsaEncryption == keyAlgorithm) {
      return generateRSAKeyPair(2048, rnd);
    } else {
      String keyType;
      switch (keyAlgorithm) {
        case ConstPublicKeyAlgorithm.ed25519:
          keyType = "ED25519";
          break;
        case ConstPublicKeyAlgorithm.ed448:
          keyType = "ED448";
          break;
        case ConstPublicKeyAlgorithm.x25519:
          keyType = "X25519";
          break;
        case ConstPublicKeyAlgorithm.x448:
          keyType = "X448";
          break;
        case ConstPublicKeyAlgorithm.ML_DSA_44:
          keyType = "ML-DSA-44";
          break;
        case ConstPublicKeyAlgorithm.ML_DSA_65:
          keyType = "ML-DSA-65";
          break;
        case ConstPublicKeyAlgorithm.ML_DSA_87:
          keyType = "ML-DSA-87";
          break;
        case ConstPublicKeyAlgorithm.ML_KEM_512:
          keyType = "ML-KEM-512";
          break;
        case ConstPublicKeyAlgorithm.ML_KEM_768:
          keyType = "ML-KEM-768";
          break;
        case ConstPublicKeyAlgorithm.ML_KEM_1024:
          keyType = "ML-KEM-1024";
          break;
        default:
          throw new InvalidKeySpecException("unknown key algorithm " +
              ConstPublicKeyAlgorithm.getDesc(keyAlgorithm));
      }

      KeyPairGenerator kpGen = KeyPairGenerator.getInstance(keyType);

      if (rnd != null) {
        try {
          kpGen.initialize(new NamedParameterSpec(keyType), rnd);
        } catch (InvalidAlgorithmParameterException e) {
          throw new InvalidKeySpecException(e);
        }
      }

      KeyPair keyPair = kpGen.generateKeyPair();
      SubjectPublicKeyInfo x509Spki;
      try {
        x509Spki = SubjectPublicKeyInfo.fromPublicKey(keyPair.getPublic());
      } catch (CodecException e) {
        throw new InvalidKeySpecException(e);
      }

      C509SubjectPublicKey c509PublicKey = C509SubjectPublicKey.fromSubjectPublicKeyInfo(x509Spki);

      if (c509PublicKey.algorithm() != keyAlgorithm) {
        throw new IllegalStateException("shall not reach here");
      }

      return new C509KeyPair(keyPair.getPrivate(), keyPair.getPublic(), c509PublicKey);
    }
  }

}
