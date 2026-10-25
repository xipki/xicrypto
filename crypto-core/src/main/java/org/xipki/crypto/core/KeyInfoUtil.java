// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.crypto.PqcPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.composite.CompositeKeyInfoConverter;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.Arrays;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Key info utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyInfoUtil {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  /**
   * System property to disable the SM algorithms (SM2, SM3), e.g. to test that the other
   * algorithms work without them. The same property is evaluated by the module xicrypto.
   */
  public static final String PROP_DISABLE_SM = "xipki.crypto.disableSm";

  /** a, b, Gx and Gy of the curve sm2p256v1, the input of Z_A. */
  private static final byte[] SM2_CURVE_DATA = Hex.decode(
      "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc" + // A
      "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93" + // B
      "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" + // Gx
      "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"); // Gy

  /** the default SM2 user ID "1234567812345678". */
  private static final byte[] SM2_DEFAULT_ID = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

  private KeyInfoUtil() {
  }

  /**
   * Returns whether the SM algorithms are disabled by the system property
   * {@link #PROP_DISABLE_SM}.
   * @return whether the SM algorithms are disabled.
   */
  public static boolean isSmDisabled() {
    return Boolean.getBoolean(PROP_DISABLE_SM);
  }

  /**
   * Returns Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A) of SM2
   * (GB/T 32918.2).
   * @param userID the user ID, null for the default "1234567812345678".
   * @param pubPoint the uncompressed public point (0x04 || x || y), 65 bytes.
   * @return Z_A.
   */
  public static byte[] getSM2Z(byte[] userID, byte[] pubPoint) {
    byte[] id = (userID == null) ? SM2_DEFAULT_ID : userID;
    if (id.length > 0x1FFF) {
      throw new IllegalArgumentException("userId too long");
    }

    MessageDigest digest = HashAlgo.SM3.createDigest();
    int len = id.length * 8;
    digest.update((byte) (len >> 8));
    digest.update((byte) len);
    digest.update(id);
    digest.update(SM2_CURVE_DATA);
    digest.update(pubPoint, 1, 64);
    return digest.digest();
  }

  /**
   * Returns Z_A of SM2, see {@link #getSM2Z(byte[], byte[])}.
   * @param userID the user ID, null for the default "1234567812345678".
   * @param pubPointX the x coordinate of the public point.
   * @param pubPointY the y coordinate of the public point.
   * @return Z_A.
   */
  public static byte[] getSM2Z(byte[] userID, BigInteger pubPointX, BigInteger pubPointY) {
    byte[] ecPoint = Arrays.concatenate(new byte[] {4},
        BigIntegers.asUnsignedByteArray(32, pubPointX),
        BigIntegers.asUnsignedByteArray(32, pubPointY));
    return getSM2Z(userID, ecPoint);
  }

  public static void setContext(Signature sig, byte[] context)
      throws InvalidAlgorithmParameterException {
    cryptoApi.setContext(sig, context);
  }

  public static byte[] xof(HashAlgo mgfDigest, byte[] Z, int length) {
    return cryptoApi.xof(mgfDigest.jceName(), Z, length);
  }

  public static PrivateKeyInfo buildPrivateKeyInfo(Asn1Oid oid, byte[] encodedSk)
      throws CodecException {
    return buildPrivateKeyInfo(new AlgorithmIdentifier(oid), encodedSk);
  }

  /**
   * <pre>
   * OneAsymmetricKey ::= SEQUENCE {
   *   version                   Version,
   *   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
   *   privateKey                PrivateKey,
   *   attributes            [0] Attributes OPTIONAL,
   *   ...,
   *   [[2: publicKey        [1] PublicKey OPTIONAL ]],
   *   ...
   * }
   * </pre>
   */
  public static PrivateKeyInfo buildPrivateKeyInfo(AlgorithmIdentifier algId, byte[] encodedSk)
      throws CodecException {
    return new PrivateKeyInfo(algId, encodedSk);
  }

  public static PrivateKey getPrivateKey(PrivateKeyInfo skInfo) throws InvalidKeySpecException {
    if (CompositeKeyInfoConverter.supportsPrivateKey(skInfo.getPrivateKeyAlgorithm())) {
      return CompositeKeyInfoConverter.generatePrivate(skInfo);
    }

    return cryptoApi.getPrivateKey(skInfo);
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo pkInfo) throws InvalidKeySpecException {
    if (CompositeKeyInfoConverter.supportsPublicKey(pkInfo.getAlgorithm())) {
      return CompositeKeyInfoConverter.generatePublic(pkInfo);
    }

    return cryptoApi.getPublicKey(pkInfo);
  }

  /**
   * Returns the algorithm OID of the encoded key (PKCS#8 for private keys, X.509 for public
   * keys). Use it instead of {@link Key#getAlgorithm()} to detect the key type: the names are
   * provider-specific, e.g. the JDK returns "EdDSA" for Ed25519 and Ed448, "XDH" for X25519 and
   * X448, and "ML-DSA" / "ML-KEM" without the parameter set.
   * @param key the key.
   * @return the algorithm OID.
   * @throws InvalidKeyException if the key is not encodable or the encoding is invalid.
   */
  public static Asn1Oid getAlgorithmOid(Key key) throws InvalidKeyException {
    byte[] encoded = Args.notNull(key, "key").getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("key is not encodable");
    }

    try {
      return (key instanceof PrivateKey)
          ? PrivateKeyInfo.algorithmFromEncoded(encoded).getAlgorithm()
          : SubjectPublicKeyInfo.algorithmFromEncoded(encoded).getAlgorithm();
    } catch (CodecException e) {
      throw new InvalidKeyException("invalid encoded key: " + e.getMessage(), e);
    }
    // encoded must not be cleared: some providers return their internal array, e.g. the
    // ML-KEM private key of BouncyCastle.
  }

  /**
   * Returns the curve of an EC (Weierstrass, Edwards or Montgomery) key, independent of the
   * name returned by {@link Key#getAlgorithm()}.
   * @param key the key.
   * @return the curve, or null if the key is not an EC key of a known curve.
   */
  public static EcCurveEnum getCurve(Key key) {
    if (key instanceof ECKey) {
      try {
        ECParameterSpec params = ((ECKey) key).getParams();
        WeierstraussCurveEnum curve = WeierstraussCurveEnum.ofOrderAndBaseX(
            params.getOrder(), params.getGenerator().getAffineX());
        return curve == null ? null : EcCurveEnum.ofOid(new Asn1Oid(curve.getOid()));
      } catch (RuntimeException e) {
        return null;
      }
    }

    try {
      return EcCurveEnum.ofOid(getAlgorithmOid(key));
    } catch (InvalidKeyException e) {
      return null;
    }
  }

  /**
   * HKDF as specified in RFC 5869.
   *
   * @param hashAlgo the hash algorithm of the HMAC.
   * @param salt the salt. If null or empty, a string of hash-length zeros is used.
   * @param ikm the input keying material.
   * @param info the context and application specific information, may be null.
   * @param outSize the length of the output keying material in bytes,
   *                at most 255 * hash-length.
   * @return the output keying material.
   */
  public static byte[] hkdf(HashAlgo hashAlgo, byte[] salt, byte[] ikm, byte[] info, int outSize) {
    int hmacSize = hashAlgo.length();
    if (outSize < 1 || outSize > 255 * hmacSize) {
      throw new IllegalArgumentException("invalid outSize: " + outSize);
    }

    String hashJceName = hashAlgo.jceName().toUpperCase(Locale.ROOT);
    String hmacAlgName = "HMAC-" + hashJceName;

    // Step 1: Extract: PRK = HMAC-Hash(salt, IKM)
    if (salt == null || salt.length == 0) {
      salt = new byte[hmacSize];
    }

    Mac mac;
    try {
      mac = cryptoApi.newMac(hmacAlgName);
      mac.init(new SecretKeySpec(salt, hmacAlgName));
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
      throw new IllegalStateException(ex);
    }

    SecretKeySpec prk = new SecretKeySpec(mac.doFinal(ikm), hmacAlgName);

    // Step 2: Expand: T(i) = HMAC-Hash(PRK, T(i-1) | info | i), i = 1..N, OKM = first L octets of
    // T(1) | T(2) | ... | T(N)
    try {
      mac.init(prk);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException(e);
    }

    byte[] okm = new byte[outSize];
    byte[] t = new byte[0];
    int off = 0;
    for (int i = 1; off < outSize; i++) {
      mac.update(t);
      if (info != null) {
        mac.update(info);
      }
      mac.update((byte) i);
      t = mac.doFinal();

      int len = Math.min(outSize - off, hmacSize);
      System.arraycopy(t, 0, okm, off, len);
      off += len;
    }
    return okm;
  }

  public static byte[] getPqcSeed(PrivateKeyInfo skInfo) throws CodecException {
    byte[] skData = skInfo.privateKey();
    return getPqcSeed(skData);
  }

  public static byte[] getPqcSeed(byte[] privateKeyData) throws CodecException {
    PqcPrivateKey sk = PqcPrivateKey.fromEncoded(privateKeyData);
    byte[] seed = sk.seed();
    if (seed == null) {
      throw new CodecException("skInfo does not contain seed");
    }

    return seed;
  }

}
