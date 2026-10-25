// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.util.Arrays;
import org.xipki.codec.exception.CodecException;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Locale;

/**
 * ML-DSA signature (FIPS 204) with support of the context string.
 * <p>
 * Without context, the signature of the JDK is used. With a non-empty context, the message
 * is formatted as M' = 0 || len(ctx) || ctx || M and signed or verified with
 * ML-DSA.Sign_internal or ML-DSA.Verify_internal of the JDK, see {@link JdkInternals.Mldsa}.
 * The context is set with {@link #setContext(byte[])} before or after the initialization, and
 * is kept until it is changed. {@link #getProvider()} returns null.
 *
 * @author Lijun Liao (xipki)
 */
final class MldsaSignature extends Signature {

  private static final byte[] EMPTY = new byte[0];

  private final Signature jdkSignature;

  /**
   * The parameter set required by the algorithm name, null if any is accepted.
   */
  private final String requiredParamSet;

  private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

  private byte[] context = EMPTY;

  private PrivateKey privateKey;

  private PublicKey publicKey;

  private SecureRandom random;

  private String paramSet;

  private byte[] expandedSk;

  private byte[] rawPk;

  MldsaSignature(String algorithm, Signature jdkSignature) {
    super(algorithm);
    this.jdkSignature = jdkSignature;
    this.requiredParamSet = requiredParamSet(algorithm);
  }

  /**
   * Returns whether the algorithm is ML-DSA, without pre-hash.
   * @param algorithm the algorithm name or OID.
   * @return whether the algorithm is ML-DSA.
   */
  static boolean isMldsa(String algorithm) {
    String upper = algorithm.toUpperCase(Locale.ROOT);
    return upper.equals("ML-DSA") || requiredParamSet(algorithm) != null;
  }

  private static String requiredParamSet(String algorithm) {
    String upper = algorithm.toUpperCase(Locale.ROOT);
    if (upper.equals("ML-DSA-44") || upper.equals(NistOIDs.id_ml_dsa_44.getId())) {
      return "ML-DSA-44";
    } else if (upper.equals("ML-DSA-65") || upper.equals(NistOIDs.id_ml_dsa_65.getId())) {
      return "ML-DSA-65";
    } else if (upper.equals("ML-DSA-87") || upper.equals(NistOIDs.id_ml_dsa_87.getId())) {
      return "ML-DSA-87";
    } else {
      return null;
    }
  }

  private static String paramSet(Asn1Oid oid) {
    return NistOIDs.id_ml_dsa_44.equals(oid) ? "ML-DSA-44"
        : NistOIDs.id_ml_dsa_65.equals(oid) ? "ML-DSA-65"
        : NistOIDs.id_ml_dsa_87.equals(oid) ? "ML-DSA-87"
        : null;
  }

  private static int level(String paramSet) {
    return paramSet.endsWith("44") ? 2 : paramSet.endsWith("65") ? 3 : 5;
  }

  /**
   * Sets the context string.
   * @param context the context, at most 255 bytes. Null or empty means no context.
   * @throws InvalidAlgorithmParameterException if the context is too long, or a non-empty
   *         context is not supported in this JVM.
   */
  void setContext(byte[] context) throws InvalidAlgorithmParameterException {
    if (context == null || context.length == 0) {
      this.context = EMPTY;
      return;
    }

    if (context.length > 255) {
      throw new InvalidAlgorithmParameterException(
          "context too long: " + context.length + " > 255");
    }

    String reason = JdkInternals.Mldsa.unavailableReason();
    if (reason != null) {
      throw new InvalidAlgorithmParameterException(
          "ML-DSA with context is not supported: " + reason);
    }

    this.context = context.clone();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    String ps = checkKey(privateKey);
    // initialize the JDK signature to detect invalid keys early
    if (random == null) {
      jdkSignature.initSign(privateKey);
    } else {
      jdkSignature.initSign(privateKey, random);
    }

    clearKeys();
    this.privateKey = privateKey;
    this.random = random;
    this.paramSet = ps;
    buffer.reset();
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    String ps = checkKey(publicKey);
    jdkSignature.initVerify(publicKey);

    clearKeys();
    this.publicKey = publicKey;
    this.paramSet = ps;
    buffer.reset();
  }

  private String checkKey(Key key) throws InvalidKeyException {
    if (key == null) {
      throw new InvalidKeyException("key must not be null");
    }

    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("key is not encodable");
    }

    Asn1Oid oid;
    try {
      oid = (key instanceof PrivateKey)
          ? PrivateKeyInfo.algorithmFromEncoded(encoded).getAlgorithm()
          : SubjectPublicKeyInfo.algorithmFromEncoded(encoded).getAlgorithm();
    } catch (CodecException e) {
      throw new InvalidKeyException("invalid ML-DSA key: " + e.getMessage(), e);
    }
    // encoded must not be cleared: some providers return their internal array.

    String ps = paramSet(oid);
    if (ps == null) {
      throw new InvalidKeyException("not an ML-DSA key: " + oid.getId());
    }

    if (requiredParamSet != null && !requiredParamSet.equals(ps)) {
      throw new InvalidKeyException("key is " + ps + ", but " + requiredParamSet
          + " is required");
    }
    return ps;
  }

  private byte[] expandedSk() throws SignatureException {
    if (expandedSk != null) {
      return expandedSk;
    }

    byte[] encoded = privateKey.getEncoded();
    try {
      MldsaPrivateKey sk = MldsaPrivateKey.fromEncoded(
          PrivateKeyInfo.fromEncoded(encoded).privateKey());
      byte[] expanded = sk.expandedKey();
      expandedSk = (expanded != null) ? expanded.clone()
          : JdkInternals.Mldsa.seedToExpanded(paramSet, sk.seed());
      return expandedSk;
    } catch (CodecException e) {
      throw new SignatureException("invalid ML-DSA private key: " + e.getMessage(), e);
    }
    // encoded must not be cleared: some providers return their internal array.
  }

  private byte[] rawPk() throws SignatureException {
    if (rawPk == null) {
      try {
        rawPk = SubjectPublicKeyInfo.fromEncoded(publicKey.getEncoded()).subjectPublicKey();
      } catch (CodecException e) {
        throw new SignatureException("invalid ML-DSA public key: " + e.getMessage(), e);
      }
    }
    return rawPk;
  }

  private void clearKeys() {
    if (expandedSk != null) {
      Arrays.clear(expandedSk);
      expandedSk = null;
    }
    rawPk = null;
    privateKey = null;
    publicKey = null;
    random = null;
  }

  @Override
  protected void engineUpdate(byte b) {
    buffer.write(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    buffer.write(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (privateKey == null) {
      throw new SignatureException("not initialized for signing");
    }

    byte[] message = buffer.toByteArray();
    buffer.reset();

    if (context.length == 0) {
      jdkSignature.update(message);
      return jdkSignature.sign();
    }

    byte[] rnd = new byte[32];
    (random != null ? random : new SecureRandom()).nextBytes(rnd);
    byte[] mPrime = formatMessage(message);
    try {
      return JdkInternals.Mldsa.signInternal(level(paramSet), expandedSk(), mPrime, rnd);
    } finally {
      Arrays.clear(rnd);
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (publicKey == null) {
      throw new SignatureException("not initialized for verification");
    }

    byte[] message = buffer.toByteArray();
    buffer.reset();

    if (context.length == 0) {
      jdkSignature.update(message);
      return jdkSignature.verify(sigBytes);
    }

    return JdkInternals.Mldsa.verifyInternal(level(paramSet), rawPk(),
        formatMessage(message), sigBytes);
  }

  /**
   * FIPS 204 Algorithms 2 and 3: M' = 0 || len(ctx) || ctx || M.
   */
  private byte[] formatMessage(byte[] message) {
    byte[] mPrime = new byte[2 + context.length + message.length];
    mPrime[1] = (byte) context.length;
    System.arraycopy(context, 0, mPrime, 2, context.length);
    System.arraycopy(message, 0, mPrime, 2 + context.length, message.length);
    return mPrime;
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    throw new InvalidAlgorithmParameterException(
        "parameters are not supported, use CryptoApi.setContext() for the context");
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
