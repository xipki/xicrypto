// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

/**
 * Base of the signatures of the XiPKI provider: the message is hashed with a
 * {@link MessageDigest}, the subclass signs or verifies the hash.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class XiSignatureSpi extends SignatureSpi {

  /** the hash of the message, null until set by the subclass (e.g. by the PSS parameters). */
  protected MessageDigest digest;

  /** the random given to initSign, may be null. */
  protected SecureRandom random;

  private static final int VERIFY = 1;

  private static final int SIGN = 2;

  /** 0 (not initialized), {@link #VERIFY} or {@link #SIGN}. */
  private int mode;

  protected XiSignatureSpi(MessageDigest digest) {
    this.digest = digest;
  }

  /**
   * Returns the digest of the primitives.
   * @param primitives the source of the digest.
   * @param algorithm the name of the digest.
   * @return the digest.
   * @throws ProviderException if the digest is not available.
   */
  public static MessageDigest digest(Primitives primitives, String algorithm) {
    try {
      return primitives.messageDigest(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new ProviderException(algorithm + " not available", e);
    }
  }

  /**
   * Checks and takes the public key.
   * @param publicKey the public key.
   * @throws InvalidKeyException if the key is not supported.
   */
  protected abstract void initVerify(PublicKey publicKey) throws InvalidKeyException;

  /**
   * Checks and takes the private key.
   * @param privateKey the private key.
   * @throws InvalidKeyException if the key is not supported.
   */
  protected abstract void initSign(PrivateKey privateKey) throws InvalidKeyException;

  /**
   * Signs the hash of the message.
   * @param hash the hash of the message.
   * @return the signature.
   * @throws SignatureException if the signing failed.
   */
  protected abstract byte[] sign(byte[] hash) throws SignatureException;

  /**
   * Verifies the signature of the hash of the message.
   * @param hash the hash of the message.
   * @param sigBytes the signature.
   * @return whether the signature is valid.
   * @throws SignatureException if the verification could not be performed.
   */
  protected abstract boolean verify(byte[] hash, byte[] sigBytes) throws SignatureException;

  /**
   * Resets the digest for the next message.
   */
  protected void resetDigest() {
    if (digest != null) {
      digest.reset();
    }
  }

  /**
   * Returns the random given to initSign, or a new {@link SecureRandom} if none was given.
   * @return the random.
   */
  protected SecureRandom secureRandom() {
    if (random == null) {
      random = new SecureRandom();
    }
    return random;
  }

  @Override
  protected final void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    initVerify(publicKey);
    mode = VERIFY;
    random = null;
    resetDigest();
  }

  @Override
  protected final void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected final void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    initSign(privateKey);
    mode = SIGN;
    this.random = random;
    resetDigest();
  }

  @Override
  protected final void engineUpdate(byte b) throws SignatureException {
    checkDigest().update(b);
  }

  @Override
  protected final void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    checkDigest().update(b, off, len);
  }

  @Override
  protected final byte[] engineSign() throws SignatureException {
    if (mode != SIGN) {
      throw new SignatureException("not initialized for signing");
    }
    return sign(finishDigest());
  }

  @Override
  protected final boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (mode != VERIFY) {
      throw new SignatureException("not initialized for verification");
    }
    return verify(finishDigest(), sigBytes);
  }

  private byte[] finishDigest() throws SignatureException {
    byte[] hash = checkDigest().digest();
    resetDigest();
    return hash;
  }

  private MessageDigest checkDigest() throws SignatureException {
    if (digest == null) {
      throw new SignatureException("the parameters are not set");
    }
    return digest;
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
