// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * KeyAgreement on EVP_PKEY_derive: ECDH, X25519 and X448.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslKeyAgreement extends KeyAgreementSpi {

  private final String[] keyTypes;

  private NativeKey privateKey;

  private byte[] secret;

  /**
   * Constructor.
   * @param keyTypes the allowed key types in OpenSSL, e.g. "EC".
   */
  OsslKeyAgreement(String... keyTypes) {
    this.keyTypes = keyTypes;
  }

  @Override
  protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
    if (!(key instanceof PrivateKey)) {
      throw new InvalidKeyException("a private key is required");
    }
    privateKey = NativeKey.of(key, keyTypes);
    clearSecret();
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      throw new InvalidAlgorithmParameterException("parameters are not supported");
    }
    engineInit(key, random);
  }

  @Override
  protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
    if (privateKey == null) {
      throw new IllegalStateException("not initialized");
    }
    if (!lastPhase) {
      throw new IllegalStateException("only two parties are supported");
    }
    if (!(key instanceof PublicKey)) {
      throw new InvalidKeyException("a public key is required");
    }

    NativeKey peer = NativeKey.of(key, keyTypes);
    byte[] z = privateKey.apply(sk -> peer.apply(pk -> OpenSsl.derive(sk, pk)));
    if (z == null) {
      throw new InvalidKeyException("key agreement failed: " + OpenSsl.errors());
    }
    clearSecret();
    secret = z;
    return null;
  }

  @Override
  protected byte[] engineGenerateSecret() {
    if (secret == null) {
      throw new IllegalStateException("doPhase has not been called");
    }
    byte[] z = secret;
    secret = null;
    return z;
  }

  @Override
  protected int engineGenerateSecret(byte[] sharedSecret, int offset)
      throws ShortBufferException {
    if (secret == null) {
      throw new IllegalStateException("doPhase has not been called");
    }
    if (sharedSecret.length - offset < secret.length) {
      throw new ShortBufferException("buffer too short");
    }
    byte[] z = engineGenerateSecret();
    System.arraycopy(z, 0, sharedSecret, offset, z.length);
    Arrays.fill(z, (byte) 0);
    return z.length;
  }

  @Override
  protected SecretKey engineGenerateSecret(String algorithm) {
    byte[] z = engineGenerateSecret();
    try {
      return new SecretKeySpec(z, algorithm);
    } finally {
      Arrays.fill(z, (byte) 0);
    }
  }

  private void clearSecret() {
    if (secret != null) {
      Arrays.fill(secret, (byte) 0);
      secret = null;
    }
  }

}
