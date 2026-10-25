// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import javax.crypto.Cipher;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Mac AES-GMAC (NIST SP 800-38D): the GCM tag over the data as additional authenticated data,
 * without plaintext. Computed with AES/GCM/NoPadding of the {@link Primitives}.
 * <p>
 * The nonce is given as {@link GCMParameterSpec} (with the tag length) or
 * {@link IvParameterSpec} (tag length 128 bits).
 *
 * @author Lijun Liao (xipki)
 */
public class AesGmacSpi extends MacSpi {

  private final Primitives primitives;

  private final ByteArrayOutputStream data = new ByteArrayOutputStream();

  private SecretKey key;

  private GCMParameterSpec gcmSpec;

  public AesGmacSpi(Primitives primitives) {
    this.primitives = primitives;
  }

  @Override
  protected int engineGetMacLength() {
    return (gcmSpec == null) ? 16 : gcmSpec.getTLen() / 8;
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (key == null || key.getEncoded() == null) {
      throw new InvalidKeyException("key is null or has no encoding");
    }

    int keyLen = key.getEncoded().length;
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
      throw new InvalidKeyException("invalid AES key length " + keyLen);
    }

    if (params instanceof GCMParameterSpec) {
      this.gcmSpec = (GCMParameterSpec) params;
    } else if (params instanceof IvParameterSpec) {
      this.gcmSpec = new GCMParameterSpec(128, ((IvParameterSpec) params).getIV());
    } else {
      throw new InvalidAlgorithmParameterException(
          "AES-GMAC requires a GCMParameterSpec or IvParameterSpec with the nonce");
    }

    this.key = new SecretKeySpec(key.getEncoded(), "AES");
    data.reset();
  }

  @Override
  protected void engineUpdate(byte input) {
    data.write(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    data.write(input, offset, len);
  }

  @Override
  protected byte[] engineDoFinal() {
    if (key == null) {
      throw new IllegalStateException("not initialized");
    }

    try {
      // a new cipher per computation: the GCM implementations refuse to reuse key and nonce
      // in the same instance, while a MAC with the same key and nonce is legitimate (e.g. to
      // verify).
      Cipher cipher = primitives.cipher("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
      cipher.updateAAD(data.toByteArray());
      return cipher.doFinal();
    } catch (GeneralSecurityException e) {
      throw new ProviderException("could not compute AES-GMAC: " + e.getMessage(), e);
    } finally {
      data.reset();
    }
  }

  @Override
  protected void engineReset() {
    data.reset();
  }

}
