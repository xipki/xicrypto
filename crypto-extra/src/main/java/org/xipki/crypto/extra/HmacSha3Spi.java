// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * HMAC (RFC 2104) with SHA3-224, SHA3-256, SHA3-384 or SHA3-512 over the {@link MessageDigest}
 * of the {@link Primitives}. The block size is the rate of the SHA3 function (FIPS 202): 144,
 * 136, 104 and 72 bytes.
 * <p>
 * For the JDKs without HmacSHA3 (JDK 11 to 15), which have the SHA3 digests (JDK 9+). Also used
 * by the deterministic nonce (RFC 6979) of ECDSA with SHA3, see {@link Primitives#mac(String)}.
 *
 * @author Lijun Liao (xipki)
 */
public class HmacSha3Spi extends MacSpi implements Cloneable {

  private MessageDigest digest;

  private final int blockSize;

  private byte[] ipadKey;

  private byte[] opadKey;

  /**
   * Constructor.
   * @param primitives the source of the SHA3 digest.
   * @param bits 224, 256, 384 or 512.
   */
  public HmacSha3Spi(Primitives primitives, int bits) {
    try {
      this.digest = primitives.messageDigest("SHA3-" + bits);
    } catch (NoSuchAlgorithmException e) {
      throw new ProviderException("SHA3-" + bits + " not available", e);
    }
    this.blockSize = 200 - 2 * (bits / 8);
  }

  @Override
  protected int engineGetMacLength() {
    return digest.getDigestLength();
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      throw new InvalidAlgorithmParameterException("HMAC does not take parameters");
    }
    byte[] k = (key == null) ? null : key.getEncoded();
    if (k == null) {
      throw new InvalidKeyException("missing key value");
    }

    if (k.length > blockSize) {
      digest.reset();
      byte[] hk = digest.digest(k);
      Arrays.fill(k, (byte) 0);
      k = hk;
    }

    byte[] ipad = new byte[blockSize];
    byte[] opad = new byte[blockSize];
    System.arraycopy(k, 0, ipad, 0, k.length);
    System.arraycopy(k, 0, opad, 0, k.length);
    Arrays.fill(k, (byte) 0);
    for (int i = 0; i < blockSize; i++) {
      ipad[i] ^= 0x36;
      opad[i] ^= 0x5c;
    }

    clearKeys();
    this.ipadKey = ipad;
    this.opadKey = opad;
    engineReset();
  }

  @Override
  protected void engineUpdate(byte input) {
    checkInit();
    digest.update(input);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    checkInit();
    digest.update(input, offset, len);
  }

  @Override
  protected byte[] engineDoFinal() {
    checkInit();
    byte[] inner = digest.digest();
    digest.update(opadKey);
    digest.update(inner);
    byte[] mac = digest.digest();
    // ready for the next MAC with the same key
    digest.update(ipadKey);
    return mac;
  }

  @Override
  protected void engineReset() {
    digest.reset();
    if (ipadKey != null) {
      digest.update(ipadKey);
    }
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    HmacSha3Spi c = (HmacSha3Spi) super.clone();
    c.digest = (MessageDigest) digest.clone();
    c.ipadKey = (ipadKey == null) ? null : ipadKey.clone();
    c.opadKey = (opadKey == null) ? null : opadKey.clone();
    return c;
  }

  private void checkInit() {
    if (ipadKey == null) {
      throw new IllegalStateException("MAC not initialized");
    }
  }

  private void clearKeys() {
    if (ipadKey != null) {
      Arrays.fill(ipadKey, (byte) 0);
      Arrays.fill(opadKey, (byte) 0);
    }
  }

}
