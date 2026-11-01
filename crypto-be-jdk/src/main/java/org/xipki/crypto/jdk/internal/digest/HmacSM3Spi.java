// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal.digest;

import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * HMAC (RFC 2104) with SM3 ({@link SM3Digest}, block size 64 bytes, output 32 bytes), as in
 * GM/T 0042-2015. The JDK has no SM3.
 *
 * @author Lijun Liao (xipki)
 */
public class HmacSM3Spi extends MacSpi implements Cloneable {

  private static final int BLOCK_SIZE = 64;

  private MessageDigest digest = new SM3Digest();

  private byte[] ipadKey;

  private byte[] opadKey;

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

    if (k.length > BLOCK_SIZE) {
      digest.reset();
      byte[] hk = digest.digest(k);
      Arrays.fill(k, (byte) 0);
      k = hk;
    }

    byte[] ipad = new byte[BLOCK_SIZE];
    byte[] opad = new byte[BLOCK_SIZE];
    System.arraycopy(k, 0, ipad, 0, k.length);
    System.arraycopy(k, 0, opad, 0, k.length);
    Arrays.fill(k, (byte) 0);
    for (int i = 0; i < BLOCK_SIZE; i++) {
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
    HmacSM3Spi c = (HmacSM3Spi) super.clone();
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
