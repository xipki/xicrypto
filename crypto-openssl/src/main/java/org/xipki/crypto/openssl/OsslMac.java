// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Mac on EVP_MAC: HMAC with a digest, and AES-GMAC.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslMac extends MacSpi implements Cloneable {

  private static final Cleaner CLEANER = Cleaner.create();

  /** The digest of HMAC in OpenSSL, or null for GMAC. */
  private final String digest;

  private MemorySegment ctx;

  private int macLen;

  /** GMAC: the parameters of the re-initialization (cipher and IV). */
  private byte[] gmacIv;

  private String gmacCipher;

  private boolean initialized;

  /**
   * Constructor.
   * @param digest the digest of HMAC in OpenSSL (e.g. "SHA2-256"), or null for AES-GMAC.
   */
  OsslMac(String digest) {
    this.digest = digest;
    setCtx(OpenSsl.macCtxNew(digest == null ? "GMAC" : "HMAC"));
    this.macLen = (digest == null) ? 16 : OpenSsl.mdSize(OpenSsl.md(digest));
  }

  private void setCtx(MemorySegment ctx) {
    if (OpenSsl.isNull(ctx)) {
      throw new IllegalStateException("EVP_MAC_CTX_new failed: " + OpenSsl.errors());
    }
    this.ctx = ctx;
    // the action must not reference this object
    CLEANER.register(this, () -> OpenSsl.macCtxFree(ctx));
  }

  @Override
  protected int engineGetMacLength() {
    return macLen;
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (!(key instanceof SecretKey) || !"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("a raw secret key is required");
    }
    byte[] keyBytes = key.getEncoded();
    if (keyBytes == null) {
      throw new InvalidKeyException("the key has no encoding");
    }

    try {
      OsslParams p;
      if (digest != null) {
        if (params != null) {
          throw new InvalidAlgorithmParameterException("HMAC has no parameters");
        }
        p = new OsslParams().utf8("digest", digest);
      } else {
        if (!(params instanceof GCMParameterSpec gcm)) {
          throw new InvalidAlgorithmParameterException("GCMParameterSpec is required");
        }
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
          throw new InvalidKeyException("invalid AES key length " + keyBytes.length);
        }
        if (gcm.getTLen() % 8 != 0 || gcm.getTLen() < 96 || gcm.getTLen() > 128) {
          throw new InvalidAlgorithmParameterException("unsupported tag length "
              + gcm.getTLen());
        }
        gmacCipher = "AES-" + (keyBytes.length * 8) + "-GCM";
        gmacIv = gcm.getIV();
        macLen = gcm.getTLen() / 8;
        p = gmacParams();
      }

      if (!OpenSsl.macInit(ctx, keyBytes, p)) {
        throw new InvalidKeyException("initializing the MAC failed: " + OpenSsl.errors());
      }
      initialized = true;
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
      Reference.reachabilityFence(this);
    }
  }

  private OsslParams gmacParams() {
    return new OsslParams().utf8("cipher", gmacCipher).octets("iv", gmacIv);
  }

  private void checkInitialized() {
    if (!initialized) {
      throw new IllegalStateException("not initialized");
    }
  }

  @Override
  protected void engineUpdate(byte input) {
    engineUpdate(new byte[]{input}, 0, 1);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    checkInitialized();
    try {
      if (!OpenSsl.macUpdate(ctx, MemorySegment.ofArray(input).asSlice(offset, len))) {
        throw new IllegalStateException("EVP_MAC_update failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  protected byte[] engineDoFinal() {
    checkInitialized();
    try {
      // GMAC: the tag is 16 bytes, truncated to the tag length
      int fullLen = (digest == null) ? 16 : macLen;
      byte[] out = new byte[fullLen];
      if (!OpenSsl.macFinal(ctx, MemorySegment.ofArray(out))) {
        throw new IllegalStateException("EVP_MAC_final failed: " + OpenSsl.errors());
      }
      return (fullLen == macLen) ? out : Arrays.copyOf(out, macLen);
    } finally {
      engineReset();
    }
  }

  /** Re-initializes with the same key (and for GMAC the same IV). */
  @Override
  protected void engineReset() {
    if (!initialized) {
      return;
    }
    try {
      if (!OpenSsl.macInit(ctx, null, (digest == null) ? gmacParams() : null)) {
        throw new IllegalStateException("resetting the MAC failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    OsslMac copy = (OsslMac) super.clone();
    try {
      copy.setCtx(OpenSsl.macCtxDup(ctx));
    } catch (IllegalStateException e) {
      throw new CloneNotSupportedException(e.getMessage());
    } finally {
      Reference.reachabilityFence(this);
    }
    return copy;
  }

}
