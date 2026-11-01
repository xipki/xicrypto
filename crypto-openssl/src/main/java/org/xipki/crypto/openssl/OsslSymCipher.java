// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Symmetric cipher on EVP_CIPHER_CTX: AES (CBC, ECB, CTR, GCM, key wrap with and without
 * padding) and DESede (CBC). The IVs generated for the encryption come from the DRBG of
 * OpenSSL.
 * <p>
 * GCM: the ciphertext is returned at doFinal together with the tag; at decryption, the
 * plaintext is returned only after the tag is verified. An encryption must be initialized with
 * a new IV after doFinal.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslSymCipher extends CipherSpi {

  private static final Cleaner CLEANER = Cleaner.create();

  /** The family: "AES" or "DES-EDE3". */
  private final String family;

  /** The mode: "CBC", "ECB", "CTR", "GCM", "WRAP" or "WRAP-PAD". */
  private final String mode;

  private final boolean padding;

  private final int blockSize;

  private final MemorySegment ctx;

  private boolean encrypt;

  private byte[] iv;

  private int tagLen;

  private boolean initialized;

  /** GCM after the encryption: a new IV is required. */
  private boolean needsNewIv;

  /** GCM (decryption) and key wrap: the input is collected until doFinal. */
  private final ByteArrayOutputStream buffered = new ByteArrayOutputStream();

  /**
   * Constructor.
   * @param family "AES" or "DES-EDE3".
   * @param mode "CBC", "ECB", "CTR", "GCM", "WRAP" or "WRAP-PAD".
   * @param padding whether PKCS#5 padding is used (CBC and ECB).
   */
  OsslSymCipher(String family, String mode, boolean padding) {
    this.family = family;
    this.mode = mode;
    this.padding = padding;
    this.blockSize = "AES".equals(family) ? 16 : 8;
    MemorySegment c = OpenSsl.cipherCtxNew();
    this.ctx = c;
    // the action must not reference this object
    CLEANER.register(this, () -> OpenSsl.cipherCtxFree(c));
  }

  private boolean isGcm() {
    return "GCM".equals(mode);
  }

  private boolean isWrap() {
    return mode.startsWith("WRAP");
  }

  /** Returns whether the input is collected until doFinal. */
  private boolean isBuffered() {
    return isWrap() || (isGcm() && !encrypt);
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    throw new NoSuchAlgorithmException("the mode is fixed: " + this.mode);
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("the padding is fixed");
  }

  @Override
  protected int engineGetBlockSize() {
    return blockSize;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    int n = buffered.size() + inputLen;
    if (isGcm()) {
      return encrypt ? n + tagLen : Math.max(0, n - tagLen);
    }
    return n + blockSize + 8;
  }

  @Override
  protected byte[] engineGetIV() {
    return iv == null ? null : iv.clone();
  }

  /** The parameters are available with {@link #engineGetIV()}. */
  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected int engineGetKeySize(Key key) throws InvalidKeyException {
    return rawKey(key).length * 8;
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random)
      throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                            SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    AlgorithmParameterSpec spec = null;
    if (params != null) {
      try {
        spec = isGcm() ? params.getParameterSpec(GCMParameterSpec.class)
            : params.getParameterSpec(IvParameterSpec.class);
      } catch (InvalidParameterSpecException e) {
        throw new InvalidAlgorithmParameterException(e.getMessage(), e);
      }
    }
    engineInit(opmode, key, spec, random);
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
                            SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    boolean enc = opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE;
    byte[] keyBytes = rawKey(key);
    try {
      MemorySegment cipher = OpenSsl.cipher(cipherName(keyBytes.length));
      if (OpenSsl.isNull(cipher)) {
        throw new InvalidKeyException("unsupported key length " + keyBytes.length);
      }

      byte[] newIv = null;
      int newTagLen = 0;
      if (isGcm()) {
        if (params instanceof GCMParameterSpec gcm) {
          newIv = gcm.getIV();
          newTagLen = gcm.getTLen() / 8;
          if (newTagLen < 12 || newTagLen > 16 || gcm.getTLen() % 8 != 0) {
            throw new InvalidAlgorithmParameterException("unsupported tag length "
                + gcm.getTLen());
          }
        } else if (params == null && enc) {
          newIv = new byte[12];
          OpenSsl.randomBytes(newIv, false);
          newTagLen = 16;
        } else {
          throw new InvalidAlgorithmParameterException("GCMParameterSpec is required");
        }
        if (newIv.length == 0) {
          throw new InvalidAlgorithmParameterException("empty IV");
        }
      } else if ("CBC".equals(mode) || "CTR".equals(mode)) {
        if (params instanceof IvParameterSpec ivSpec) {
          newIv = ivSpec.getIV();
        } else if (params == null && enc) {
          newIv = new byte[blockSize];
          OpenSsl.randomBytes(newIv, false);
        } else {
          throw new InvalidAlgorithmParameterException("IvParameterSpec is required");
        }
        if (newIv.length != blockSize) {
          throw new InvalidAlgorithmParameterException("IV must be " + blockSize + " bytes");
        }
      } else if (params != null) {
        throw new InvalidAlgorithmParameterException("parameters are not supported");
      }

      boolean ok;
      if (isGcm() && newIv.length != 12) {
        // the IV length must be set before the IV
        ok = OpenSsl.cipherInit(ctx, cipher, keyBytes, null, enc ? 1 : 0,
                new OsslParams().integer("ivlen", newIv.length))
            && OpenSsl.cipherInit(ctx, MemorySegment.NULL, null, newIv, -1, null);
      } else {
        ok = OpenSsl.cipherInit(ctx, cipher, keyBytes, newIv, enc ? 1 : 0, null);
      }
      if (!ok || (("CBC".equals(mode) || "ECB".equals(mode))
          && !OpenSsl.cipherSetPadding(ctx, padding))) {
        throw new InvalidKeyException("initializing the cipher failed: " + OpenSsl.errors());
      }

      this.encrypt = enc;
      this.iv = newIv;
      this.tagLen = newTagLen;
      this.initialized = true;
      this.needsNewIv = false;
      buffered.reset();
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
      Reference.reachabilityFence(this);
    }
  }

  private String cipherName(int keyLen) throws InvalidKeyException {
    if ("DES-EDE3".equals(family)) {
      if (keyLen != 24) {
        throw new InvalidKeyException("DESede key must be 24 bytes");
      }
      return "ECB".equals(mode) ? "DES-EDE3-ECB" : "DES-EDE3-" + mode;
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
      throw new InvalidKeyException("invalid AES key length " + keyLen);
    }
    return "AES-" + (keyLen * 8) + "-" + mode;
  }

  private static byte[] rawKey(Key key) throws InvalidKeyException {
    if (!(key instanceof SecretKey) || !"RAW".equalsIgnoreCase(key.getFormat())) {
      throw new InvalidKeyException("a raw secret key is required");
    }
    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("the key has no encoding");
    }
    return encoded;
  }

  private void checkState() {
    if (!initialized) {
      throw new IllegalStateException("not initialized");
    }
    if (needsNewIv) {
      throw new IllegalStateException("GCM encryption: initialize with a new IV");
    }
  }

  @Override
  protected void engineUpdateAAD(byte[] src, int offset, int len) {
    checkState();
    if (!isGcm()) {
      throw new IllegalStateException("AAD is only supported by GCM");
    }
    try {
      if (OpenSsl.cipherUpdate(ctx, MemorySegment.NULL,
          MemorySegment.ofArray(src).asSlice(offset, len)) < 0) {
        throw new IllegalStateException("updating the AAD failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    checkState();
    if (isBuffered()) {
      buffered.write(input, inputOffset, inputLen);
      return new byte[0];
    }
    byte[] out = new byte[inputLen + blockSize];
    int n = update(input, inputOffset, inputLen, out, 0);
    return (n == out.length) ? out : Arrays.copyOf(out, n);
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
                             int outputOffset) throws ShortBufferException {
    byte[] out = engineUpdate(input, inputOffset, inputLen);
    if (output.length - outputOffset < out.length) {
      throw new ShortBufferException("output buffer too short");
    }
    System.arraycopy(out, 0, output, outputOffset, out.length);
    return out.length;
  }

  private int update(byte[] in, int inOff, int inLen, byte[] out, int outOff) {
    if (inLen == 0) {
      return 0;
    }
    try {
      int n = OpenSsl.cipherUpdate(ctx, MemorySegment.ofArray(out).asSlice(outOff),
          MemorySegment.ofArray(in).asSlice(inOff, inLen));
      if (n < 0) {
        throw new IllegalStateException("EVP_CipherUpdate failed: " + OpenSsl.errors());
      }
      return n;
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    checkState();
    try {
      if (isGcm()) {
        return encrypt ? gcmEncryptFinal(input, inputOffset, inputLen)
            : gcmDecryptFinal(input, inputOffset, inputLen);
      }

      byte[] in;
      int inOff;
      int inLen;
      if (isWrap()) {
        buffered.write(input == null ? new byte[0] : input, inputOffset, inputLen);
        in = buffered.toByteArray();
        inOff = 0;
        inLen = in.length;
      } else {
        in = (input == null) ? new byte[0] : input;
        inOff = inputOffset;
        inLen = inputLen;
      }

      byte[] out = new byte[inLen + 2 * blockSize + 8];
      int n = update(in, inOff, inLen, out, 0);
      int m = OpenSsl.cipherFinal(ctx, MemorySegment.ofArray(out).asSlice(n));
      if (m < 0) {
        String err = OpenSsl.errors();
        if (!encrypt && (padding || isWrap())) {
          throw new BadPaddingException("decryption failed: " + err);
        }
        throw new IllegalBlockSizeException("input length not a multiple of the block size: "
            + err);
      }
      return Arrays.copyOf(out, n + m);
    } finally {
      buffered.reset();
      if (!(isGcm() && encrypt)) {
        resetCtx();
      }
      Reference.reachabilityFence(this);
    }
  }

  private byte[] gcmEncryptFinal(byte[] input, int inputOffset, int inputLen) {
    needsNewIv = true;
    byte[] out = new byte[inputLen + 16 + tagLen];
    int n = (input == null) ? 0 : update(input, inputOffset, inputLen, out, 0);
    int m = OpenSsl.cipherFinal(ctx, MemorySegment.ofArray(out).asSlice(n));
    byte[] tag = (m < 0) ? null : OpenSsl.cipherGetOctets(ctx, "tag", tagLen);
    if (tag == null) {
      throw new IllegalStateException("GCM encryption failed: " + OpenSsl.errors());
    }
    System.arraycopy(tag, 0, out, n + m, tagLen);
    return Arrays.copyOf(out, n + m + tagLen);
  }

  private byte[] gcmDecryptFinal(byte[] input, int inputOffset, int inputLen)
      throws AEADBadTagException {
    if (input != null) {
      buffered.write(input, inputOffset, inputLen);
    }
    byte[] data = buffered.toByteArray();
    if (data.length < tagLen) {
      throw new AEADBadTagException("input shorter than the tag");
    }

    int ctLen = data.length - tagLen;
    byte[] tag = Arrays.copyOfRange(data, ctLen, data.length);
    if (!OpenSsl.cipherSetParams(ctx, new OsslParams().octets("tag", tag))) {
      throw new IllegalStateException("setting the tag failed: " + OpenSsl.errors());
    }

    byte[] out = new byte[ctLen + 16];
    int n = update(data, 0, ctLen, out, 0);
    int m = OpenSsl.cipherFinal(ctx, MemorySegment.ofArray(out).asSlice(n));
    if (m < 0) {
      OpenSsl.clearErrors();
      Arrays.fill(out, (byte) 0);
      throw new AEADBadTagException("tag mismatch");
    }
    return Arrays.copyOf(out, n + m);
  }

  /** Re-initializes the context with the same key and IV, as required by JCA after doFinal. */
  private void resetCtx() {
    if (!OpenSsl.cipherInit(ctx, MemorySegment.NULL, null, iv, -1, null)) {
      OpenSsl.clearErrors();
      initialized = false;
    }
  }

  @Override
  protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                              int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] out = engineDoFinal(input, inputOffset, inputLen);
    if (output.length - outputOffset < out.length) {
      throw new ShortBufferException("output buffer too short");
    }
    System.arraycopy(out, 0, output, outputOffset, out.length);
    return out.length;
  }

  @Override
  protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("the key has no encoding");
    }
    try {
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (BadPaddingException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

  @Override
  protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                             int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    byte[] encoded;
    try {
      encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidKeyException("unwrapping failed: " + e.getMessage(), e);
    }
    return toKey(encoded, wrappedKeyAlgorithm, wrappedKeyType);
  }

  /** Returns the unwrapped key: the private and public keys are those of OpenSSL. */
  static Key toKey(byte[] encoded, String algorithm, int keyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    try {
      if (keyType == Cipher.SECRET_KEY) {
        return new SecretKeySpec(encoded, algorithm);
      }
      KeyFactory kf = KeyFactory.getInstance(algorithm, OpensslCryptoApi.provider());
      return (keyType == Cipher.PRIVATE_KEY)
          ? kf.generatePrivate(new PKCS8EncodedKeySpec(encoded))
          : kf.generatePublic(new X509EncodedKeySpec(encoded));
    } catch (InvalidKeySpecException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    } finally {
      Arrays.fill(encoded, (byte) 0);
    }
  }

}
