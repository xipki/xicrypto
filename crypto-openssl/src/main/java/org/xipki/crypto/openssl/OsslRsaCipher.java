// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

/**
 * RSA cipher on OpenSSL: PKCS#1 v1.5, OAEP (by default SHA-1 and MGF1 with SHA-1, otherwise as
 * set by {@link OAEPParameterSpec}), and without padding.
 * <p>
 * As in JCA, the encryption with the private key is the signature primitive (PKCS#1 v1.5 type
 * 1 padding, or none), and the decryption with the public key its inverse.
 * <p>
 * The decryption with PKCS#1 v1.5 padding uses the implicit rejection of OpenSSL (protection
 * against Bleichenbacher-style attacks such as Marvin): an invalid padding results in a random
 * output instead of a {@link BadPaddingException}.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslRsaCipher extends CipherSpi {

  /** The padding: "pkcs1", "oaep" or "none". */
  private final String padding;

  private NativeKey key;

  private int opmode;

  private OsslParams oaepParams;

  private final ByteArrayOutputStream buffered = new ByteArrayOutputStream();

  /**
   * Constructor.
   * @param padding "pkcs1", "oaep" or "none".
   */
  OsslRsaCipher(String padding) {
    this.padding = padding;
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (!"ECB".equalsIgnoreCase(mode) && !"NONE".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException("unsupported mode " + mode);
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("the padding is fixed");
  }

  @Override
  protected int engineGetBlockSize() {
    return 0;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    return (key == null) ? 0 : key.maxSigLen();
  }

  @Override
  protected byte[] engineGetIV() {
    return null;
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected int engineGetKeySize(Key key) throws InvalidKeyException {
    return NativeKey.of(key, "RSA", "RSA-PSS").apply(OpenSsl::pkeyBits);
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
        spec = params.getParameterSpec(OAEPParameterSpec.class);
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
    if (!(key instanceof PublicKey) && !(key instanceof PrivateKey)) {
      throw new InvalidKeyException("an RSA public or private key is required");
    }

    OsslParams oaep = null;
    if ("oaep".equals(padding)) {
      OAEPParameterSpec spec;
      if (params == null) {
        spec = OAEPParameterSpec.DEFAULT;
      } else if (params instanceof OAEPParameterSpec o) {
        spec = o;
      } else {
        throw new InvalidAlgorithmParameterException("OAEPParameterSpec is required");
      }

      if (!"MGF1".equalsIgnoreCase(spec.getMGFAlgorithm())
          || !(spec.getMGFParameters() instanceof MGF1ParameterSpec mgf)) {
        throw new InvalidAlgorithmParameterException("only MGF1 is supported");
      }
      String md = OsslNames.digest(spec.getDigestAlgorithm());
      String mgfMd = OsslNames.digest(mgf.getDigestAlgorithm());
      if (md == null || mgfMd == null) {
        throw new InvalidAlgorithmParameterException("unsupported digest");
      }
      oaep = new OsslParams().utf8("pad-mode", "oaep").utf8("digest", md)
          .utf8("mgf1-digest", mgfMd);
      if (spec.getPSource() instanceof PSource.PSpecified p && p.getValue().length > 0) {
        oaep.octets("oaep-label", p.getValue());
      }
    } else if (params != null) {
      throw new InvalidAlgorithmParameterException("parameters are not supported");
    }

    boolean isPrivate = key instanceof PrivateKey;
    if ("oaep".equals(padding) && isPrivate
        != (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)) {
      throw new InvalidKeyException("OAEP: encryption with the public key, decryption with "
          + "the private key");
    }

    this.key = NativeKey.of(key, "RSA", "RSA-PSS");
    this.opmode = opmode;
    this.oaepParams = oaep;
    buffered.reset();
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    buffered.write(input, inputOffset, inputLen);
    return new byte[0];
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
                             int outputOffset) {
    engineUpdate(input, inputOffset, inputLen);
    return 0;
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    if (key == null) {
      throw new IllegalStateException("not initialized");
    }
    if (input != null) {
      buffered.write(input, inputOffset, inputLen);
    }
    byte[] in = buffered.toByteArray();
    buffered.reset();

    boolean enc = opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE;
    int k = key.maxSigLen();
    if (in.length > k) {
      throw new IllegalBlockSizeException("input longer than " + k + " bytes");
    }

    OpenSsl.PkeyOp op;
    OsslParams params;
    if ("none".equals(padding)) {
      // the raw RSA operation, the input as integer of k bytes
      if (in.length < k) {
        byte[] padded = new byte[k];
        System.arraycopy(in, 0, padded, k - in.length, in.length);
        Arrays.fill(in, (byte) 0);
        in = padded;
      }
      op = key.isPrivate() ? OpenSsl.PkeyOp.DECRYPT : OpenSsl.PkeyOp.ENCRYPT;
      params = new OsslParams().utf8("pad-mode", "none");
    } else if ("oaep".equals(padding)) {
      op = enc ? OpenSsl.PkeyOp.ENCRYPT : OpenSsl.PkeyOp.DECRYPT;
      params = oaepParams;
    } else {
      // PKCS#1 v1.5: encryption (type 2) with the public key, signature (type 1) with the
      // private key
      if (enc) {
        op = key.isPrivate() ? OpenSsl.PkeyOp.SIGN : OpenSsl.PkeyOp.ENCRYPT;
      } else {
        op = key.isPrivate() ? OpenSsl.PkeyOp.DECRYPT : OpenSsl.PkeyOp.VERIFY_RECOVER;
      }
      params = new OsslParams().utf8("pad-mode", "pkcs1");
    }

    byte[] data = in;
    try {
      byte[] out = key.apply(pkey -> OpenSsl.pkeyOp(op, pkey, params, data));
      if (out == null) {
        String err = OpenSsl.errors();
        if (enc) {
          throw new IllegalBlockSizeException("RSA operation failed: " + err);
        }
        throw new BadPaddingException("RSA decryption failed: " + err);
      }
      return out;
    } finally {
      Arrays.fill(data, (byte) 0);
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
    return OsslSymCipher.toKey(encoded, wrappedKeyAlgorithm, wrappedKeyType);
  }

}
