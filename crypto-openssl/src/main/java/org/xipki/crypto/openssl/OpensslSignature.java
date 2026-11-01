// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Signature on OpenSSL. The message is collected and signed or verified with one downcall; the
 * key is imported once ({@link NativeKey}). By default, the operation is EVP_DigestSign /
 * EVP_DigestVerify; the subclasses of the algorithms OpenSSL does not support as such compose
 * them of OpenSSL's primitives.
 * <p>
 * The randomness of the signatures comes from the DRBG of OpenSSL, a {@code SecureRandom}
 * passed to {@code initSign} is not used.
 *
 * @author Lijun Liao (xipki)
 */
abstract class OpensslSignature extends SignatureSpi {

  private final String[] keyTypes;

  NativeKey key;

  private boolean signing;

  private byte[] buf = new byte[256];

  private int count;

  OpensslSignature(String... keyTypes) {
    this.keyTypes = keyTypes;
  }

  /**
   * Returns a new EVP_MD_CTX for the operation with {@link #key}. The caller frees it.
   */
  abstract MemorySegment newCtx() throws InvalidKeyException;

  /** Called at initSign and initVerify. */
  void reset() {
  }

  /**
   * Signs the message, by default with EVP_DigestSign.
   * @return the signature.
   */
  byte[] sign(MemorySegment msg) throws SignatureException {
    MemorySegment ctx;
    try {
      ctx = newCtx();
    } catch (InvalidKeyException e) {
      throw new SignatureException(e.getMessage(), e);
    }

    try {
      byte[] sig = OpenSsl.digestSign(ctx, key.maxSigLen(), msg);
      if (sig == null) {
        throw new SignatureException("signing failed: " + OpenSsl.errors());
      }
      return sig;
    } finally {
      OpenSsl.mdCtxFree(ctx);
    }
  }

  /**
   * Verifies the signature, by default with EVP_DigestVerify.
   * @return whether the signature is valid.
   */
  boolean verify(MemorySegment msg, byte[] sig) throws SignatureException {
    MemorySegment ctx;
    try {
      ctx = newCtx();
    } catch (InvalidKeyException e) {
      throw new SignatureException(e.getMessage(), e);
    }

    try {
      int rc = OpenSsl.digestVerify(ctx, MemorySegment.ofArray(sig), msg);
      if (rc != 1) {
        // invalid signature, or a malformed one
        OpenSsl.clearErrors();
        return false;
      }
      return true;
    } finally {
      OpenSsl.mdCtxFree(ctx);
    }
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    key = NativeKey.of(publicKey, keyTypes);
    signing = false;
    count = 0;
    reset();
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    key = NativeKey.of(privateKey, keyTypes);
    signing = true;
    count = 0;
    reset();
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    ensureCapacity(1);
    buf[count++] = b;
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    ensureCapacity(len);
    System.arraycopy(b, off, buf, count, len);
    count += len;
  }

  private void ensureCapacity(int len) throws SignatureException {
    if (key == null) {
      throw new SignatureException("not initialized");
    }
    if (count + len > buf.length) {
      buf = Arrays.copyOf(buf, Math.max(buf.length * 2, count + len));
    }
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (key == null || !signing) {
      throw new SignatureException("not initialized for signing");
    }
    try {
      return sign(MemorySegment.ofArray(buf).asSlice(0, count));
    } finally {
      count = 0;
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (key == null || signing) {
      throw new SignatureException("not initialized for verification");
    }
    try {
      return verify(MemorySegment.ofArray(buf).asSlice(0, count), sigBytes);
    } finally {
      count = 0;
    }
  }

  @Override
  @Deprecated
  protected void engineSetParameter(String param, Object value) {
    throw new InvalidParameterException("unsupported parameter " + param);
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(String param) {
    throw new InvalidParameterException("unsupported parameter " + param);
  }

  /**
   * Signature with EVP_DigestSign and fixed parameters: RSA (PKCS#1 v1.5, PSS), ECDSA,
   * SM3withSM2 and EdDSA.
   */
  static final class Fixed extends OpensslSignature {

    private final NativeKey.SigOp op;

    /**
     * Constructor.
     * @param op the operation.
     * @param keyTypes the allowed key types in OpenSSL.
     */
    Fixed(NativeKey.SigOp op, String... keyTypes) {
      super(keyTypes);
      this.op = op;
    }

    @Override
    MemorySegment newCtx() throws InvalidKeyException {
      return key.newCtx(op);
    }

    /** RSA PKCS#1 v1.5 with the digest. */
    static NativeKey.SigOp rsa(String md) {
      return NativeKey.SigOp.global(md, null);
    }

    /**
     * RSA PSS with the digest, MGF1 with the same digest, and the salt length equal to the
     * digest length. The parameters are set after the initialization: the provider fips of
     * OpenSSL 3.5 rejects them as parameters of EVP_DigestSignInit_ex ("invalid digest").
     */
    static NativeKey.SigOp rsaPss(String md) {
      return NativeKey.SigOp.globalParamsAfterInit(md, new OsslParams()
          .utf8("pad-mode", "pss").utf8("mgf1-digest", md).utf8("saltlen", "digest"));
    }

    /** ECDSA with the digest. */
    static NativeKey.SigOp ecdsa(String md) {
      return NativeKey.SigOp.global(md, null);
    }

    /**
     * SM3withSM2 with the default user ID "1234567812345678". The ID is set after the
     * initialization: OpenSSL 3.6 rejects it as parameter of EVP_DigestSignInit_ex.
     */
    static NativeKey.SigOp sm2() {
      byte[] defaultId = "1234567812345678".getBytes(StandardCharsets.US_ASCII);
      return NativeKey.SigOp.globalParamsAfterInit("SM3",
          new OsslParams().octets("distid", defaultId));
    }

    /** EdDSA (pure). */
    static NativeKey.SigOp eddsa() {
      return NativeKey.SigOp.global(null, null);
    }

  }

  /**
   * RSASSA-PSS with the parameters set by {@link PSSParameterSpec}: MGF1, trailer field 1.
   */
  static final class RsaPss extends OpensslSignature {

    /** The operations per parameters "digest/mgf1-digest/saltlen". */
    private static final Map<String, NativeKey.SigOp> OPS = new ConcurrentHashMap<>();

    private NativeKey.SigOp op;

    RsaPss() {
      super("RSA", "RSA-PSS");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
      if (!(params instanceof PSSParameterSpec spec)) {
        throw new InvalidAlgorithmParameterException("PSSParameterSpec is required");
      }
      if (spec.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
        throw new InvalidAlgorithmParameterException("unsupported trailer field");
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
      int saltLen = spec.getSaltLength();
      // the parameters after the initialization, see Fixed#rsaPss
      op = OPS.computeIfAbsent(md + "/" + mgfMd + "/" + saltLen,
          k -> NativeKey.SigOp.globalParamsAfterInit(md, new OsslParams()
              .utf8("pad-mode", "pss").utf8("mgf1-digest", mgfMd).integer("saltlen", saltLen)));
    }

    @Override
    MemorySegment newCtx() throws InvalidKeyException {
      if (op == null) {
        throw new InvalidKeyException("the PSSParameterSpec is not set");
      }
      return key.newCtx(op);
    }

  }

  /**
   * ML-DSA (FIPS 204, pure), with the context string set by {@link ContextSpec}. The context
   * is reset to the empty string at initSign and initVerify.
   */
  static final class Mldsa extends OpensslSignature {

    /** Without context: the templates are cached. */
    private static final NativeKey.SigOp OP = NativeKey.SigOp.global(null, null);

    private byte[] context;

    /**
     * Constructor.
     * @param keyTypes the allowed parameter sets, e.g. "ML-DSA-65".
     */
    Mldsa(String... keyTypes) {
      super(keyTypes);
    }

    @Override
    void reset() {
      context = null;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
      if (!(params instanceof ContextSpec)) {
        throw new InvalidAlgorithmParameterException("unsupported parameters " + params);
      }
      byte[] ctx = ((ContextSpec) params).context();
      if (ctx != null && ctx.length > 255) {
        throw new InvalidAlgorithmParameterException("context longer than 255 bytes");
      }
      this.context = (ctx == null || ctx.length == 0) ? null : ctx.clone();
    }

    @Override
    MemorySegment newCtx() throws InvalidKeyException {
      if (context == null) {
        return key.newCtx(OP);
      }

      try (Arena arena = Arena.ofConfined()) {
        // the parameters are applied at the initialization of the context
        return key.newCtx(new NativeKey.SigOp(MemorySegment.NULL,
            new OsslParams().octets("context-string", context).build(arena), false));
      }
    }

  }

  /**
   * ECDSA with SHAKE128 or SHAKE256 (RFC 8692): OpenSSL does not support XOFs as the digest of
   * ECDSA, so the hash (SHAKE128: 256 bits, SHAKE256: 512 bits) is computed by OpenSSL, and
   * signed by the ECDSA of OpenSSL (EVP_PKEY_sign).
   */
  static final class EcdsaShake extends OpensslSignature {

    private final MemorySegment md;

    private final int hashLen;

    /**
     * Constructor.
     * @param shake "SHAKE128" or "SHAKE256".
     */
    EcdsaShake(String shake) {
      super("EC");
      this.md = OpenSsl.md(shake);
      this.hashLen = "SHAKE128".equals(shake) ? 32 : 64;
    }

    @Override
    MemorySegment newCtx() {
      throw new UnsupportedOperationException();
    }

    @Override
    byte[] sign(MemorySegment msg) throws SignatureException {
      byte[] hash = OpenSsl.digest(md, msg, hashLen, true);
      byte[] sig = key.apply(pkey -> OpenSsl.pkeyOp(OpenSsl.PkeyOp.SIGN, pkey,
          new OsslParams(), hash));
      if (sig == null) {
        throw new SignatureException("signing failed: " + OpenSsl.errors());
      }
      return sig;
    }

    @Override
    boolean verify(MemorySegment msg, byte[] sig) {
      byte[] hash = OpenSsl.digest(md, msg, hashLen, true);
      int rc = key.apply(pkey -> OpenSsl.pkeyVerify(pkey, sig, hash));
      if (rc != 1) {
        OpenSsl.clearErrors();
        return false;
      }
      return true;
    }

  }

  /**
   * The context string of ML-DSA (FIPS 204), see
   * {@link OpensslCryptoApi#setContext(java.security.Signature, byte[])}.
   *
   * @param context the context string, null or empty for none.
   */
  record ContextSpec(byte[] context) implements AlgorithmParameterSpec {
  }

}
