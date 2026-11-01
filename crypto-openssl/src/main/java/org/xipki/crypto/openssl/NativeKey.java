// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import org.xipki.codec.util.XiArrays;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A key of OpenSSL (EVP_PKEY), together with the initialized EVP_MD_CTX templates of its
 * signature operations: a signature copies the template (EVP_MD_CTX_copy_ex) instead of
 * initializing a new context, which would fetch the digest and the signature algorithm again.
 * <p>
 * The keys of this provider ({@link OsslKey}) hold their NativeKey. The other keys are imported
 * once and cached per Java key. The native memory is freed when the NativeKey becomes
 * unreachable.
 *
 * @author Lijun Liao (xipki)
 */
final class NativeKey {

  private static final Cleaner CLEANER = Cleaner.create();

  /**
   * The cache. The values do not reference the keys, so the entries are removed when the keys
   * become unreachable; a NativeKey in use by an operation stays reachable through the latter.
   */
  private static final Map<Key, NativeKey> CACHE =
      Collections.synchronizedMap(new WeakHashMap<>());

  private final MemorySegment pkey;

  private final boolean privateKey;

  private final int maxSigLen;

  /** The EVP_MD_CTX templates per operation, initialized for signing or verifying. */
  private final Map<SigOp, MemorySegment> templates = new ConcurrentHashMap<>();

  /**
   * Constructor.
   * @param pkey the EVP_PKEY, owned by this object.
   * @param privateKey whether it is a private key.
   */
  NativeKey(MemorySegment pkey, boolean privateKey) {
    this.pkey = pkey;
    this.privateKey = privateKey;
    this.maxSigLen = OpenSsl.pkeySize(pkey);
    // the action must not reference this object
    Map<SigOp, MemorySegment> ctxs = templates;
    CLEANER.register(this, () -> {
      ctxs.values().forEach(OpenSsl::mdCtxFree);
      OpenSsl.pkeyFree(pkey);
    });
  }

  /**
   * Returns the imported key: the private key for signing, the public key for verifying.
   * @param key the key.
   * @param keyTypes the allowed key types in OpenSSL, e.g. "SM2".
   * @return the native key.
   * @throws InvalidKeyException if the key cannot be imported or is not of the types.
   */
  static NativeKey of(Key key, String... keyTypes) throws InvalidKeyException {
    NativeKey nk = (key instanceof OsslKey ok) ? ok.nativeKey() : CACHE.get(key);
    if (nk == null) {
      nk = importKey(key);
      // a concurrent import of the same key is harmless: one of them is cached
      CACHE.put(key, nk);
    }

    boolean isA = false;
    for (String keyType : keyTypes) {
      if (OpenSsl.pkeyIsA(nk.pkey, keyType)) {
        isA = true;
        break;
      }
    }
    Reference.reachabilityFence(nk);
    if (!isA) {
      throw new InvalidKeyException("not a " + String.join(" / ", keyTypes) + " key");
    }
    return nk;
  }

  /**
   * Returns the key of OpenSSL, without checking its type.
   * @param key the key: the private key for signing, the public key for verifying.
   * @return the native key.
   * @throws InvalidKeyException if the key cannot be imported.
   */
  static NativeKey of(Key key) throws InvalidKeyException {
    if (key instanceof OsslKey ok) {
      return ok.nativeKey();
    }
    NativeKey nk = CACHE.get(key);
    if (nk == null) {
      nk = importKey(key);
      CACHE.put(key, nk);
    }
    return nk;
  }

  private static NativeKey importKey(Key key) throws InvalidKeyException {
    byte[] der = key.getEncoded();
    if (der == null) {
      throw new InvalidKeyException("key " + key.getClass().getName() + " has no encoding");
    }

    boolean isPrivate = key instanceof PrivateKey;
    MemorySegment pkey;
    try {
      pkey = isPrivate ? OpenSsl.d2iPrivateKey(der) : OpenSsl.d2iPublicKey(der);
    } finally {
      if (isPrivate) {
        XiArrays.clear(der);
      }
    }

    if (pkey.address() == 0) {
      throw new InvalidKeyException("could not import the key into OpenSSL: " + OpenSsl.errors());
    }
    return new NativeKey(pkey, isPrivate);
  }

  int maxSigLen() {
    return maxSigLen;
  }

  boolean isPrivate() {
    return privateKey;
  }

  /**
   * A function on the EVP_PKEY.
   *
   * @param <T> the type of the result.
   */
  @FunctionalInterface
  interface PkeyFunction<T> {
    T apply(MemorySegment pkey);
  }

  /**
   * Applies the function to the EVP_PKEY. The EVP_PKEY is not freed during the function.
   */
  <T> T apply(PkeyFunction<T> function) {
    try {
      return function.apply(pkey);
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  /**
   * Returns a new EVP_MD_CTX initialized for the operation: for signing if this is a private
   * key, otherwise for verifying. The caller frees it. For a cacheable operation, it is a copy
   * of the cached template.
   * @param op the operation.
   * @return the new EVP_MD_CTX.
   * @throws InvalidKeyException if the operation cannot be initialized with this key.
   */
  MemorySegment newCtx(SigOp op) throws InvalidKeyException {
    if (!op.cacheable()) {
      try {
        return newTemplate(op);
      } finally {
        Reference.reachabilityFence(this);
      }
    }

    MemorySegment template = templates.get(op);
    if (template == null) {
      template = newTemplate(op);
      MemorySegment prev = templates.putIfAbsent(op, template);
      if (prev != null) {
        OpenSsl.mdCtxFree(template);
        template = prev;
      }
    }

    MemorySegment ctx = OpenSsl.mdCtxNew();
    try {
      if (!OpenSsl.mdCtxCopy(ctx, template)) {
        OpenSsl.mdCtxFree(ctx);
        throw new IllegalStateException("EVP_MD_CTX_copy_ex failed: " + OpenSsl.errors());
      }
    } finally {
      // the template must not be freed during the copy. The copy holds own references to the
      // EVP_PKEY and the algorithms.
      Reference.reachabilityFence(this);
    }
    return ctx;
  }

  private MemorySegment newTemplate(SigOp op) throws InvalidKeyException {
    MemorySegment ctx = OpenSsl.mdCtxNew();
    MemorySegment initParams = op.paramsAfterInit() ? MemorySegment.NULL : op.params();
    boolean ok = privateKey
        ? OpenSsl.digestSignInit(ctx, op.mdName(), pkey, initParams)
        : OpenSsl.digestVerifyInit(ctx, op.mdName(), pkey, initParams);
    if (ok && op.paramsAfterInit()) {
      ok = OpenSsl.digestSignVerifySetParams(ctx, op.params());
    }
    if (!ok) {
      OpenSsl.mdCtxFree(ctx);
      throw new InvalidKeyException("could not initialize the signature: " + OpenSsl.errors());
    }
    return ctx;
  }

  /**
   * The parameters of a signature operation. The cacheable instances are constants: they are
   * compared by identity, and their templates are cached.
   */
  static final class SigOp {

    private final MemorySegment mdName;

    private final MemorySegment params;

    private final boolean cacheable;

    private final boolean paramsAfterInit;

    /**
     * Constructor.
     * @param mdName the name of the digest as C string, or {@link MemorySegment#NULL} for the
     *               algorithms without digest, such as ML-DSA.
     * @param params the OSSL_PARAM array, or {@link MemorySegment#NULL}.
     * @param cacheable whether the templates of this operation are cached. If true, mdName and
     *                  params must be in global native memory.
     */
    SigOp(MemorySegment mdName, MemorySegment params, boolean cacheable) {
      this(mdName, params, cacheable, false);
    }

    private SigOp(MemorySegment mdName, MemorySegment params, boolean cacheable,
                  boolean paramsAfterInit) {
      this.mdName = mdName;
      this.params = params;
      this.cacheable = cacheable;
      this.paramsAfterInit = paramsAfterInit;
    }

    /**
     * Returns a cacheable operation, in global native memory.
     * @param mdName the name of the digest in OpenSSL, or null for none.
     * @param params the parameters, or null for none.
     */
    static SigOp global(String mdName, OsslParams params) {
      return global(mdName, params, false);
    }

    /**
     * Returns a cacheable operation, in global native memory, whose parameters are set after
     * the initialization, not passed to EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex.
     * @param mdName the name of the digest in OpenSSL, or null for none.
     * @param params the parameters.
     */
    static SigOp globalParamsAfterInit(String mdName, OsslParams params) {
      return global(mdName, params, true);
    }

    private static SigOp global(String mdName, OsslParams params, boolean paramsAfterInit) {
      Arena arena = Arena.global();
      return new SigOp(mdName == null ? MemorySegment.NULL : arena.allocateFrom(mdName),
          params == null ? MemorySegment.NULL : params.build(arena), true, paramsAfterInit);
    }

    boolean cacheable() {
      return cacheable;
    }

    boolean paramsAfterInit() {
      return paramsAfterInit;
    }

    MemorySegment mdName() {
      return mdName;
    }

    MemorySegment params() {
      return params;
    }

  }

}
