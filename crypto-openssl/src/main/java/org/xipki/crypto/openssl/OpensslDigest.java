// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

/**
 * MessageDigest on EVP_MD_CTX. The data of {@code update(byte[])} is passed to OpenSSL without
 * copying (critical downcall on the heap array).
 *
 * @author Lijun Liao (xipki)
 */
final class OpensslDigest extends MessageDigestSpi implements Cloneable {

  private static final Cleaner CLEANER = Cleaner.create();

  /** Larger inputs are passed in chunks, to keep the critical downcalls short. */
  private static final int MAX_CHUNK = 64 * 1024;

  private final MemorySegment md;

  private final int digestLen;

  /** Whether the digest is an XOF with a fixed output length, e.g. SHAKE128-256. */
  private final boolean xof;

  private MemorySegment ctx;

  /**
   * Constructor.
   * @param name the name of the digest in OpenSSL, e.g. "SM3".
   * @throws NoSuchAlgorithmException if OpenSSL does not support the digest.
   */
  OpensslDigest(String name) throws NoSuchAlgorithmException {
    this(name, 0);
  }

  /**
   * Constructor.
   * @param name the name of the digest in OpenSSL, e.g. "SM3" or "SHAKE128".
   * @param xofLen the output length of the XOF in bytes, 0 for the digests.
   * @throws NoSuchAlgorithmException if OpenSSL does not support the digest.
   */
  OpensslDigest(String name, int xofLen) throws NoSuchAlgorithmException {
    this.md = OpenSsl.md(name);
    if (md.address() == 0) {
      throw new NoSuchAlgorithmException("OpenSSL does not support the digest " + name);
    }
    this.xof = xofLen > 0;
    this.digestLen = xof ? xofLen : OpenSsl.mdSize(md);
    setCtx(OpenSsl.mdCtxNew());
    if (!OpenSsl.digestInit(ctx, md)) {
      throw new IllegalStateException("EVP_DigestInit_ex2 failed: " + OpenSsl.errors());
    }
  }

  private void setCtx(MemorySegment ctx) {
    this.ctx = ctx;
    // the action must not reference this object
    CLEANER.register(this, () -> OpenSsl.mdCtxFree(ctx));
  }

  @Override
  protected int engineGetDigestLength() {
    return digestLen;
  }

  @Override
  protected void engineUpdate(byte input) {
    engineUpdate(new byte[]{input}, 0, 1);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    MemorySegment data = MemorySegment.ofArray(input);
    while (len > 0) {
      int n = Math.min(len, MAX_CHUNK);
      update(data.asSlice(offset, n));
      offset += n;
      len -= n;
    }
  }

  @Override
  protected void engineUpdate(ByteBuffer input) {
    if (input.isDirect()) {
      MemorySegment data = MemorySegment.ofBuffer(input);
      update(data);
      input.position(input.limit());
    } else {
      super.engineUpdate(input);
    }
  }

  private void update(MemorySegment data) {
    try {
      if (!OpenSsl.digestUpdate(ctx, data)) {
        throw new IllegalStateException("EVP_DigestUpdate failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  protected byte[] engineDigest() {
    byte[] out = new byte[digestLen];
    finish(out, 0);
    return out;
  }

  @Override
  protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
    if (len < digestLen) {
      throw new DigestException("output buffer too small");
    }
    finish(buf, offset);
    return digestLen;
  }

  private void finish(byte[] buf, int offset) {
    try {
      MemorySegment out = MemorySegment.ofArray(buf).asSlice(offset, digestLen);
      if (!(xof ? OpenSsl.digestFinalXof(ctx, out) : OpenSsl.digestFinal(ctx, out))) {
        throw new IllegalStateException("EVP_DigestFinal_ex failed: " + OpenSsl.errors());
      }
    } finally {
      engineReset();
    }
  }

  @Override
  protected void engineReset() {
    try {
      if (!OpenSsl.digestInit(ctx, md)) {
        throw new IllegalStateException("EVP_DigestInit_ex2 failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    OpensslDigest copy = (OpensslDigest) super.clone();
    MemorySegment newCtx = OpenSsl.mdCtxNew();
    try {
      if (!OpenSsl.mdCtxCopy(newCtx, ctx)) {
        OpenSsl.mdCtxFree(newCtx);
        throw new CloneNotSupportedException("EVP_MD_CTX_copy_ex failed: " + OpenSsl.errors());
      }
    } finally {
      Reference.reachabilityFence(this);
    }
    copy.setCtx(newCtx);
    return copy;
  }

}
