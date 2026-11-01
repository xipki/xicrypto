// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.crypto;

import org.xipki.codec.util.Args;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author Lijun Liao (xipki)
 */
public class SignatureOutputStream extends OutputStream {

  private final Signature sig;

  public SignatureOutputStream(Signature sig) {
    this.sig = Args.notNull(sig, "sig");
  }

  Signature getSig() {
    return sig;
  }

  @Override
  public void write(byte[] bytes, int off, int len) throws IOException {
    try {
      sig.update(bytes, off, len);
    } catch (SignatureException e) {
      throw new IOException(e.getMessage(), e);
    }
  }

  @Override
  public void write(byte[] bytes) throws IOException {
    try {
      sig.update(bytes);
    } catch (SignatureException e) {
      throw new IOException(e.getMessage(), e);
    }
  }

  @Override
  public void write(int b) throws IOException {
    try {
      sig.update((byte)b);
    } catch (SignatureException e) {
      throw new IOException(e.getMessage(), e);
    }
  }

  public byte[] getSignature() throws SignatureException {
    return sig.sign();
  }

}
