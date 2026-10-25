// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.util.Args;

/**
 * @author Lijun Liao (xipki)
 */
public final class SecretWithEncapImpl implements SecretWithEncap {

  private final byte[] secret;

  private final byte[] encap;

  public SecretWithEncapImpl(byte[] secret, byte[] encap) {
    this.secret = Args.notNull(secret, "secret");
    this.encap = Args.notNull(encap, "encap");
  }

  @Override
  public byte[] secret() {
    return secret;
  }

  @Override
  public byte[] encap() {
    return encap;
  }

}
