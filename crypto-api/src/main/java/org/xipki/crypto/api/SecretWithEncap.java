// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

/**
 * @author Lijun Liao (xipki)
 */
public interface SecretWithEncap {

  byte[] secret();

  byte[] encap();

}
