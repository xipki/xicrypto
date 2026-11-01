// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl.befips;

import org.xipki.crypto.openssl.OpensslCryptoApi;

/**
 * Crypto backend "openssl-fips" on libcrypto of OpenSSL 3.5+, see {@link OpensslCryptoApi}.
 * OpenSSL must be in the FIPS mode (provider fips, {@code default_properties = fips=yes});
 * otherwise use {@code CryptoOpenssl} (module crypto-be-openssl).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpensslFips extends OpensslCryptoApi {

  /**
   * Constructor.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available, or if OpenSSL
   *         is not in the FIPS mode.
   */
  public CryptoOpensslFips() {
    super(true);
  }

  @Override
  public String name() {
    return "openssl-fips";
  }

}
