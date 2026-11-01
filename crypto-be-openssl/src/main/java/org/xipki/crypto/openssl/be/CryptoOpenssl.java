// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl.be;

import org.xipki.crypto.openssl.OpensslCryptoApi;

/**
 * Crypto backend "openssl" on libcrypto of OpenSSL 3.5+, see {@link OpensslCryptoApi}.
 * OpenSSL must not be in the FIPS mode; for the FIPS mode use {@code CryptoOpensslFips}
 * (module crypto-be-openssl-fips).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpenssl extends OpensslCryptoApi {

  /**
   * Constructor.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available, or if OpenSSL
   *         is in the FIPS mode.
   */
  public CryptoOpenssl() {
    super(false);
  }

  @Override
  public String name() {
    return "openssl";
  }

}
