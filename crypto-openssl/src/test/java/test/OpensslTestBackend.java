// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.openssl.OpenSsl;
import org.xipki.crypto.openssl.OpensslCryptoApi;

/**
 * The backend of the tests of crypto-openssl: runs in the mode OpenSSL is in, so the same tests
 * cover the backends crypto-be-openssl (not in the FIPS mode) and crypto-be-openssl-fips.
 *
 * @author Lijun Liao (xipki)
 */
public final class OpensslTestBackend extends OpensslCryptoApi {

  public OpensslTestBackend() {
    super(OpenSsl.isFipsEnabled());
  }

  @Override
  public String name() {
    return OpenSsl.isFipsEnabled() ? "openssl-fips" : "openssl";
  }

}
