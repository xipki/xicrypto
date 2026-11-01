// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiSpeed;
import org.xipki.crypto.openssl.OpenSsl;

/**
 * Performance tests of the backend crypto-be-openssl, run with the Maven profile speed.
 * Skipped if libcrypto of OpenSSL 3.5+ is not available.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpensslSpeedTest extends CryptoApiSpeed {

  private static CryptoApi cryptoApi;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    cryptoApi = new OpensslTestBackend();
  }

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
