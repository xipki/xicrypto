// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiSpeed;
import org.xipki.crypto.bc.CryptoBc;

/**
 * Performance tests of the backend crypto-be-bc, run with the Maven profile speed.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoBcSpeedTest extends CryptoApiSpeed {

  private static final CryptoApi cryptoApi = new CryptoBc();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
