// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiSpeed;
import org.xipki.crypto.bcfips.CryptoBcFips;

/**
 * Performance tests of the backend crypto-be-bc-fips, run with the Maven profile speed.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoBcFipsSpeedTest extends CryptoApiSpeed {

  private static final CryptoApi cryptoApi = new CryptoBcFips();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
