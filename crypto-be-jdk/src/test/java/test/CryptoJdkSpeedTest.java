// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiSpeed;
import org.xipki.crypto.jdk.CryptoJdk;

/**
 * Performance tests of the backend crypto-be-jdk, run with the Maven profile speed.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkSpeedTest extends CryptoApiSpeed {

  private static final CryptoApi cryptoApi = new CryptoJdk();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
