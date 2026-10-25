// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiConformance;
import org.xipki.crypto.bcfips.CryptoBcFips;

/**
 * Conformance tests of the BouncyCastle FIPS backend.
 *
 * @author Lijun Liao (xipki)
 */
public class BcProvUtilTest extends CryptoApiConformance {

  private static final CryptoApi cryptoApi = new CryptoBcFips();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
