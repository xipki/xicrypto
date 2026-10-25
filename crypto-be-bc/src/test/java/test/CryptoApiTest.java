// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiConformance;
import org.xipki.crypto.bc.CryptoBc;

/**
 * Conformance tests of the BouncyCastle backend.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoApiTest extends CryptoApiConformance {

  private static final CryptoApi cryptoApi = new CryptoBc();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

}
