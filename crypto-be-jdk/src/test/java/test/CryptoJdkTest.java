// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiConformance;
import org.xipki.crypto.jdk.CryptoJdk;

/**
 * Conformance tests of the JDK backend.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkTest extends CryptoApiConformance {

  private static final CryptoApi cryptoApi = new CryptoJdk();

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

  /**
   * Supported with the JVM option --add-exports java.base/sun.security.provider=ALL-UNNAMED.
   */
  @Override
  protected boolean supportsMldsaContext() {
    return Object.class.getModule().isExported("sun.security.provider",
        CryptoJdk.class.getModule());
  }

}
