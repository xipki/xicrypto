// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiCrossTest;
import org.xipki.crypto.bc.CryptoBc;
import org.xipki.crypto.jdk.CryptoJdk;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Cross tests of the BouncyCastle backend with the JDK backend (crypto-be-jdk).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkCrossTest extends CryptoApiCrossTest {

  private static final CryptoApi backend = new CryptoBc();

  private static final CryptoApi reference = new CryptoJdk();

  @Override
  protected CryptoApi backend() {
    return backend;
  }

  @Override
  protected CryptoApi reference() {
    return reference;
  }

  @Override
  protected Set<String> backendProviders() {
    return new HashSet<>(Arrays.asList("BC"));
  }

  /**
   * crypto-be-jdk: supported with the JVM option
   * --add-exports java.base/sun.security.provider=ALL-UNNAMED.
   */
  @Override
  protected boolean supportsMldsaContext() {
    return Object.class.getModule().isExported("sun.security.provider",
        CryptoJdk.class.getModule());
  }

}
