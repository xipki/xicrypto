// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiCrossTest;
import org.xipki.crypto.bcfips.CryptoBcFips;
import org.xipki.crypto.jdk.CryptoJdk;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Cross tests of the BouncyCastle FIPS backend with the JDK backend (crypto-be-jdk).
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkCrossTest extends CryptoApiCrossTest {

  private static final int FEATURE = Runtime.version().feature();

  private static final CryptoApi backend = new CryptoBcFips();

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
    return new HashSet<>(Arrays.asList("BCFIPS", "BCPQC"));
  }

  /** ML-DSA and ML-KEM of crypto-be-jdk require JDK 25+. */
  @Override
  protected boolean supportsMldsa() {
    return FEATURE >= 25;
  }

  @Override
  protected boolean supportsMlkem() {
    return FEATURE >= 25;
  }

  /** Ed25519 and Ed448 of the JDK: JDK 15+. */
  @Override
  protected boolean supportsEdDsa() {
    return FEATURE >= 15;
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
