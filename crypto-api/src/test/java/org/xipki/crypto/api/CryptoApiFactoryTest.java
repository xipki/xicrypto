// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tests the backend selection of {@link CryptoApiFactory}.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoApiFactoryTest {

  // class names follow the convention Crypto<Name>
  interface CryptoFoo extends CryptoApi {
  }

  interface CryptoBar extends CryptoApi {
  }

  private static final AtomicInteger instances = new AtomicInteger();

  private static ServiceLoader.Provider<CryptoApi> provider(
      Class<? extends CryptoApi> type, String name) {
    return new ServiceLoader.Provider<CryptoApi>() {
      @Override
      public Class<? extends CryptoApi> type() {
        return type;
      }

      @Override
      public CryptoApi get() {
        instances.incrementAndGet();
        return (CryptoApi) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
            (proxy, method, args) -> {
              if (method.getName().equals("name")) {
                return name;
              }
              throw new UnsupportedOperationException(method.getName());
            });
      }
    };
  }

  @Test
  public void testSelection() {
    List<ServiceLoader.Provider<CryptoApi>> providers = Arrays.asList(
        provider(CryptoFoo.class, "foo"), provider(CryptoBar.class, "bar"));

    instances.set(0);
    Assert.assertEquals("bar", CryptoApiFactory.select(providers, "bar").name());
    // only the selected backend is instantiated
    Assert.assertEquals(1, instances.get());

    Assert.assertEquals("foo", CryptoApiFactory.select(providers, " FOO ").name());
    Assert.assertEquals("foo", CryptoApiFactory.select(
        Collections.singletonList(providers.get(0)), null).name());
  }

  @Test(expected = IllegalStateException.class)
  public void testAmbiguous() {
    CryptoApiFactory.select(Arrays.asList(
        provider(CryptoFoo.class, "foo"), provider(CryptoBar.class, "bar")), null);
  }

  @Test(expected = IllegalStateException.class)
  public void testUnknown() {
    CryptoApiFactory.select(Collections.singletonList(provider(CryptoFoo.class, "foo")), "jdk");
  }

  @Test(expected = IllegalStateException.class)
  public void testNameMismatch() {
    CryptoApiFactory.select(Collections.singletonList(provider(CryptoFoo.class, "other")), "foo");
  }

  @Test(expected = IllegalStateException.class)
  public void testNone() {
    CryptoApiFactory.select(Collections.emptyList(), null);
  }

}
