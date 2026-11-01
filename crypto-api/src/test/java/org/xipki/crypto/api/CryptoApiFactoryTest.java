// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
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

  interface CryptoFooFips extends CryptoApi {
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

  @Test
  public void testNameWithHyphen() {
    List<ServiceLoader.Provider<CryptoApi>> providers = Arrays.asList(
        provider(CryptoFoo.class, "foo"), provider(CryptoFooFips.class, "foo-fips"));
    Assert.assertEquals("foo-fips", CryptoApiFactory.select(providers, "foo-fips").name());
    Assert.assertEquals("foo-fips", CryptoApiFactory.select(providers, "FooFips").name());
    Assert.assertEquals("foo", CryptoApiFactory.select(providers, "foo").name());
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

  private static final UnsupportedClassVersionError NEWER_JAVA = new UnsupportedClassVersionError(
      "org/xipki/crypto/jdk/CryptoJdk has been compiled by a more recent version of the Java "
      + "Runtime (class file version 69.0), this version of the Java Runtime only recognizes "
      + "class file versions up to 61.0");

  @Test
  public void testFailedName() {
    Assert.assertEquals("jdk", CryptoApiFactory.failedName(NEWER_JAVA));
    Assert.assertEquals("openssl", CryptoApiFactory.failedName(new ServiceConfigurationError(
        "org.xipki.crypto.api.CryptoApi: Provider org.xipki.crypto.openssl.CryptoOpenssl could "
        + "not be instantiated")));
  }

  @Test
  public void testFailedBackendSkipped() {
    Map<String, Throwable> failures = Collections.singletonMap("jdk", NEWER_JAVA);
    List<ServiceLoader.Provider<CryptoApi>> providers =
        Collections.singletonList(provider(CryptoFoo.class, "foo"));
    Assert.assertEquals("foo", CryptoApiFactory.select(providers, failures, null).name());
    Assert.assertEquals("foo", CryptoApiFactory.select(providers, failures, "foo").name());
  }

  @Test
  public void testFailedBackendChosen() {
    Map<String, Throwable> failures = Collections.singletonMap("jdk", NEWER_JAVA);
    for (List<ServiceLoader.Provider<CryptoApi>> providers : Arrays.asList(
        Collections.<ServiceLoader.Provider<CryptoApi>>emptyList(),
        Collections.singletonList(provider(CryptoFoo.class, "foo")))) {
      String name = providers.isEmpty() ? null : "JDK";
      try {
        CryptoApiFactory.select(providers, failures, name);
        Assert.fail("IllegalStateException expected");
      } catch (IllegalStateException e) {
        Assert.assertTrue(e.getMessage(), e.getMessage().contains("requires Java 25 or later"));
        Assert.assertSame(NEWER_JAVA, e.getCause());
      }
    }
  }

}
