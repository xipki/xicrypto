// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads the crypto backend.
 * <p>
 * If the system property {@value #PROP_BACKEND} is set, the backend with this name
 * (see {@link CryptoApi#name()}) is used. Otherwise, exactly one backend must be on the
 * classpath. A backend that cannot be loaded, e.g. the backend jdk (Java 25+) on an older Java,
 * is skipped; choosing it fails with a message naming the required Java version.
 *
 * @author Lijun Liao (xipki)
 */
public final class CryptoApiFactory {

  public static final String PROP_BACKEND = "xipki.crypto.backend";

  /** A class name such as org.xipki.crypto.jdk.CryptoJdk or org/xipki/crypto/jdk/CryptoJdk. */
  private static final Pattern BACKEND_CLASS =
      Pattern.compile("(?:[A-Za-z0-9_$]+[./])+Crypto([A-Za-z0-9]+)\\b");

  private static final Pattern CLASS_VERSION = Pattern.compile("class file version (\\d+)");

  private static final class Holder {
    private static final CryptoApi INSTANCE = load();
  }

  private CryptoApiFactory() {}

  public static CryptoApi get() {
    return Holder.INSTANCE;
  }

  private static CryptoApi load() {
    List<ServiceLoader.Provider<CryptoApi>> providers = new ArrayList<>();
    Map<String, Throwable> failures = new LinkedHashMap<>();
    Iterator<ServiceLoader.Provider<CryptoApi>> it =
        ServiceLoader.load(CryptoApi.class).stream().iterator();
    // the lookup continues with the next provider after an error; the bound guards against a
    // lookup that would fail again and again on the same provider
    for (int i = 0; i < 100; i++) {
      try {
        if (!it.hasNext()) {
          break;
        }
        providers.add(it.next());
      } catch (ServiceConfigurationError | LinkageError e) {
        // e.g. UnsupportedClassVersionError: the backend requires a newer Java version
        failures.putIfAbsent(normalize(failedName(e)), e);
      }
    }
    return select(providers, failures, System.getProperty(PROP_BACKEND));
  }

  static CryptoApi select(List<ServiceLoader.Provider<CryptoApi>> providers, String name) {
    return select(providers, Collections.emptyMap(), name);
  }

  /**
   * Selects the backend without instantiating the other ones: their constructors may have
   * side effects such as registering JCA providers. The class of a backend must be named
   * {@code Crypto<Name>}, e.g. {@code CryptoBc} for the backend "bc"; names are compared
   * case-insensitively and without '-', e.g. {@code CryptoOpensslFips} for "openssl-fips".
   * @param providers the providers that could be loaded.
   * @param failures the backends that could not be loaded: name (lower case, without '-') to
   *                 the cause.
   * @param name the name of the backend, or null.
   */
  static CryptoApi select(List<ServiceLoader.Provider<CryptoApi>> providers,
                          Map<String, Throwable> failures, String name) {
    if (name != null && !name.trim().isEmpty()) {
      name = name.trim();
      for (ServiceLoader.Provider<CryptoApi> provider : providers) {
        if (normalize(typeName(provider)).equals(normalize(name))) {
          CryptoApi backend = provider.get();
          if (!normalize(backend.name()).equals(normalize(name))) {
            throw new IllegalStateException("CryptoApi " + provider.type().getName()
                + " has the name " + backend.name() + ", expected " + name);
          }
          return backend;
        }
      }

      Throwable failure = failures.get(normalize(name));
      if (failure != null) {
        throw failed(name, failure);
      }
      throw new IllegalStateException("No implementation of CryptoApi with name '" + name
          + "' found on the classpath, available: " + names(providers));
    }

    if (providers.isEmpty()) {
      if (failures.isEmpty()) {
        throw new IllegalStateException("No implementation of CryptoApi found on the classpath");
      }
      Map.Entry<String, Throwable> first = failures.entrySet().iterator().next();
      throw failed(first.getKey(), first.getValue());
    }

    if (providers.size() > 1) {
      throw new IllegalStateException("More than one implementation of CryptoApi found on the "
          + "classpath: " + names(providers) + ", set the system property " + PROP_BACKEND);
    }

    return providers.get(0).get();
  }

  /** Lower case, without '-': "openssl-fips" and "OpensslFips" are both "opensslfips". */
  private static String normalize(String name) {
    return name.toLowerCase(Locale.ROOT).replace("-", "");
  }

  private static String typeName(ServiceLoader.Provider<CryptoApi> provider) {
    String simpleName = provider.type().getSimpleName();
    return simpleName.startsWith("Crypto") ? simpleName.substring("Crypto".length()) : simpleName;
  }

  /**
   * Returns the lower-case name of the backend whose class appears in the message of the error,
   * e.g. "jdk" for "org/xipki/crypto/jdk/CryptoJdk has been compiled by a more recent version
   * of the Java Runtime", or the message itself if there is no such class.
   */
  static String failedName(Throwable error) {
    String msg = String.valueOf(error.getMessage());
    Matcher m = BACKEND_CLASS.matcher(msg);
    while (m.find()) {
      if (!"Api".equals(m.group(1))) {
        return m.group(1).toLowerCase(Locale.ROOT);
      }
    }
    return msg;
  }

  private static IllegalStateException failed(String name, Throwable cause) {
    String msg = "CryptoApi backend '" + name + "' could not be loaded";
    Matcher m = CLASS_VERSION.matcher(String.valueOf(cause.getMessage()));
    if (cause instanceof UnsupportedClassVersionError && m.find()) {
      // class file version N is that of Java N - 44
      msg += ": it requires Java " + (Integer.parseInt(m.group(1)) - 44) + " or later, running "
          + System.getProperty("java.specification.version");
    } else {
      msg += ": " + cause.getMessage();
    }
    return new IllegalStateException(msg, cause);
  }

  private static List<String> names(List<ServiceLoader.Provider<CryptoApi>> providers) {
    List<String> names = new ArrayList<>(providers.size());
    for (ServiceLoader.Provider<CryptoApi> provider : providers) {
      names.add(typeName(provider).toLowerCase(Locale.ROOT));
    }
    return names;
  }

}
