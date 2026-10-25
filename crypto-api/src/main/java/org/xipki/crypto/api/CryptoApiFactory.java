// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Loads the crypto backend.
 * <p>
 * If the system property {@value #PROP_BACKEND} is set, the backend with this name
 * (see {@link CryptoApi#name()}) is used. Otherwise, exactly one backend must be on the
 * classpath.
 *
 * @author Lijun Liao (xipki)
 */
public final class CryptoApiFactory {

  public static final String PROP_BACKEND = "xipki.crypto.backend";

  private static final class Holder {
    private static final CryptoApi INSTANCE = load();
  }

  private CryptoApiFactory() {}

  public static CryptoApi get() {
    return Holder.INSTANCE;
  }

  private static CryptoApi load() {
    List<ServiceLoader.Provider<CryptoApi>> providers = new ArrayList<>();
    ServiceLoader.load(CryptoApi.class).stream().forEach(providers::add);
    return select(providers, System.getProperty(PROP_BACKEND));
  }

  /**
   * Selects the backend without instantiating the other ones: their constructors may have
   * side effects such as registering JCA providers. The class of a backend must be named
   * {@code Crypto<Name>}, e.g. {@code CryptoBc} for the backend "bc".
   */
  static CryptoApi select(List<ServiceLoader.Provider<CryptoApi>> providers, String name) {
    if (providers.isEmpty()) {
      throw new IllegalStateException("No implementation of CryptoApi found on the classpath");
    }

    if (name != null && !name.trim().isEmpty()) {
      name = name.trim();
      for (ServiceLoader.Provider<CryptoApi> provider : providers) {
        if (typeName(provider).equalsIgnoreCase(name)) {
          CryptoApi backend = provider.get();
          if (!backend.name().equalsIgnoreCase(name)) {
            throw new IllegalStateException("CryptoApi " + provider.type().getName()
                + " has the name " + backend.name() + ", expected " + name);
          }
          return backend;
        }
      }
      throw new IllegalStateException("No implementation of CryptoApi with name '" + name
          + "' found on the classpath, available: " + names(providers));
    }

    if (providers.size() > 1) {
      throw new IllegalStateException("More than one implementation of CryptoApi found on the "
          + "classpath: " + names(providers) + ", set the system property " + PROP_BACKEND);
    }

    return providers.get(0).get();
  }

  private static String typeName(ServiceLoader.Provider<CryptoApi> provider) {
    String simpleName = provider.type().getSimpleName();
    return simpleName.startsWith("Crypto") ? simpleName.substring("Crypto".length()) : simpleName;
  }

  private static List<String> names(List<ServiceLoader.Provider<CryptoApi>> providers) {
    List<String> names = new ArrayList<>(providers.size());
    for (ServiceLoader.Provider<CryptoApi> provider : providers) {
      names.add(typeName(provider).toLowerCase(java.util.Locale.ROOT));
    }
    return names;
  }

}
