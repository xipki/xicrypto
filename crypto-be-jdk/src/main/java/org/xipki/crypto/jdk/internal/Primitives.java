// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Source of the primitives the XiPKI provider does not implement itself: message digests
 * (SHA-1, SHA-2, SHA-3), HMACs and ciphers (raw RSA, AES/GCM).
 * <p>
 * The crypto backend using the XiPKI provider passes its own providers, so the primitives come
 * from the backend (e.g. the JDK providers or BC-FIPS). Without providers, the default JCA
 * lookup is used.
 *
 * @author Lijun Liao (xipki)
 */
public final class Primitives {

  private final List<Provider> providers;

  /**
   * Constructor.
   * @param providers the providers of the primitives, tried in the given order. If none is
   *                  given, the default JCA lookup is used.
   */
  public Primitives(Provider... providers) {
    this.providers = (providers == null || providers.length == 0)
        ? Collections.emptyList() : Arrays.asList(providers.clone());
  }

  public MessageDigest messageDigest(String algorithm) throws NoSuchAlgorithmException {
    if (providers.isEmpty()) {
      return MessageDigest.getInstance(algorithm);
    }

    NoSuchAlgorithmException ex = null;
    for (Provider p : providers) {
      try {
        return MessageDigest.getInstance(algorithm, p);
      } catch (NoSuchAlgorithmException e) {
        ex = e;
      }
    }
    throw ex;
  }

  public Mac mac(String algorithm) throws NoSuchAlgorithmException {
    if (providers.isEmpty()) {
      return Mac.getInstance(algorithm);
    }

    NoSuchAlgorithmException ex = null;
    for (Provider p : providers) {
      try {
        return Mac.getInstance(algorithm, p);
      } catch (NoSuchAlgorithmException e) {
        ex = e;
      }
    }
    throw ex;
  }

  public Cipher cipher(String transformation)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    if (providers.isEmpty()) {
      return Cipher.getInstance(transformation);
    }

    NoSuchAlgorithmException ex = null;
    for (Provider p : providers) {
      try {
        return Cipher.getInstance(transformation, p);
      } catch (NoSuchAlgorithmException e) {
        ex = e;
      }
    }
    throw ex;
  }

}
