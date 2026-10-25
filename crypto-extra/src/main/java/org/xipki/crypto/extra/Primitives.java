// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

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

  /**
   * Returns the MAC of the providers. If none of them has HmacSHA3-* (e.g. the JDK 11 to 15),
   * the HMAC of {@link HmacSha3Spi} over the SHA3 digest of the providers is returned.
   * @param algorithm the name of the MAC.
   * @return the MAC.
   * @throws NoSuchAlgorithmException if the MAC is not available.
   */
  public Mac mac(String algorithm) throws NoSuchAlgorithmException {
    NoSuchAlgorithmException ex = null;
    if (providers.isEmpty()) {
      try {
        return Mac.getInstance(algorithm);
      } catch (NoSuchAlgorithmException e) {
        ex = e;
      }
    } else {
      for (Provider p : providers) {
        try {
          return Mac.getInstance(algorithm, p);
        } catch (NoSuchAlgorithmException e) {
          ex = e;
        }
      }
    }

    HmacSha3Spi spi = hmacSha3(algorithm);
    if (spi == null) {
      throw ex;
    }
    return new Mac(spi, null, algorithm) {
    };
  }

  private HmacSha3Spi hmacSha3(String algorithm) {
    switch (algorithm.toUpperCase(Locale.ROOT)) {
      case "HMACSHA3-224":
        return new HmacSha3Spi(this, 224);
      case "HMACSHA3-256":
        return new HmacSha3Spi(this, 256);
      case "HMACSHA3-384":
        return new HmacSha3Spi(this, 384);
      case "HMACSHA3-512":
        return new HmacSha3Spi(this, 512);
      default:
        return null;
    }
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
