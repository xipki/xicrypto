// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.util.Locale;
import java.util.Map;

/**
 * The names of the algorithms in OpenSSL.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslNames {

  /** Upper-case JCA name of the digest to the name in OpenSSL. */
  private static final Map<String, String> DIGESTS = Map.ofEntries(
      Map.entry("SHA-1", "SHA1"),
      Map.entry("SHA1", "SHA1"),
      Map.entry("SHA", "SHA1"),
      Map.entry("SHA-224", "SHA2-224"),
      Map.entry("SHA224", "SHA2-224"),
      Map.entry("SHA-256", "SHA2-256"),
      Map.entry("SHA256", "SHA2-256"),
      Map.entry("SHA-384", "SHA2-384"),
      Map.entry("SHA384", "SHA2-384"),
      Map.entry("SHA-512", "SHA2-512"),
      Map.entry("SHA512", "SHA2-512"),
      Map.entry("SHA-512/224", "SHA2-512/224"),
      Map.entry("SHA512/224", "SHA2-512/224"),
      Map.entry("SHA-512/256", "SHA2-512/256"),
      Map.entry("SHA512/256", "SHA2-512/256"),
      Map.entry("SHA3-224", "SHA3-224"),
      Map.entry("SHA3-256", "SHA3-256"),
      Map.entry("SHA3-384", "SHA3-384"),
      Map.entry("SHA3-512", "SHA3-512"),
      Map.entry("SM3", "SM3"),
      Map.entry("SHAKE128", "SHAKE128"),
      Map.entry("SHAKE256", "SHAKE256"));

  private OsslNames() {
  }

  /**
   * Returns the name of the digest in OpenSSL.
   * @param jcaName the JCA name, e.g. "SHA-256".
   * @return the name in OpenSSL, e.g. "SHA2-256", or null if unknown.
   */
  static String digest(String jcaName) {
    return (jcaName == null) ? null : DIGESTS.get(jcaName.toUpperCase(Locale.ROOT));
  }

}
