// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509.id;

import java.util.HashMap;
import java.util.Map;

/**
 * Hash Algorithms
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstHashAlgorithm {

  // 2.16.840.1.101.3.4.2.1
  public static final int SHA1   = -14;

  // 2.16.840.1.101.3.4.2.1
  public static final int SHA256 = -16;

  // 2.16.840.1.101.3.4.2.2
  public static final int SHA384 = -43;

  // 2.16.840.1.101.3.4.2.3
  public static final int SHA512 = -44;

  // 2.16.840.1.101.3.4.2.11
  public static final int SHAKE128 = -18;

  // 2.16.840.1.101.3.4.2.12
  public static final int SHAKE256 = -45;

  private static final Map<Integer, String> codeToName = new HashMap<>();

  static {
    f(SHA1,      "SHA1");
    f(SHA256,    "SHA256");
    f(SHA384,    "SHA384");
    f(SHA512,    "SHA512");
    f(SHAKE128,  "SHAKE128");
    f(SHAKE256,  "SHAKE256");
  }

  private static void f(int code, String name) {
    Const.addEntry(code, name, codeToName);
  }

  private static final Map<String, Integer> ALIASES =
      Const.buildAliases(ConstHashAlgorithm.class, codeToName);

  /**
   * Returns the code for the name of the constant in this class (e.g. {@code SHA256}, also
   * written as {@code sha-256} or {@code sha_256}; case, spaces, dashes and underscores are
   * ignored), the registered name, or the decimal code.
   *
   * @param nameOrCode the name or the decimal code.
   * @return the code, or {@code null} if the name is unknown.
   */
  public static Integer code(String nameOrCode) {
    return Const.codeOf(nameOrCode, ALIASES);
  }

  public static String describe(int code) {
    return name(code) + " (" + code + ")";
  }

  public static String name(int code) {
    String name = codeToName.get(code);
    return name == null ? "unknown" : name;
  }

  public static int hashValueLength(int alg) {
    switch (alg) {
      case SHA256:
      case SHAKE128:
        return 32;
      case SHA384:
        return 48;
      case SHA512:
      case SHAKE256:
        return 64;
      case SHA1:
        return 20;
      default:
        throw new IllegalArgumentException("invalid hash algorithm code " + alg);
    }
  }

}
