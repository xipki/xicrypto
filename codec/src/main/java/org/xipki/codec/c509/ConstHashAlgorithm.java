// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import java.util.HashMap;
import java.util.Map;

/**
 * Hash Algorithms
 *
 * @author Lijun Liao (xipki)
 */
public final class ConstHashAlgorithm {

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
    f(SHA256,    "SHA256");
    f(SHA384,    "SHA384");
    f(SHA512,    "SHA512");
    f(SHAKE128,  "SHAKE128");
    f(SHAKE256,  "SHAKE256");
  }

  private static void f(int code, String name) {
    Const.addEntry(code, name, codeToName);
  }

  public static String getDesc(int code) {
    return getName(code) + " (" + code + ")";
  }

  public static String getName(int code) {
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
      default:
        throw new IllegalArgumentException("invalid hash algorithm code " + alg);
    }
  }

}
