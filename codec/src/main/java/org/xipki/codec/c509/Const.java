// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
abstract class Const {

  static void addEntry(int code, String name, Map<Integer, String> codeToName) {
    if (codeToName.containsKey(code)) {
      throw new IllegalArgumentException("duplicated code " + code);
    }

    codeToName.put(code, name);
  }

  static void addEntry(long code, String name, Map<Long, String> codeToName) {
    if (codeToName.containsKey(code)) {
      throw new IllegalArgumentException("duplicated code " + code);
    }

    codeToName.put(code, name);
  }

}
