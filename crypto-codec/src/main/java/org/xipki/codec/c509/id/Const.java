// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509.id;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
abstract class Const {

  /**
   * Returns the canonical form of a name: case, spaces, dashes and underscores are ignored, so
   * that e.g. {@code x_y}, {@code xy} and {@code x-y} are the same name.
   */
  static String canonical(String name) {
    StringBuilder sb = new StringBuilder(name.length());
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (c != ' ' && c != '-' && c != '_') {
        sb.append(c);
      }
    }
    return sb.toString().toUpperCase(Locale.ROOT);
  }

  /**
   * Builds the names of the codes, in canonical form: the registered names and the names of the
   * {@code public static final int} constants of the class.
   *
   * @throws IllegalStateException if a name is used for two different codes.
   */
  static Map<String, Integer> buildAliases(Class<?> clazz, Map<Integer, String> codeToName) {
    Map<String, Integer> aliases = new HashMap<>();
    for (Map.Entry<Integer, String> entry : codeToName.entrySet()) {
      addAlias(clazz, aliases, entry.getValue(), entry.getKey());
    }

    for (Field field : clazz.getFields()) {
      int mod = field.getModifiers();
      if (field.getType() == int.class && Modifier.isStatic(mod) && Modifier.isFinal(mod)) {
        try {
          addAlias(clazz, aliases, field.getName(), field.getInt(null));
        } catch (IllegalAccessException ex) {
          throw new IllegalStateException(ex);
        }
      }
    }
    return aliases;
  }

  private static void addAlias(Class<?> clazz, Map<String, Integer> aliases, String name,
                               int code) {
    Integer prev = aliases.putIfAbsent(canonical(name), code);
    if (prev != null && prev != code) {
      throw new IllegalStateException(clazz.getSimpleName() + ": name '" + name
          + "' of code " + code + " is already used by code " + prev);
    }
  }

  /**
   * Resolves a name or a decimal code.
   *
   * @return the code, or {@code null} if the name is unknown.
   */
  static Integer codeOf(String nameOrCode, Map<String, Integer> aliases) {
    String text = nameOrCode.trim();
    try {
      return Integer.parseInt(text);
    } catch (NumberFormatException ex) {
      return aliases.get(canonical(text));
    }
  }

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
