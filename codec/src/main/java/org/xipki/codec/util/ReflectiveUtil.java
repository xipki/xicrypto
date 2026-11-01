// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.util;

import org.xipki.codec.asn1.GenerationException;

/**
 * Reflective Util.
 *
 * @author Lijun Liao (xipki)
 */
public class ReflectiveUtil {

  public static <T> T newInstance(String className) throws GenerationException {
    return newInstance(className, null);
  }

  public static <T> T newInstance(String className, ClassLoader classLoader)
      throws GenerationException {
    try {
      Class<?> clazz = (classLoader == null)
          ? Class.forName(className) : Class.forName(className, true, classLoader);
      return (T) clazz.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException ex) {
      throw new GenerationException("create not create instance from "
          + className + ": " + ex.getMessage(), ex);
    } catch (ClassCastException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }
  }

}
