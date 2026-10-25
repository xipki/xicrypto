// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

import org.xipki.codec.util.Args;

import java.net.URL;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * String utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class HsmStringUtil {

  private HsmStringUtil() {
  }

  public static boolean isBlank(String str) {
    return Args.isBlank(str);
  }

  public static String getBundleVersion(Class<?> clazz) {
    try {
      String className = "/" + clazz.getName().replace(".", "/") + ".class";
      URL resource = clazz.getResource(className);
      if (resource == null) {
        return "UNKNOWN";
      }

      String classPath = resource.toString();
      String manifestPath = classPath.substring(0, classPath.length() - className.length()) +
                            "/META-INF/MANIFEST.MF";
      Manifest manifest = new Manifest(new URL(manifestPath).openStream());
      Attributes attrs = manifest.getMainAttributes();
      String version = attrs.getValue("Build-Version");
      if (version == null) {
        return "UNKNOWN";
      }

      String buildNumber = attrs.getValue("Build-Id");
      String timestamp = attrs.getValue("Build-Timestamp");
      return version + " buildNumber " + buildNumber + " built at " + timestamp;
    } catch (Exception ex) {
      return "ERROR";
    }
  }

}
