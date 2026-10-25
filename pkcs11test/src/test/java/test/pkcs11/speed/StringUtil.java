// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.speed;

import org.xipki.codec.util.Args;

/**
 * String Util, the methods used by {@link BenchmarkExecutor} and {@link ProcessLog}.
 *
 * @author Lijun Liao (xipki)
 */
public class StringUtil {

  private StringUtil() {
  }

  public static boolean isNotBlank(String str) {
    return Args.isNotBlank(str);
  }

  public static String formatText(String text, int minLen) {
    int len = Args.notNull(text, "text").length();
    if (len >= minLen) {
      return text;
    }

    return " ".repeat(minLen - len) + text;
  }

  public static String formatAccount(long account, int minLen) {
    String accountS = Long.toString(account);

    final int n = accountS.length();
    if (n > 3) {
      StringBuilder sb = new StringBuilder(n + 3);
      int firstBlockLen = n % 3;
      if (firstBlockLen != 0) {
        sb.append(accountS, 0, firstBlockLen).append(',');
      }

      for (int i = 0;; i++) {
        int offset = firstBlockLen + i * 3;
        if (offset >= n) {
          break;
        }

        sb.append(accountS, offset, offset + 3);
        if (offset + 3 < n) {
          sb.append(',');
        }
      }
      accountS = sb.toString();
    }

    return formatText(accountS, minLen);
  }

  public static String formatTime(long seconds, boolean withPrefix) {
    return formatTime(seconds, withPrefix ? 12 : 0);
  }

  public static String formatTime(long seconds, int minLen) {
    long minutes = seconds / 60;

    StringBuilder sb = new StringBuilder();
    long hour = minutes / 60;
    // hours
    if (hour > 0) {
      sb.append(hour).append(':');
    }

    long modMinute = minutes % 60;
    // minutes
    if (modMinute < 10) {
      sb.append('0');
    }
    sb.append(modMinute).append(':');

    long modSec = seconds % 60;
    // seconds
    if (modSec < 10) {
      sb.append('0');
    }
    sb.append(modSec);

    return formatText(sb.toString(), minLen);
  }

  public static String concatObjectsCap(int cap, Object o1, Object... objs) {
    StringBuilder sb = new StringBuilder(cap).append(o1);
    for (Object obj : objs) {
      sb.append(obj);
    }
    return sb.toString();
  }

}
