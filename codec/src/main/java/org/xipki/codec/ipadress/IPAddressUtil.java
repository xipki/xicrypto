// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.ipadress;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utility functions to validate, parse and encode textual IP addresses.
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressUtil {

  /**
   * Encodes the given IP address, with optional netmask, as the content of the iPAddress
   * choice of GeneralName.
   *
   * @param ip the IP address, optionally followed by '/' and a netmask.
   *
   * @return the encoded address, or {@code null} if the given text is not valid.
   */
  public static byte[] ipAddrToGeneralNameEncoding(String ip) {
    boolean v6 = isValidIPv6WithNetmask(ip) || isValidIPv6(ip);
    if (!v6 && !isValidIPv4WithNetmask(ip) && !isValidIPv4(ip)) {
      return null;
    }

    int slashIndex = ip.indexOf('/');
    byte[] addr = toBytes(v6, slashIndex < 0 ? ip : ip.substring(0, slashIndex));
    if (slashIndex < 0) {
      return addr;
    }

    String mask = ip.substring(slashIndex + 1);
    boolean fullMask = mask.indexOf(v6 ? ':' : '.') >= 0;
    byte[] maskBytes = fullMask ? toBytes(v6, mask)
        : prefixToMask(Integer.parseInt(mask), addr.length);

    byte[] ret = Arrays.copyOf(addr, addr.length * 2);
    System.arraycopy(maskBytes, 0, ret, addr.length, addr.length);
    return ret;
  }

  private static byte[] toBytes(boolean v6, String str) {
    return v6 ? toIPv6Bytes(str) : toIPv4Bytes(str);
  }

  private static byte[] prefixToMask(int prefixLen, int len) {
    byte[] mask = new byte[len];
    for (int i = 0; i < prefixLen; i++) {
      mask[i / 8] |= (byte) (1 << (7 - (i % 8)));
    }
    return mask;
  }

  static byte[] toIPv4Bytes(String str) {
    String[] tokens = str.split("\\.");
    if (tokens.length > 4) {
      throw new IllegalArgumentException("invalid IPv4 address " + str);
    }

    byte[] ret = new byte[4];
    for (int i = 0; i < tokens.length; i++) {
      int k = Integer.parseInt(tokens[i]);
      if (k >= 0 && k <= 255) {
        ret[i] = (byte) k;
      } else {
        throw new IllegalArgumentException("invalid IPv4 address " + str);
      }
    }
    return ret;
  }

  static byte[] toIPv6Bytes(String str) {
    List<Integer> startTokens;
    List<Integer> endTokens;
    int idx = str.indexOf("::");
    if (idx == -1) {
      startTokens = toIPv6Tokens(str);
      endTokens = Collections.emptyList();
    } else {
      if (str.lastIndexOf('.', idx) >= 0) {
        throw new IllegalArgumentException("invalid IPv6 address " + str);
      }
      startTokens = toIPv6Tokens(str.substring(0, idx));
      endTokens = toIPv6Tokens(str.substring(idx + 2));
    }

    byte[] ret = new byte[16];
    for (int i = 0; i < startTokens.size(); i++) {
      int off = 2 * i;
      int v = startTokens.get(i);
      ret[off] = (byte) (v >> 8);
      ret[off + 1] = (byte) v;
    }

    int off0 = 2 * (8 - endTokens.size());
    for (int i = 0; i < endTokens.size(); i++) {
      int off = off0 + 2 * i;
      int v = endTokens.get(i);
      ret[off] = (byte) (v >> 8);
      ret[off + 1] = (byte) v;
    }

    return ret;
  }

  private static List<Integer> toIPv6Tokens(String str) {
    if (str.isEmpty()) {
      return Collections.emptyList();
    }

    String[] tokens = str.split(":");
    List<Integer> list = new ArrayList<>(tokens.length + 1);
    for (int idx = 0; idx < tokens.length; idx++) {
      String token = tokens[idx];
      if (token.indexOf('.') >= 0) {
        // an embedded IPv4 address is only allowed at the end, and covers two segments.
        if (idx != tokens.length - 1 || !isValidIPv4(token)) {
          throw new IllegalArgumentException("invalid token " + str);
        }

        byte[] v4 = toIPv4Bytes(token);
        list.add((0xFF & v4[0]) << 8 | (0xFF & v4[1]));
        list.add((0xFF & v4[2]) << 8 | (0xFF & v4[3]));
        continue;
      }

      int i = Integer.parseInt(token, 16);
      if (i >= 0 && i <= 0xFFFF) {
        list.add(i);
      } else {
        throw new IllegalArgumentException("invalid token " + str);
      }
    }
    return list;
  }

  /**
   * Validate the given IPv4 or IPv6 address.
   *
   * @param address the IP address as a String.
   *
   * @return true if a valid address, false otherwise
   */
  public static boolean isValid(String address) {
    return isValidIPv4(address) || isValidIPv6(address);
  }

  /**
   * Validate the given IPv4 or IPv6 address and netmask.
   *
   * @param address the IP address as a String.
   *
   * @return true if a valid address with netmask, false otherwise
   */
  public static boolean isValidWithNetMask(String address) {
    return isValidIPv4WithNetmask(address) || isValidIPv6WithNetmask(address);
  }

  /**
   * Validate the given IPv4 address.
   *
   * @param address the IP address as a String.
   *
   * @return true if a valid IPv4 address, false otherwise
   */
  public static boolean isValidIPv4(String address) {
    int length = address.length();
    if (length < 7 || length > 15) {
      return false;
    }

    int pos = 0;
    for (int octetIndex = 0; octetIndex < 3; ++octetIndex) {
      int end = address.indexOf('.', pos);

      if (!isParseableIPv4Octet(address, pos, end)) {
        return false;
      }

      pos = end + 1;
    }

    return isParseableIPv4Octet(address, pos, length);
  }

  public static boolean isValidIPv4WithNetmask(String address) {
    int index = address.indexOf("/");
    if (index < 1) {
      return false;
    }

    String before = address.substring(0, index);
    String after = address.substring(index + 1);

    return isValidIPv4(before) && (isValidIPv4(after) || isParseableIPv4Mask(after));
  }

  /**
   * Validate the given IPv6 address.
   *
   * @param address the IP address as a String.
   *
   * @return true if a valid IPv6 address, false otherwise
   */
  public static boolean isValidIPv6(String address) {
    if (address.isEmpty()) {
        return false;
    }

    char firstChar = address.charAt(0);
    if (firstChar != ':' && Character.digit(firstChar, 16) < 0) {
        return false;
    }

    // a leading or trailing colon is only allowed as part of "::".
    if ((firstChar == ':' && !address.startsWith("::"))
        || (address.endsWith(":") && !address.endsWith("::"))) {
      return false;
    }

    int segmentCount = 0;
    String temp = address + ":";
    boolean doubleColonFound = false;

    int pos = 0, end;
    while (pos < temp.length() && (end = temp.indexOf(':', pos)) >= pos) {
      if (segmentCount == 8) {
        return false;
      }

      if (pos != end) {
        String value = temp.substring(pos, end);

        if (end == temp.length() - 1 && value.indexOf('.') > 0) {
          // add an extra one as address covers 2 words.
          if (++segmentCount == 8) {
            return false;
          }

          if (!isValidIPv4(value)) {
            return false;
          }
        } else if (!isParseableIPv6Segment(temp, pos, end)) {
          return false;
        }
        ++segmentCount;
      } else {
        if (end != 1 && end != temp.length() - 1 && doubleColonFound) {
          return false;
        }
        doubleColonFound = true;
      }

      pos = end + 1;
    }

    // "::" stands for at least one zero segment.
    return doubleColonFound ? segmentCount < 8 : segmentCount == 8;
  }

  public static boolean isValidIPv6WithNetmask(String address) {
    int index = address.indexOf("/");
    if (index < 1) {
      return false;
    }

    String before = address.substring(0, index);
    String after = address.substring(index + 1);

    return isValidIPv6(before) && (isValidIPv6(after) || isParseableIPv6Mask(after));
  }

  private static boolean isParseableIPv4Mask(String s) {
    return isParseable(s, 0, s.length(), 10, 2, false, 0, 32);
  }

  private static boolean isParseableIPv4Octet(String s, int pos, int end) {
    return isParseable(s, pos, end, 10, 3, true, 0, 255);
  }

  private static boolean isParseableIPv6Mask(String s) {
    return isParseable(s, 0, s.length(), 10, 3, false, 0, 128);
  }

  private static boolean isParseableIPv6Segment(String s, int pos, int end) {
    return isParseable(s, pos, end, 16, 4, true, 0x0000, 0xFFFF);
  }

  private static boolean isParseable(String s, int pos, int end, int radix,
                                     int maxLength, boolean allowLeadingZero,
      int minValue, int maxValue) {
      int length = end - pos;
      if (length < 1 | length > maxLength) {
          return false;
      }

      boolean checkLeadingZero = length > 1 & !allowLeadingZero;
      if (checkLeadingZero && Character.digit(s.charAt(pos), radix) <= 0) {
          return false;
      }

      int value = 0;
      while (pos < end) {
          char c = s.charAt(pos++);
          int d = Character.digit(c, radix);
          if (d < 0) {
              return false;
          }

          value *= radix;
          value += d;
      }

      return value >= minValue & value <= maxValue;
  }

}
