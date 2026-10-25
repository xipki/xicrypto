// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.ipadress;

import org.xipki.codec.util.Args;
import org.xipki.codec.Hex;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * IPAddress.
 * <pre>
 * IPAddress ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddress {

  /**
   * Context enumeration.
   */
  public enum Context {
    PREFIX,
    RANGE_MIN,
    RANGE_MAX,
    C509_RANGE_MIN,
    C509_RANGE_MAX
  }

  private final byte[] value;

  private final int unusedBits;

  public IPAddress(byte[] value, int unusedBits) {
    this.unusedBits = unusedBits;
    this.value = Args.notEmptyBytes(value, "value");
  }

  public IPAddress(byte[] value) {
    this(value, 0);
  }

  public byte[] value() {
    return value;
  }

  public int unusedBits() {
    return unusedBits;
  }

  public String toString(int afi, Context context) {
    byte[] bytes = value.clone();
    if (unusedBits > 0) {
      int b = bytes[bytes.length - 1];
      bytes[bytes.length - 1] = (byte) ((b >> unusedBits) << unusedBits);
    }

    boolean isIPv4 = afi == IPAddressFamily.AFI_IPv4;
    boolean isIPv6 = afi == IPAddressFamily.AFI_IPv6;

    if (context == Context.RANGE_MIN) {
      if (isIPv4 || isIPv6) {
        int len = (afi == IPAddressFamily.AFI_IPv4) ? 4 : 16;
        if (bytes.length < len) {
          bytes = Arrays.copyOf(bytes, len);
        }
      }
    } else if (context == Context.RANGE_MAX) {
      if (isIPv4 || isIPv6) {
        int len = isIPv4 ? 4 : 16;
        // create the mask
        byte[] mask = new byte[len];
        int bytesLen = bytes.length;

        Arrays.fill(mask, (byte) 0xFF);
        for (int i = 0; i < bytesLen; i++) {
          mask[i] = 0;
        }

        if (unusedBits > 0) {
          int k = ~((0xFF >>> unusedBits) << unusedBits);
          mask[bytesLen - 1] = (byte) k;
        }

        for (int i = 0; i < bytesLen; i++) {
          mask[i] |= bytes[i];
        }

        bytes = mask;
      }
    }

    StringBuilder sb = new StringBuilder();
    if (isIPv4) {
      switch (context) {
        case PREFIX:
          for (int i = 0; i < bytes.length; i++) {
            if (i != 0) {
              sb.append(".");
            }
            sb.append(0xFF & bytes[i]);
          }

          if (bytes.length < 4) {
            sb.append(".0".repeat(4 - bytes.length));
          }

          int prefixLen = bytes.length * 8 - unusedBits;
          sb.append("/").append(prefixLen);
          break;
        case RANGE_MIN:
        case RANGE_MAX:
          for (int i = 0; i < bytes.length; i++) {
            if (i != 0) {
              sb.append(".");
            }
            sb.append(0xFF & bytes[i]);
          }
      }
    } else if (isIPv6) {
      switch (context) {
        case PREFIX:
          sb.append(toStringIPv6Address(bytes)).append("/").append(8 * bytes.length - unusedBits);
          break;
        case RANGE_MIN:
        case RANGE_MAX:
          sb.append(toStringIPv6Address(bytes));
          break;
      }
    } else {
      sb.append(Hex.encode(value)).append(" (unused bits ").append(unusedBits).append(")");
    }
    return sb.toString();
  }

  private static String toStringIPv6Address(byte[] bytes) {
    // do not consider the ending zeros
    int endIndexOfNonZeros = bytes.length; // exclusive
    if (bytes[bytes.length - 1] == 0) {
      if (bytes.length % 2 != 0) {
        endIndexOfNonZeros--;
      }

      while (endIndexOfNonZeros > 2) {
        if (bytes[endIndexOfNonZeros - 1] == 0 && bytes[endIndexOfNonZeros - 2] == 0) {
          endIndexOfNonZeros -= 2;
        } else {
          break;
        }
      }
    }

    int numTokens = (endIndexOfNonZeros + 1) / 2;
    int[] tokens = new int[numTokens];
    for (int i = 0; i < numTokens; i++) {
      int off = i * 2;
      tokens[i] = (0xFF & bytes[off]) << 8;
      if (off + 1 < bytes.length) {
        tokens[i] |= (0xFF & bytes[off + 1]);
      }
    }

    int zerosStartIndex = -1; // inclusive
    int zerosEndIndex   = -1; // inclusive

    for (int i = 0; i < numTokens; i++) {
      int token = tokens[i];
      if (token == 0) {
        if (zerosStartIndex == -1) {
          zerosStartIndex = i;
          zerosEndIndex = i;
        } else {
          zerosEndIndex = i;
        }
      } else {
        if (zerosStartIndex != -1) {
          break;
        }
      }
    }

    StringBuilder sb = new StringBuilder();
    if (zerosStartIndex == -1 || zerosStartIndex == zerosEndIndex) {
      for (int i = 0; i < numTokens; i++) {
        if (i != 0) {
          sb.append(":");
        }

        sb.append(Integer.toHexString(tokens[i]));
      }
    } else {
      for (int i = 0; i < zerosStartIndex; i++) {
        if (i != 0) {
          sb.append(":");
        }

        sb.append(Integer.toHexString(tokens[i]));
      }
      sb.append("::");

      for (int i = zerosEndIndex + 1; i < numTokens; i++) {
        if (i != zerosEndIndex + 1) {
          sb.append(":");
        }
        sb.append(Integer.toHexString(tokens[i]));
      }
    }

    if (numTokens < 8 &&
        !(sb.charAt(sb.length() - 1) == ':' && sb.charAt(sb.length() - 2) == ':')) {
      sb.append("::");
    }

    return sb.toString();
  }

  public static IPAddress getIPv4Instance(String str, Context context) {
    return getInstance(true, str, context);
  }

  public static IPAddress getIPv6Instance(String str, Context context) {
    return getInstance(false, str, context);
  }

  public static IPAddress getInstance(boolean ipv4, String str, Context context) {
    int numFullBytes = ipv4 ? 4 : 16;

    int prefixLen = -1;
    if (context == Context.PREFIX) {
      prefixLen = 8 * numFullBytes;
      int idx = str.indexOf('/');
      if (idx != -1) {
        prefixLen = Integer.parseInt(str.substring(idx + 1));
        str = str.substring(0, idx);
      }
    }

    byte[] bytes = ipv4 ? toIPv4Bytes(str) : toIPv6Bytes(str);

    switch (context) {
      case PREFIX: {
        int numBytes = (prefixLen + 7) / 8;
        bytes = (bytes.length == numBytes) ? bytes : Arrays.copyOf(bytes, numBytes);
        int unusedBits = (8 - (prefixLen % 8)) % 8;

        if (unusedBits != 0) {
          int x = bytes[bytes.length - 1];
          bytes[bytes.length - 1] = (byte) ((x >> unusedBits) << unusedBits);
        }

        return new IPAddress(bytes, unusedBits);
      }
      case RANGE_MIN:
      case RANGE_MAX:
      case C509_RANGE_MIN:
      case C509_RANGE_MAX: {
        BigInteger bn = new BigInteger(1, bytes);
        boolean min = context == Context.RANGE_MIN || context == Context.C509_RANGE_MIN;
        int numDefaultBits = 0;
        boolean dfltBitSet = !min;
        for (int i = 0; i < bytes.length * 8; i++) {
          if (dfltBitSet != bn.testBit(i)) {
            break;
          }
          numDefaultBits++;
        }

        if (context == Context.C509_RANGE_MIN || context == Context.C509_RANGE_MAX) {
          numDefaultBits = numDefaultBits / 8 * 8;
        }

        bn = bn.shiftRight(numDefaultBits);
        int unusedBits = numDefaultBits % 8;
        if (unusedBits != 0) {
          bn = bn.shiftLeft(unusedBits);
        }

        int numBytes = numFullBytes - numDefaultBits / 8;
        byte[] bnBytes = bn.toByteArray();
        if (bnBytes.length == numBytes) {
          bytes = bnBytes;
        } else if (bnBytes.length < numBytes) {
          System.arraycopy(bnBytes, 0, bytes, numBytes - bnBytes.length, bnBytes.length);
        } else {
          System.arraycopy(bnBytes, 1, bytes, 0, numBytes);
        }

        return new IPAddress(bytes, unusedBits);
      }
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

  private static byte[] toIPv4Bytes(String str) {
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

  private static byte[] toIPv6Bytes(String str) {
    List<Integer> startTokens;
    List<Integer> endTokens;
    int idx = str.indexOf("::");
    if (idx == -1) {
      startTokens = toIPv6Tokens(str);
      endTokens = Collections.emptyList();
    } else {
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
    List<Integer> list = new ArrayList<>(tokens.length);
    for (String token : tokens) {
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
      } else {
        if (end != 1 && end != temp.length() - 1 && doubleColonFound) {
          return false;
        }
        doubleColonFound = true;
      }

      pos = end + 1;
      ++segmentCount;
    }

    return segmentCount == 8 || doubleColonFound;
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
    return isParseable(s, 0, s.length(), 10, 3, false, 1, 128);
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
