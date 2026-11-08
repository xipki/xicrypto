// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.ipadress;

import org.xipki.codec.util.Args;
import org.xipki.codec.Hex;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The IPAddress type defined in RFC 3779.
 * <pre>
 * IPAddress ::= BIT STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Rfc3779IPAddress {

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

  public Rfc3779IPAddress(byte[] value, int unusedBits) {
    this.value = Args.notNull(value, "value");
    // an empty value is the zero-length prefix (/0), which has no byte to hold unused bits.
    if (value.length == 0 && unusedBits != 0) {
      throw new IllegalArgumentException("unusedBits must be 0 for an empty value");
    }
    this.unusedBits = unusedBits;
  }

  public Rfc3779IPAddress(byte[] value) {
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
          for (int i = 0; i < 4; i++) {
            if (i != 0) {
              sb.append(".");
            }
            sb.append(i < bytes.length ? 0xFF & bytes[i] : 0);
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
    if (bytes.length == 0) {
      return "::";
    }

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

  public static Rfc3779IPAddress getIPv4Instance(String str, Context context) {
    return getInstance(true, str, context);
  }

  public static Rfc3779IPAddress getIPv6Instance(String str, Context context) {
    return getInstance(false, str, context);
  }

  public static Rfc3779IPAddress getInstance(boolean ipv4, String str, Context context) {
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

    byte[] bytes = ipv4 ? IPAddressUtil.toIPv4Bytes(str) : IPAddressUtil.toIPv6Bytes(str);

    switch (context) {
      case PREFIX: {
        int numBytes = (prefixLen + 7) / 8;
        bytes = (bytes.length == numBytes) ? bytes : Arrays.copyOf(bytes, numBytes);
        int unusedBits = (8 - (prefixLen % 8)) % 8;

        if (unusedBits != 0) {
          int x = bytes[bytes.length - 1];
          bytes[bytes.length - 1] = (byte) ((x >> unusedBits) << unusedBits);
        }

        return new Rfc3779IPAddress(bytes, unusedBits);
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

        int unusedBits = numDefaultBits % 8;
        bytes = Arrays.copyOf(bytes, numFullBytes - numDefaultBits / 8);
        if (unusedBits != 0) {
          int x = bytes[bytes.length - 1];
          bytes[bytes.length - 1] = (byte) ((x >> unusedBits) << unusedBits);
        }

        return new Rfc3779IPAddress(bytes, unusedBits);
      }
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

}
