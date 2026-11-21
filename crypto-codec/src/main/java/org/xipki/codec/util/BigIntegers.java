// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * BigInteger utilities.
 * @author Lijun Liao (xipki)
 */
public final class BigIntegers  {

  /**
   * Return the passed in value as an unsigned byte array.
   *
   * @param value the value to be converted.
   * @return a byte array without a leading zero byte if present in the signed encoding.
   */
  public static byte[] asUnsignedByteArray(BigInteger value) {
    byte[] bytes = value.toByteArray();
    return (bytes[0] == 0 && bytes.length > 1)
        ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
  }

  /**
   * Return the passed in value as an unsigned byte array of the specified length, padded with
   * leading zeros as necessary..
   *
   * @param length the fixed length of the result
   * @param value  the value to be converted.
   * @return a byte array padded to a fixed length with leading zeros.
   */
  public static byte[] asUnsignedByteArray(int length, BigInteger value) {
    byte[] buff = new byte[length];
    asUnsignedByteArray(value, buff, 0, length);
    return buff;
  }

  public static void asUnsignedByteArray(BigInteger value, byte[] buff, int off, int length) {
    byte[] keyBytes = value.toByteArray();
    int len = keyBytes.length;

    if (len == length) {
      System.arraycopy(keyBytes, 0, buff, off, length);
    } else if (len < length) {
      System.arraycopy(keyBytes, 0, buff, off + length - len, len);
    } else if (len == length + 1 && keyBytes[0] == 0) {
      System.arraycopy(keyBytes, 1, buff, off, length);
    } else {
      throw new IllegalArgumentException("value too long");
    }
  }

}
