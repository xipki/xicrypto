// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.util;

/**
 * General array utilities.
 *
 * @author BouncyCastle
 * @author Lijun Liao (xipki)
 */
public final class Arrays {

  private Arrays() {
    // static class, hide constructor
  }

  /**
   * A constant time equals comparison - does not terminate early if
   * test will fail. For best results always pass the expected value
   * as the first parameter.
   *
   * @param expected first array
   * @param supplied second array
   * @return true if arrays equal, false otherwise.
   */
  public static boolean constantTimeAreEqual(byte[] expected, byte[] supplied) {
    if (expected == null || supplied == null) {
      return false;
    }

    if (expected == supplied) {
      return true;
    }

    int len = (expected.length < supplied.length) ? expected.length : supplied.length;

    int nonEqual = expected.length ^ supplied.length;

    for (int i = 0; i != len; i++) {
      nonEqual |= (expected[i] ^ supplied[i]);
    }

    for (int i = len; i < supplied.length; i++) {
      nonEqual |= (supplied[i] ^ ~supplied[i]);
    }

    return nonEqual == 0;
  }

  public static byte[] clone(byte[] data) {
    return null == data ? null : data.clone();
  }

  public static byte[] concatenate(byte[]... bytesList) {
    int len = 0;
    for (byte[] m : bytesList) {
      len += m.length;
    }

    byte[] r = new byte[len];
    int off = 0;
    for (byte[] m : bytesList) {
      System.arraycopy(m, 0, r, off, m.length);
      off += m.length;
    }
    return r;
  }

  /**
   * Fill input array by zeros
   *
   * @param data input array
   */
  public static void clear(byte[] data) {
    if (null != data) {
      java.util.Arrays.fill(data, (byte)0x00);
    }
  }

  public static void clear(char[] data) {
    if (null != data) {
      java.util.Arrays.fill(data, ' ');
    }
  }

  public static int getIndex(byte[] arrayA, byte[] arrayB) {
    int endIndex = arrayA.length - arrayB.length;
    for (int i = 0; i <= endIndex; i++) {
      boolean found = true;
      for (int j = 0; j < arrayB.length; j++) {
        if (arrayA[i + j] != arrayB[j]) {
          found = false;
          break;
        }
      }
      if (found) {
        return i;
      }
    }
    return -1;
  }
}
