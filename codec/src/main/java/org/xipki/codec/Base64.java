// #THIRDPARTY#
// original license BSD.

package org.xipki.codec;

import org.xipki.codec.util.Args;

import java.util.Arrays;

/**
 * Base64.
 *
 * @author original author
 * @author Lijun Liao (xipki)
 */
public abstract class Base64 {

  private static final char[] STD_CA =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

  private static final char[] URL_CA;

  private static final int[] IA = new int[256];

  private static final Encoder pemEncoder = new Encoder(false, true, false, 64);

  private static final Encoder encoder = new Encoder(false, true);

  private static final Encoder noPaddingEncoder = new Encoder(false, false);

  private static final Encoder urlEncoder = new Encoder(true, true);

  private static final Encoder urlNoPaddingEncoder = new Encoder(true, false);

  static {
    URL_CA = STD_CA.clone();
    URL_CA[62] = '-';
    URL_CA[63] = '_';

    Arrays.fill(IA, -1);
    for (int i = 0, is = STD_CA.length; i < is; ++i) {
      IA[STD_CA[i]] = i;
    }
    IA['='] = 0;

    IA['-'] = 62;
    IA['_'] = 63;
  }

  public static Encoder getEncoder() {
    return encoder;
  }

  public static Encoder getUrlEncoder() {
    return urlEncoder;
  }

  public static Encoder getNoPaddingEncoder() {
    return noPaddingEncoder;
  }

  public static Encoder getUrlNoPaddingEncoder() {
    return urlNoPaddingEncoder;
  }

  public static byte[] encodeToByte(byte[] sArr) {
    return encoder.encodeToByte(sArr);
  }

  public static char[] encodeToChar(byte[] sArr) {
    return encoder.encodeToChar(sArr);
  }

  public static String encodeToString(byte[] sArr) {
    return encoder.encodeToString(sArr);
  }

  public static byte[] encodeToByte(byte[] sArr, boolean lineSep) {
    return encoder.encodeToByte(sArr, lineSep);
  }

  public static char[] encodeToChar(byte[] sArr, boolean lineSep) {
    return encoder.encodeToChar(sArr, lineSep);
  }

  public static String encodeToString(byte[] sArr, boolean lineSep) {
    return encoder.encodeToString(sArr, lineSep);
  }

  public static boolean containsOnlyValidChars(byte[] bytes) {
    return containsOnlyValidChars(bytes, 0, bytes.length);
  }

  public static boolean containsOnlyValidChars(byte[] bytes, int off, int len) {
    int endIndex = off + len;
    for (int i = off; i < endIndex; i++) {
      int x = bytes[i] & 0xFF;
      if ((x >= '0' && x <= '9')
          || (x >= 'a' && x <= 'z')
          || (x >= 'A' && x <= 'Z')
          || (x == '=') || (x == '+') || (x == '/')
          || (x == '-') || (x == '_')) {
        continue;
      }

      return false;
    }

    return true;
  }

  /**
   * Encodes a raw byte array into a PEM <code>byte[]</code> representation
   * in accordance with RFC 2045, with line 64 characters per line, and with
   * LF as line separator.
   * @param sArr
   *          The bytes to convert. If <code>null</code> or length 0 an empty
   *          array will be returned.
   * @return A BASE64 encoded array. Never <code>null</code>.
   */
  public static String encodeToPemString(byte[] sArr) {
    Args.notNull(sArr, "sArr");
    return pemEncoder.encodeToString(sArr, true);
  }

  public static byte[] encodeToPemByte(byte[] sArr) {
    Args.notNull(sArr, "sArr");
    return pemEncoder.encodeToByte(sArr, true);
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded char array. Whitespaces (e.g. line
   * separators) are ignored, other invalid characters are rejected.
   * @param sArr The source array. <code>null</code> or length 0 will return an
   *             empty array.
   * @return The decoded array of bytes. Maybe of length 0.
   */
  public static byte[] decode(char[] sArr) {
    // Check special case
    int sLen = sArr != null ? sArr.length : 0;
    if (sLen == 0) {
      return new byte[0];
    }

    // count the data characters and padding, and validate the characters.
    int n = 0;
    int pad = 0;
    for (int i = 0; i < sLen; i++) {
      char c = sArr[i];
      if (c == '=') {
        pad++;
      } else if (c < 256 && IA[c] >= 0) {
        if (pad > 0) {
          throw new IllegalArgumentException("invalid Base64: '=' within the data");
        }
        n++;
      } else if (!isWhitespace(c)) {
        throw new IllegalArgumentException("invalid Base64 character at index " + i);
      }
    }

    checkLength(n, pad);

    byte[] dArr = new byte[n * 6 >> 3];
    int d = 0;
    int acc = 0;
    int j = 0;
    for (int i = 0; i < sLen; i++) {
      char c = sArr[i];
      if (c == '=' || c >= 256 || IA[c] < 0) {
        continue;
      }

      acc = (acc << 6) | IA[c];
      if (++j == 4) {
        dArr[d++] = (byte) (acc >> 16);
        dArr[d++] = (byte) (acc >> 8);
        dArr[d++] = (byte) acc;
        acc = 0;
        j = 0;
      }
    }

    finalBytes(dArr, d, acc, j);
    return dArr;
  }

  /**
   * Decodes a BASE64 /BASE64-URL encoded char array that is known to be reasonably well formatted.
   * The method is about twice as fast as {@link #decode(char[])}. The preconditions are:<br>
   * + Whitespaces at the beginning and end are ignored.<br>
   * + If the input contains whitespaces (e.g. line separators) within the encoded string,
   *   {@code decode} will be used.<br>
   * + Other invalid characters, and invalid length or padding are rejected with
   *   IllegalArgumentException.<br>
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(char[] sArr) {
    int sIx = 0;
    int eIx = sArr.length - 1;    // Start and end index after trimming.

    // Trim whitespaces from start and end
    while (sIx <= eIx && isWhitespace(sArr[sIx])) {
      ++sIx;
    }

    while (eIx >= sIx && isWhitespace(sArr[eIx])) {
      --eIx;
    }

    // get the padding count (=)
    int pad = 0;
    while (eIx >= sIx && sArr[eIx] == '=') {
      ++pad;
      --eIx;
    }

    for (int i = sIx; i <= eIx; i++) {
      char c = sArr[i];
      if (c == '=' || c >= 256 || IA[c] < 0) {
        if (isWhitespace(c)) {
          // e.g. with line separators: use the decoder which ignores the whitespaces.
          return decode(sArr);
        }
        throw new IllegalArgumentException("invalid Base64 character at index " + i);
      }
    }

    int n = eIx - sIx + 1;
    checkLength(n, pad);

    int len = n * 6 >> 3; // The number of decoded bytes
    byte[] dArr = new byte[len];

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++]] << 18 | IA[sArr[sIx++]] << 12
          | IA[sArr[sIx++]] << 6 | IA[sArr[sIx++]];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;
    }

    // Decode the last 2-3 chars into 1-2 bytes
    int acc = 0;
    int j = 0;
    for (; sIx <= eIx; j++) {
      acc = (acc << 6) | IA[sArr[sIx++]];
    }
    finalBytes(dArr, d, acc, j);

    return dArr;
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded <code>String</code>. Whitespaces (e.g. line
   * separators) are ignored, other invalid characters are rejected.<br>
   * <b>Note!</b> It can be up to about 2x the speed to call
   * <code>decode(str.toCharArray())</code> instead. That will create a temporary array though.
   * This version will use <code>str.charAt(i)</code> to iterate the string.
   * @param str
   *          The source string. <code>null</code> or length 0 will return an empty array.
   * @return The decoded array of bytes. May be of length 0.
   * @throws IllegalArgumentException
   *         If the input contains invalid characters, or has invalid length or padding.
   */
  public static byte[] decode(String str) {    // Check special case
    return str == null || str.isEmpty() ? new byte[0] : decode(str.toCharArray());
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded string that is known to be resonably well formatted.
   * The method is about twice as fast as {@link #decode(String)}. The preconditions are:<br>
   * + Whitespaces at the beginning and end are ignored.<br>
   * + If the input contains whitespaces (e.g. line separators) within the encoded string,
   *   {@code decode} will be used.<br>
   * + Other invalid characters, and invalid length or padding are rejected with
   *   IllegalArgumentException.<br>
   * @param s
   *          The source string. Length 0 will return an empty array. <code>null</code> will
   *          throw an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(String s) {
    return s == null || s.isEmpty() ? new byte[0] : decodeFast(s.toCharArray());
  }

  /**
   * Decodes a BASE64 / BASE64URL encoded byte array. Whitespaces (e.g. line
   * separators) are ignored, other invalid characters are rejected.
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   * @throws IllegalArgumentException
   *         If the input contains invalid characters, or has invalid length or padding.
   */
  public static byte[] decode(byte[] sArr) {
    // Check special cases
    int sLen = sArr.length;
    if (sLen == 0) {
      return new byte[0];
    }

    // count the data characters and padding, and validate the characters.
    int n = 0;
    int pad = 0;
    for (int i = 0; i < sLen; i++) {
      int c = sArr[i] & 0xff;
      if (c == '=') {
        pad++;
      } else if (IA[c] >= 0) {
        if (pad > 0) {
          throw new IllegalArgumentException("invalid Base64: '=' within the data");
        }
        n++;
      } else if (!isWhitespace((char) c)) {
        throw new IllegalArgumentException("invalid Base64 character at index " + i);
      }
    }

    checkLength(n, pad);

    byte[] dArr = new byte[n * 6 >> 3];
    int d = 0;
    int acc = 0;
    int j = 0;
    for (int i = 0; i < sLen; i++) {
      int c = sArr[i] & 0xff;
      if (c == '=' || IA[c] < 0) {
        continue;
      }

      acc = (acc << 6) | IA[c];
      if (++j == 4) {
        dArr[d++] = (byte) (acc >> 16);
        dArr[d++] = (byte) (acc >> 8);
        dArr[d++] = (byte) acc;
        acc = 0;
        j = 0;
      }
    }

    finalBytes(dArr, d, acc, j);
    return dArr;
  }

  /**
   * Decodes a BASE64 / BASE64-URL encoded byte array that is known to be reasonably well formatted.
   * The method is about twice as fast as {@link #decode(byte[])}. The preconditions are:<br>
   * + Whitespaces at the beginning and end are ignored.<br>
   * + If the input contains whitespaces (e.g. line separators) within the encoded string,
   *   {@code decode} will be used.<br>
   * + Other invalid characters, and invalid length or padding are rejected with
   *   IllegalArgumentException.<br>
   * @param sArr
   *          The source array. Length 0 will return an empty array. <code>null</code> will throw
   *          an exception.
   * @return The decoded array of bytes. May be of length 0.
   */
  public static byte[] decodeFast(byte[] sArr) {
    int sIx = 0;
    int eIx = sArr.length - 1;    // Start and end index after trimming.

    // Trim whitespaces from start and end
    while (sIx <= eIx && isWhitespace((char) (sArr[sIx] & 0xff))) {
      ++sIx;
    }

    while (eIx >= sIx && isWhitespace((char) (sArr[eIx] & 0xff))) {
      --eIx;
    }

    // get the padding count (=)
    int pad = 0;
    while (eIx >= sIx && sArr[eIx] == '=') {
      ++pad;
      --eIx;
    }

    for (int i = sIx; i <= eIx; i++) {
      int c = sArr[i] & 0xff;
      if (c == '=' || IA[c] < 0) {
        if (isWhitespace((char) c)) {
          // e.g. with line separators: use the decoder which ignores the whitespaces.
          return decode(sArr);
        }
        throw new IllegalArgumentException("invalid Base64 character at index " + i);
      }
    }

    int n = eIx - sIx + 1;
    checkLength(n, pad);

    int len = n * 6 >> 3; // The number of decoded bytes
    byte[] dArr = new byte[len];

    // Decode all but the last 0 - 2 bytes.
    int d = 0;
    for (int eLen = (len / 3) * 3; d < eLen;) {
      // Assemble three bytes into an int from four "valid" characters.
      int i = IA[sArr[sIx++] & 0xff] << 18 | IA[sArr[sIx++] & 0xff] << 12
          | IA[sArr[sIx++] & 0xff] << 6 | IA[sArr[sIx++] & 0xff];

      // Add the bytes
      dArr[d++] = (byte) (i >> 16);
      dArr[d++] = (byte) (i >> 8);
      dArr[d++] = (byte) i;
    }

    // Decode the last 2-3 chars into 1-2 bytes
    int acc = 0;
    int j = 0;
    for (; sIx <= eIx; j++) {
      acc = (acc << 6) | IA[sArr[sIx++] & 0xff];
    }
    finalBytes(dArr, d, acc, j);

    return dArr;
  }

  private static boolean isWhitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  }

  /**
   * Checks the number of data characters and padding characters.
   * @param n number of data characters, without padding.
   * @param pad number of padding characters '='.
   */
  private static void checkLength(int n, int pad) {
    // n % 4 == 1 cannot be decoded, the padding (if present) must complete the last quantum.
    if (pad > 2 || (n & 3) == 1 || (pad > 0 && ((n + pad) & 3) != 0)) {
      throw new IllegalArgumentException("invalid Base64 length");
    }
  }

  /**
   * Writes the last 1-2 bytes encoded in the remaining j (2 or 3) characters.
   */
  private static void finalBytes(byte[] dArr, int d, int acc, int j) {
    if (j == 2) {
      dArr[d] = (byte) (acc >> 4);
    } else if (j == 3) {
      dArr[d]     = (byte) (acc >> 10);
      dArr[d + 1] = (byte) (acc >> 2);
    }
  }

  public static class Encoder {

    private final boolean base64Url;

    private final boolean withPadding;

    private final boolean CRLFAsLineSep;

    private final int charsPerLine;

    private Encoder(boolean base64Url, boolean withPadding) {
      this(base64Url, withPadding, true, 76);
    }

    private Encoder(boolean base64Url, boolean withPadding,
                    boolean CRLFAsLineSep, int charsPerLine) {
      this.base64Url = base64Url;
      this.withPadding = withPadding;
      this.CRLFAsLineSep = CRLFAsLineSep;
      this.charsPerLine = charsPerLine;
    }

    public boolean containsOnlyValidChars(byte[] bytes, int off, int len) {
      int endIndex = off + len;
      for (int i = off; i < endIndex; i++) {
        int x = bytes[i] & 0xFF;
        if ((x >= '0' && x <= '9')
            || (x >= 'a' && x <= 'z')
            || (x >= 'A' && x <= 'Z')
            || (x == '\r' || x == '\n')) {
          continue;
        }

        switch (x) {
          case '=':
            if (!withPadding) {
              return false;
            }
            break;
          case '+':
          case '/':
            if (base64Url) {
              return false;
            }
            break;
          case '-':
          case '_':
            if (!base64Url) {
              return false;
            }
            break;
          default:
            return false;
        }
      }

      return true;
    }

    /**
     * The same as encodeToChar(byte[], false)
     *
     * @param sArr The bytes to convert. If <code>null</code> or length 0, an
     *             empty array will be returned.
     * @return A BASE64 encoded array without line separator.
     */
    public char[] encodeToChar(byte[] sArr) {
      return encodeToChar(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>char[]</code> representation
     * in accordance with RFC 2045.
     *
     * @param sArr The bytes to convert. If <code>null</code> or length 0 an
     *            empty array will be returned.
     * @param lineSep
     *          Optional "\r\n" or "\n" after 76 characters, unless end of file.<br>
     *          No line separator will be in breach of RFC 2045 which specifies
     *          max 76 per line but will be a little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public char[] encodeToChar(byte[] sArr, boolean lineSep) {
      // Check special case
      int sLen = sArr != null ? sArr.length : 0;
      if (sLen == 0) {
        return new char[0];
      }
      //assert sArr != null;

      // Length of even 24-bits.
      int eLen = (sLen / 3) * 3;
      // Returned character count
      int cCnt = ((sLen - 1) / 3 + 1) << 2;

      // Length of returned array
      int dLen = cCnt;
      if (lineSep) {
        int numSeps = (cCnt - 1) / charsPerLine;
        dLen += numSeps;
        if (CRLFAsLineSep) {
          dLen += numSeps;
        }
      }

      int left = sLen - eLen;
      if (!withPadding && left > 0) {
        dLen -= (left == 1) ? 2 : 1;
      }

      char[] dArr = new char[dLen];

      char[] CA = base64Url ? URL_CA : STD_CA;

      // Encode even 24-bits
      final int numGroups = charsPerLine / 4;

      for (int s = 0, d = 0, cc = 0; s < eLen;) {
        // Copy the next three bytes into lower 24 bits of int, paying attention to sign.
        int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

        // Encode the int into four chars
        dArr[d++] = CA[(i >>> 18) & 0x3f];
        dArr[d++] = CA[(i >>> 12) & 0x3f];
        dArr[d++] = CA[(i >>> 6)  & 0x3f];
        dArr[d++] = CA[ i         & 0x3f];

        // Add optional line separator
        if (lineSep && ++cc == numGroups && d < dLen - 2) {
          if (CRLFAsLineSep) {
            dArr[d++] = '\r';
          }
          dArr[d++] = '\n';
          cc = 0;
        }
      }

      // Pad and encode last bits if source isn't even 24 bits.
      if (left > 0) {
        // Prepare the int
        int i = ((sArr[eLen] & 0xff) << 10)
            | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

        int off;
        if (withPadding) {
          off = dLen - 4;
        } else {
          off = (left == 2) ? dLen - 3 : dLen - 2;
        }

        // Set last four chars
        dArr[off++] = CA[ i >> 12];
        dArr[off++] = CA[(i >>> 6) & 0x3f];

        if (withPadding) {
          dArr[off++] = left == 2 ? CA[i & 0x3f] : '=';
          dArr[off] = '=';
        } else {
          if (left == 2) {
            dArr[off] = CA[i & 0x3f];
          }
        }
      }

      return dArr;
    }

    // *******************
    // *  byte[] version
    // *******************

    /**
     *
     * The same #encodeToByte(byte[], false)}.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty
     *          array will be returned.
     * @return A BASE64 encoded array without line separator. Never <code>null</code>.
     */
    public byte[] encodeToByte(byte[] sArr) {
      return encodeToByte(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>byte[]</code> representation in accordance with
     * RFC 2045.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @param lineSep
     *         Optional "\r\n" or "\n" after 76 characters, unless end of file.<br>
     *         No line separator will be in breach of RFC 2045 which specifies max 76 per line but
     *         will be a little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public byte[] encodeToByte(byte[] sArr, boolean lineSep) {
      if ((charsPerLine & 0x3) != 0) {
        throw new IllegalArgumentException("charsPerLine % 4 != 0");
      }

      // number of 3-byte groups
      final int nn = charsPerLine >> 2;

      // Check special cases
      int sLen = sArr != null ? sArr.length : 0;
      if (sLen == 0) {
        return new byte[0];
      }
      //assert sArr != null;

      // Length of even 24-bits.
      int eLen = (sLen / 3) * 3;
      // Returned character count
      int cCnt = ((sLen - 1) / 3 + 1) << 2;

      // Length of returned array
      int dLen = cCnt;
      if (lineSep) {
        int numSeps = (cCnt - 1) / charsPerLine;
        dLen += numSeps;
        if (CRLFAsLineSep) {
          dLen += numSeps;
        }
      }

      int left = sLen - eLen;
      if (!withPadding && left > 0) {
        dLen -= (left == 1) ? 2 : 1;
      }

      byte[] dArr = new byte[dLen];

      char[] CA = base64Url ? URL_CA : STD_CA;

      // Encode even 24-bits
      for (int s = 0, d = 0, cc = 0; s < eLen;) {
        // Copy next three bytes into lower 24 bits of int, paying attention to sign.
        int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

        // Encode the int into four chars
        dArr[d++] = (byte) CA[(i >>> 18) & 0x3f];
        dArr[d++] = (byte) CA[(i >>> 12) & 0x3f];
        dArr[d++] = (byte) CA[(i >>> 6)  & 0x3f];
        dArr[d++] = (byte) CA[ i         & 0x3f];

        // Add optional line separator
        if (lineSep && ++cc == nn && d < dLen - 2) {
          if (CRLFAsLineSep) {
            dArr[d++] = '\r';
          }
          dArr[d++] = '\n';
          cc = 0;
        }
      }

      // Pad and encode last bits if source isn't an even 24 bits.
      if (left > 0) {
        // Prepare the int
        int i = ((sArr[eLen] & 0xff) << 10)
            | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

        int off;
        if (withPadding) {
          off = dLen - 4;
        } else {
          off = (left == 2) ? dLen - 3 : dLen - 2;
        }

        // Set last four chars
        dArr[off++] = (byte) CA[ i >> 12];
        dArr[off++] = (byte) CA[(i >>> 6) & 0x3f];

        if (withPadding) {
          dArr[off++] = left == 2 ? (byte) CA[i & 0x3f] : (byte) '=';
          dArr[off] = '=';
        } else {
          if (left == 2) {
            dArr[off] = (byte) CA[i & 0x3f];
          }
        }
      }
      return dArr;
    }

    // ******************
    // * String version
    // ******************

    /**
     *
     * The same as encodeToString(byte[], false).
     *
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @return A BASE64 encoded array without line separator. Never <code>null</code>.
     */
    public String encodeToString(byte[] sArr) {
      return encodeToString(sArr, false);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>String</code> representation in accordance with
     * RFC 2045.
     * @param sArr
     *          The bytes to convert. If <code>null</code> or length 0 an empty array will be
     *          returned.
     * @param lineSep
     *          Optional "\r\n" or "\n" after {@link #charsPerLine} characters, unless end of file.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    public String encodeToString(byte[] sArr, boolean lineSep) {
      // Reuse char[] since we can't create a String incrementally anyway and StringBuffer/Builder
      // would be slower.
      return new String(encodeToChar(sArr, lineSep));
    }

  }
}
