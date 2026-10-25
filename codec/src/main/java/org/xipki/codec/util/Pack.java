// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.util;

/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 *
 * @author BouncyCastle
 * @author Lijun Liao (xipki)
 */
public abstract class Pack {

  public static int bigEndianToInt(byte[] bs, int off) {
    int n = bs[off] << 24;
    n |= (bs[++off] & 0xff) << 16;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff);
    return n;
  }

  public static byte[] intToBigEndian(int n) {
    byte[] bs = new byte[4];
    intToBigEndian(n, bs, 0);
    return bs;
  }

  public static void intToBigEndian(int n, byte[] bs, int off) {
    bs[off] = (byte)(n >>> 24);
    bs[++off] = (byte)(n >>> 16);
    bs[++off] = (byte)(n >>> 8);
    bs[++off] = (byte)(n);
  }

  public static void intToBigEndian(int[] ns, byte[] bs, int off) {
    for (int n : ns) {
      intToBigEndian(n, bs, off);
      off += 4;
    }
  }

  public static long bigEndianToLong(byte[] bs, int off) {
    int hi = bigEndianToInt(bs, off);
    int lo = bigEndianToInt(bs, off + 4);
    return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
  }

  public static byte[] longToBigEndian(long n) {
    byte[] bs = new byte[8];
    longToBigEndian(n, bs, 0);
    return bs;
  }

  public static void longToBigEndian(long n, byte[] bs, int off) {
    intToBigEndian((int)(n >>> 32), bs, off);
    intToBigEndian((int)(n & 0xffffffffL), bs, off + 4);
  }

  public static int littleEndianToInt(byte[] bs, int off) {
    int n = bs[off] & 0xff;
    n |= (bs[++off] & 0xff) << 8;
    n |= (bs[++off] & 0xff) << 16;
    n |= bs[++off] << 24;
    return n;
  }

  public static void intToLittleEndian(int n, byte[] bs, int off) {
    bs[off] = (byte)(n);
    bs[++off] = (byte)(n >>> 8);
    bs[++off] = (byte)(n >>> 16);
    bs[++off] = (byte)(n >>> 24);
  }

  public static long littleEndianToLong(byte[] bs, int off) {
    int lo = littleEndianToInt(bs, off);
    int hi = littleEndianToInt(bs, off + 4);
    return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
  }

  public static byte[] longToLittleEndian(long n)
  {
      byte[] bs = new byte[8];
      longToLittleEndian(n, bs, 0);
      return bs;
  }

  public static void longToLittleEndian(long n, byte[] bs, int off)
  {
      intToLittleEndian((int)(n & 0xffffffffL), bs, off);
      intToLittleEndian((int)(n >>> 32), bs, off + 4);
  }

  public static int parseInt(byte[] bytes, int offset) {
    return  (0xFF & bytes[offset++]) << 24 | (0xFF & bytes[offset++]) << 16
          | (0xFF & bytes[offset++]) << 8  |  0xFF & bytes[offset];
  }
}
