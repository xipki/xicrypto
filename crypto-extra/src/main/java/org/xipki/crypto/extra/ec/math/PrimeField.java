// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.xipki.codec.util.BigIntegers;

import java.math.BigInteger;

/**
 * Arithmetic in the prime field GF(p), in Montgomery representation.
 * <p>
 * Elements are little-endian arrays of 32-bit limbs. Addition, subtraction, multiplication
 * and conditional swap run without secret-dependent branches or memory accesses. So do the
 * conversions from and to fixed-length byte arrays ({@link #fromBytes(byte[])},
 * {@link #toBytes(int[])}). The conversions from and to {@link BigInteger} are not
 * constant-time (leading zeros); they are applied only to public values, or at the API boundary.
 *
 * @author Lijun Liao (xipki)
 */
final class PrimeField {

  private static final long M = 0xFFFFFFFFL;

  final BigInteger p;

  final int n;

  final int byteLength;

  private final int[] pl;

  private final long n0inv;

  private final int[] r2;

  private final int[] one;

  PrimeField(BigInteger p) {
    if (p.signum() <= 0 || !p.testBit(0)) {
      throw new IllegalArgumentException("p is not an odd prime");
    }

    this.p = p;
    this.n = (p.bitLength() + 31) / 32;
    this.byteLength = (p.bitLength() + 7) / 8;
    this.pl = toLimbs(p, n);

    // -p^{-1} mod 2^32
    long p0 = pl[0] & M;
    long x = p0;
    for (int i = 0; i < 5; i++) {
      x = (x * (2 - p0 * x)) & M;
    }
    this.n0inv = (-x) & M;

    BigInteger r = BigInteger.ONE.shiftLeft(32 * n);
    this.one = toLimbs(r.mod(p), n);
    this.r2 = toLimbs(r.multiply(r).mod(p), n);
  }

  int[] zero() {
    return new int[n];
  }

  int[] one() {
    return one.clone();
  }

  /**
   * Converts a value in [0, p) into Montgomery form.
   */
  int[] fromBigInteger(BigInteger v) {
    if (v.signum() < 0 || v.compareTo(p) >= 0) {
      throw new IllegalArgumentException("value out of range");
    }
    return mul(toLimbs(v, n), r2);
  }

  /**
   * Converts a big-endian unsigned value of at most 4n bytes into Montgomery form, reduced
   * mod p. Any value below R = 2^(32n) is accepted. Constant-time for a given length.
   */
  int[] fromBytes(byte[] be) {
    return mul(limbsFromBytes(be, n), r2);
  }

  /**
   * Returns the value of a (Montgomery form) as big-endian bytes of exactly
   * {@link #byteLength} bytes. Constant-time.
   */
  byte[] toBytes(int[] a) {
    int[] v = toPlain(a);
    byte[] out = new byte[byteLength];
    for (int i = 0; i < byteLength; i++) {
      out[byteLength - 1 - i] = (byte) (v[i >>> 2] >>> (8 * (i & 3)));
    }
    return out;
  }

  /**
   * Converts from Montgomery form into the plain value, as limbs.
   */
  int[] toPlain(int[] a) {
    int[] t = new int[n];
    t[0] = 1;
    return mul(a, t);
  }

  BigInteger toBigInteger(int[] a) {
    return new BigInteger(1, toBytes(a));
  }

  /**
   * Returns whether the plain value (limbs, not Montgomery form) is in [1, p-1]. Constant-time;
   * only the result is revealed.
   */
  boolean isInRangeNonZero(int[] plain) {
    int acc = 0;
    long borrow = 0;
    for (int i = 0; i < n; i++) {
      acc |= plain[i];
      long t = (plain[i] & M) - (pl[i] & M) - borrow;
      borrow = (t >>> 63);
    }
    // nonZero == 1 iff acc != 0; borrow == 1 iff plain < p
    int nonZero = (acc | -acc) >>> 31;
    return (nonZero & (int) borrow) == 1;
  }

  /**
   * Converts a big-endian unsigned value of at most 4n bytes into n little-endian limbs.
   * The running time depends only on the length.
   */
  static int[] limbsFromBytes(byte[] be, int n) {
    if (be.length > 4 * n) {
      throw new IllegalArgumentException("value too long");
    }
    int[] limbs = new int[n];
    for (int i = 0; i < be.length; i++) {
      int b = be[be.length - 1 - i] & 0xFF;
      limbs[i >>> 2] |= b << (8 * (i & 3));
    }
    return limbs;
  }

  int[] add(int[] a, int[] b) {
    int[] s = new int[n];
    long carry = 0;
    for (int i = 0; i < n; i++) {
      long t = (a[i] & M) + (b[i] & M) + carry;
      s[i] = (int) t;
      carry = t >>> 32;
    }
    return reduceOnce(s, carry);
  }

  int[] sub(int[] a, int[] b) {
    int[] d = new int[n];
    long borrow = 0;
    for (int i = 0; i < n; i++) {
      long t = (a[i] & M) - (b[i] & M) - borrow;
      d[i] = (int) t;
      borrow = (t >>> 63);
    }

    // add p if borrow
    long mask = -borrow & M;
    long carry = 0;
    for (int i = 0; i < n; i++) {
      long t = (d[i] & M) + (pl[i] & mask) + carry;
      d[i] = (int) t;
      carry = t >>> 32;
    }
    return d;
  }

  int[] neg(int[] a) {
    return sub(new int[n], a);
  }

  /**
   * Montgomery multiplication (CIOS): returns a * b * R^{-1} mod p.
   */
  int[] mul(int[] a, int[] b) {
    long[] t = new long[n + 2];
    for (int i = 0; i < n; i++) {
      long ai = a[i] & M;
      long c = 0;
      for (int j = 0; j < n; j++) {
        long s = t[j] + ai * (b[j] & M) + c;
        t[j] = s & M;
        c = s >>> 32;
      }
      long s = t[n] + c;
      t[n] = s & M;
      t[n + 1] = s >>> 32;

      long m = (t[0] * n0inv) & M;
      s = t[0] + m * (pl[0] & M);
      c = s >>> 32;
      for (int j = 1; j < n; j++) {
        s = t[j] + m * (pl[j] & M) + c;
        t[j - 1] = s & M;
        c = s >>> 32;
      }
      s = t[n] + c;
      t[n - 1] = s & M;
      t[n] = t[n + 1] + (s >>> 32);
      t[n + 1] = 0;
    }

    int[] r = new int[n];
    for (int i = 0; i < n; i++) {
      r[i] = (int) t[i];
    }
    return reduceOnce(r, t[n]);
  }

  int[] sqr(int[] a) {
    return mul(a, a);
  }

  /**
   * Returns a^e. The exponent e must be public.
   */
  int[] pow(int[] a, BigInteger e) {
    int[] r = one();
    for (int i = e.bitLength() - 1; i >= 0; i--) {
      r = sqr(r);
      if (e.testBit(i)) {
        r = mul(r, a);
      }
    }
    return r;
  }

  int[] inv(int[] a) {
    return pow(a, p.subtract(BigInteger.TWO));
  }

  /**
   * Returns a square root of a, or null if a is not a quadratic residue.
   */
  int[] sqrt(int[] a) {
    if (!p.testBit(1)) {
      throw new UnsupportedOperationException("sqrt is only supported for p = 3 mod 4");
    }

    int[] r = pow(a, p.add(BigInteger.ONE).shiftRight(2));
    return equal(sqr(r), a) ? r : null;
  }

  boolean isZero(int[] a) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
      acc |= a[i];
    }
    return acc == 0;
  }

  boolean equal(int[] a, int[] b) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
      acc |= a[i] ^ b[i];
    }
    return acc == 0;
  }

  /**
   * Swaps a and b in place if bit is 1, without branching on bit.
   */
  static void cswap(int[] a, int[] b, int bit) {
    int mask = -bit;
    for (int i = 0; i < a.length; i++) {
      int t = mask & (a[i] ^ b[i]);
      a[i] ^= t;
      b[i] ^= t;
    }
  }

  /**
   * Given v < 2p, represented by the limbs and a carry, returns v mod p.
   */
  private int[] reduceOnce(int[] v, long carry) {
    int[] u = new int[n];
    long borrow = 0;
    for (int i = 0; i < n; i++) {
      long t = (v[i] & M) - (pl[i] & M) - borrow;
      u[i] = (int) t;
      borrow = (t >>> 63);
    }

    // use u if carry == 1 or borrow == 0, i.e. v >= p
    int useU = (int) (carry | (borrow ^ 1));
    int mask = -useU;
    for (int i = 0; i < n; i++) {
      v[i] = (u[i] & mask) | (v[i] & ~mask);
    }
    return v;
  }

  private static int[] toLimbs(BigInteger v, int n) {
    return limbsFromBytes(BigIntegers.asUnsignedByteArray(4 * n, v), n);
  }

}
