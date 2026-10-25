// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import java.math.BigInteger;

/**
 * Variable-time computation of u1·G + u2·Q for public values (signature verification), in
 * Jacobian coordinates (x = X/Z^2, y = Y/Z^3):
 * <ul>
 *   <li>interleaved width-w NAF of both scalars (Straus / Shamir's trick),</li>
 *   <li>a cached table of affine odd multiples of G (width {@value #W_G}), added with mixed
 *       additions,</li>
 *   <li>a table of odd multiples of Q (width {@value #W_Q}) per call.</li>
 * </ul>
 * The formulas are those of the Explicit-Formulas Database: dbl-2007-bl, add-2007-bl and
 * madd-2007-bl, with explicit handling of the exceptional cases (equal points, opposite points,
 * point at infinity).
 * <p>
 * Do not use it with secret scalars: the running time depends on the scalars.
 *
 * @author Lijun Liao (xipki)
 */
final class VarTimeMultiplier {

  static final int W_G = 7;

  static final int W_Q = 5;

  private final PrimeField f;

  private final int[] a;

  /** affine odd multiples of G: {x, y} of 1G, 3G, ..., (2^(W_G-1) - 1)G. */
  private final int[][][] gTable;

  VarTimeMultiplier(WeierstrassCurve curve) {
    this.f = curve.field;
    this.a = curve.a;

    // G is affine (Z = 1)
    WeierstrassPoint g = curve.getG();
    int[][][] jac = oddMultiples(new int[][]{g.x, g.y, f.one()}, W_G);
    this.gTable = new int[jac.length][][];
    for (int i = 0; i < jac.length; i++) {
      gTable[i] = toAffine(jac[i]);
    }
  }

  /**
   * Returns u1·G + u2·Q.
   * @param u1 the scalar of G, in [0, n).
   * @param u2 the scalar of Q, in [0, n).
   * @param qx the affine x-coordinate of Q (Montgomery form of the field).
   * @param qy the affine y-coordinate of Q (Montgomery form of the field).
   * @return the affine result {x, y}, or null for the point at infinity.
   */
  int[][] sumOfTwoMultiplies(BigInteger u1, BigInteger u2, int[] qx, int[] qy) {
    int[] naf1 = wnaf(u1, W_G);
    int[] naf2 = wnaf(u2, W_Q);
    int[][][] qTable = oddMultiples(new int[][]{qx, qy, f.one()}, W_Q);

    int[][] r = null;
    for (int i = Math.max(naf1.length, naf2.length) - 1; i >= 0; i--) {
      r = dbl(r);

      int d1 = (i < naf1.length) ? naf1[i] : 0;
      if (d1 != 0) {
        int[][] p = gTable[Math.abs(d1) >> 1];
        r = madd(r, p[0], (d1 > 0) ? p[1] : f.neg(p[1]));
      }

      int d2 = (i < naf2.length) ? naf2[i] : 0;
      if (d2 != 0) {
        int[][] p = qTable[Math.abs(d2) >> 1];
        r = add(r, (d2 > 0) ? p : new int[][]{p[0], f.neg(p[1]), p[2]});
      }
    }

    return (r == null) ? null : toAffine(r);
  }

  /**
   * Returns the odd multiples P, 3P, ..., (2^(w-1) - 1)P in Jacobian coordinates.
   */
  private int[][][] oddMultiples(int[][] p, int w) {
    int[][][] t = new int[1 << (w - 2)][][];
    t[0] = p;
    int[][] p2 = dbl(p);
    for (int i = 1; i < t.length; i++) {
      t[i] = add(t[i - 1], p2);
    }
    return t;
  }

  /**
   * Width-w non-adjacent form, least significant digit first. The digits are odd and in
   * (-2^(w-1), 2^(w-1)), or zero.
   */
  static int[] wnaf(BigInteger k, int w) {
    int[] digits = new int[k.bitLength() + 1];
    int len = 0;
    int mask = (1 << w) - 1;
    int half = 1 << (w - 1);

    while (k.signum() > 0) {
      int d = 0;
      if (k.testBit(0)) {
        d = k.intValue() & mask;
        if (d >= half) {
          d -= (1 << w);
        }
        k = k.subtract(BigInteger.valueOf(d));
      }
      digits[len++] = d;
      k = k.shiftRight(1);
    }

    int[] r = new int[len];
    System.arraycopy(digits, 0, r, 0, len);
    return r;
  }

  private int[][] toAffine(int[][] p) {
    if (p == null || f.isZero(p[2])) {
      return null;
    }
    int[] zInv = f.inv(p[2]);
    int[] zInv2 = f.sqr(zInv);
    return new int[][]{f.mul(p[0], zInv2), f.mul(p[1], f.mul(zInv2, zInv))};
  }

  /**
   * Doubling, dbl-2007-bl (1M + 8S + 1·a). null is the point at infinity.
   */
  private int[][] dbl(int[][] p) {
    if (p == null || f.isZero(p[1])) {
      return null;
    }

    int[] x1 = p[0];
    int[] y1 = p[1];
    int[] z1 = p[2];

    int[] xx = f.sqr(x1);
    int[] yy = f.sqr(y1);
    int[] yyyy = f.sqr(yy);
    int[] zz = f.sqr(z1);
    // S = 2*((X1+YY)^2-XX-YYYY)
    int[] s = f.sub(f.sub(f.sqr(f.add(x1, yy)), xx), yyyy);
    s = f.add(s, s);
    // M = 3*XX+a*ZZ^2
    int[] m = f.add(f.add(xx, xx), xx);
    m = f.add(m, f.mul(a, f.sqr(zz)));
    // T = M^2-2*S
    int[] t = f.sub(f.sqr(m), f.add(s, s));
    // Y3 = M*(S-T)-8*YYYY
    int[] yyyy8 = f.add(yyyy, yyyy);
    yyyy8 = f.add(yyyy8, yyyy8);
    yyyy8 = f.add(yyyy8, yyyy8);
    int[] y3 = f.sub(f.mul(m, f.sub(s, t)), yyyy8);
    // Z3 = (Y1+Z1)^2-YY-ZZ
    int[] z3 = f.sub(f.sub(f.sqr(f.add(y1, z1)), yy), zz);
    return new int[][]{t, y3, z3};
  }

  /**
   * Addition, add-2007-bl (11M + 5S). null is the point at infinity.
   */
  private int[][] add(int[][] p, int[][] q) {
    if (p == null) {
      return q;
    }
    if (q == null) {
      return p;
    }

    int[] z1z1 = f.sqr(p[2]);
    int[] z2z2 = f.sqr(q[2]);
    int[] u1 = f.mul(p[0], z2z2);
    int[] u2 = f.mul(q[0], z1z1);
    int[] s1 = f.mul(f.mul(p[1], q[2]), z2z2);
    int[] s2 = f.mul(f.mul(q[1], p[2]), z1z1);
    int[] h = f.sub(u2, u1);
    int[] r = f.sub(s2, s1);

    if (f.isZero(h)) {
      // same x: P = Q or P = -Q
      return f.isZero(r) ? dbl(p) : null;
    }

    r = f.add(r, r);
    int[] i = f.add(h, h);
    i = f.sqr(i);
    int[] j = f.mul(h, i);
    int[] v = f.mul(u1, i);
    // X3 = r^2-J-2*V
    int[] x3 = f.sub(f.sub(f.sqr(r), j), f.add(v, v));
    // Y3 = r*(V-X3)-2*S1*J
    int[] s1j = f.mul(s1, j);
    int[] y3 = f.sub(f.mul(r, f.sub(v, x3)), f.add(s1j, s1j));
    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
    int[] z3 = f.mul(f.sub(f.sub(f.sqr(f.add(p[2], q[2])), z1z1), z2z2), h);
    return new int[][]{x3, y3, z3};
  }

  /**
   * Mixed addition with an affine point (x2, y2), madd-2007-bl (7M + 4S). null is the point at
   * infinity.
   */
  private int[][] madd(int[][] p, int[] x2, int[] y2) {
    if (p == null) {
      return new int[][]{x2, y2, f.one()};
    }

    int[] z1z1 = f.sqr(p[2]);
    int[] u2 = f.mul(x2, z1z1);
    int[] s2 = f.mul(f.mul(y2, p[2]), z1z1);
    int[] h = f.sub(u2, p[0]);
    int[] r = f.sub(s2, p[1]);

    if (f.isZero(h)) {
      return f.isZero(r) ? dbl(p) : null;
    }

    int[] hh = f.sqr(h);
    int[] i = f.add(hh, hh);
    i = f.add(i, i);
    int[] j = f.mul(h, i);
    r = f.add(r, r);
    int[] v = f.mul(p[0], i);
    // X3 = r^2-J-2*V
    int[] x3 = f.sub(f.sub(f.sqr(r), j), f.add(v, v));
    // Y3 = r*(V-X3)-2*Y1*J
    int[] y1j = f.mul(p[1], j);
    int[] y3 = f.sub(f.mul(r, f.sub(v, x3)), f.add(y1j, y1j));
    // Z3 = (Z1+H)^2-Z1Z1-HH
    int[] z3 = f.sub(f.sub(f.sqr(f.add(p[2], h)), z1z1), hh);
    return new int[][]{x3, y3, z3};
  }

}
