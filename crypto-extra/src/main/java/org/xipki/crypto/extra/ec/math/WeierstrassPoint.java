// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Point of a {@link WeierstrassCurve} in homogeneous projective coordinates (X : Y : Z).
 * The point at infinity is (0 : 1 : 0). Instances are immutable.
 *
 * @author Lijun Liao (xipki)
 */
public final class WeierstrassPoint {

  private final WeierstrassCurve curve;

  final int[] x;

  final int[] y;

  final int[] z;

  WeierstrassPoint(WeierstrassCurve curve, int[] x, int[] y, int[] z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    this.z = z;
  }

  public WeierstrassCurve getCurve() {
    return curve;
  }

  public boolean isInfinity() {
    return curve.field.isZero(z);
  }

  public WeierstrassPoint add(WeierstrassPoint other) {
    return add(this, cast(other));
  }

  /**
   * Scalar multiplication with the Montgomery ladder. The scalar is reduced modulo the order n.
   * The conversion of the {@link BigInteger} is not constant-time; the ladder itself does not
   * depend on the scalar.
   */
  public WeierstrassPoint multiply(BigInteger k) {
    return multiply(curve.scalars().fromBigInteger(k.mod(curve.getOrder())));
  }

  /**
   * Scalar multiplication with the Montgomery ladder, constant-time.
   * @param k the scalar, an element of {@link WeierstrassCurve#scalars()}.
   * @return k times this point.
   */
  public WeierstrassPoint multiply(ModN.Element k) {
    int[] limbs = curve.scalars().plainLimbs(k);
    try {
      return multiplyLimbs(limbs);
    } finally {
      Arrays.fill(limbs, 0);
    }
  }

  /**
   * The ladder: for every bit of the order (most significant first) one addition and one
   * doubling. The bit is taken from the limbs by shifts and applied by conditional swaps, so
   * neither the control flow nor the memory accesses depend on the scalar.
   * @param k the scalar in [0, n), as little-endian 32-bit limbs of the length of the order.
   */
  WeierstrassPoint multiplyLimbs(int[] k) {
    BigInteger order = curve.getOrder();
    if (k.length != (order.bitLength() + 31) / 32) {
      throw new IllegalArgumentException("invalid length of the scalar");
    }

    WeierstrassPoint inf = curve.infinity();
    int[][] r0 = {inf.x, inf.y, inf.z};
    int[][] r1 = {x.clone(), y.clone(), z.clone()};

    for (int i = order.bitLength() - 1; i >= 0; i--) {
      int bit = (k[i >>> 5] >>> (i & 31)) & 1;
      cswap(r0, r1, bit);
      WeierstrassPoint p0 = new WeierstrassPoint(curve, r0[0], r0[1], r0[2]);
      WeierstrassPoint p1 = new WeierstrassPoint(curve, r1[0], r1[1], r1[2]);
      WeierstrassPoint sum = add(p0, p1);
      WeierstrassPoint dbl = add(p0, p0);
      r1 = new int[][]{sum.x, sum.y, sum.z};
      r0 = new int[][]{dbl.x, dbl.y, dbl.z};
      cswap(r0, r1, bit);
    }

    return new WeierstrassPoint(curve, r0[0], r0[1], r0[2]);
  }

  public WeierstrassPoint normalize() {
    PrimeField f = curve.field;
    if (isInfinity()) {
      return curve.infinity();
    }

    int[] zInv = f.inv(z);
    return new WeierstrassPoint(curve, f.mul(x, zInv), f.mul(y, zInv), f.one());
  }

  public BigInteger getXCoordBigInt() {
    return curve.field.toBigInteger(affine().x);
  }

  /**
   * Returns the affine x coordinate as big-endian bytes of the field length. Constant-time,
   * unlike {@link #getXCoordBigInt()}, e.g. for an ECDH shared secret.
   * @return the x coordinate.
   */
  public byte[] getXCoordBytes() {
    return curve.field.toBytes(affine().x);
  }

  public BigInteger getYCoordBigInt() {
    return curve.field.toBigInteger(affine().y);
  }

  public byte[] getEncoded(boolean compressed) {
    if (isInfinity()) {
      return new byte[1];
    }

    // constant-time: the coordinates are encoded directly from the limbs
    WeierstrassPoint p = affine();
    int len = curve.field.byteLength;
    byte[] xb = curve.field.toBytes(p.x);
    byte[] yb = curve.field.toBytes(p.y);
    if (compressed) {
      byte[] r = new byte[1 + len];
      r[0] = (byte) (0x02 | (yb[len - 1] & 1));
      System.arraycopy(xb, 0, r, 1, len);
      return r;
    } else {
      byte[] r = new byte[1 + 2 * len];
      r[0] = 0x04;
      System.arraycopy(xb, 0, r, 1, len);
      System.arraycopy(yb, 0, r, 1 + len, len);
      return r;
    }
  }

  private WeierstrassPoint affine() {
    if (isInfinity()) {
      throw new IllegalStateException("point at infinity has no affine coordinates");
    }
    return normalize();
  }

  private WeierstrassPoint cast(WeierstrassPoint other) {
    if (other.curve != curve) {
      throw new IllegalArgumentException("point is not on the same curve");
    }
    return other;
  }

  private static void cswap(int[][] a, int[][] b, int bit) {
    for (int i = 0; i < 3; i++) {
      PrimeField.cswap(a[i], b[i], bit);
    }
  }

  /**
   * Complete addition, Algorithm 1 of Renes, Costello and Batina (2016).
   */
  private static WeierstrassPoint add(WeierstrassPoint p, WeierstrassPoint q) {
    WeierstrassCurve c = p.curve;
    PrimeField f = c.field;
    int[] a = c.a;
    int[] b3 = c.b3;

    int[] x1 = p.x;
    int[] y1 = p.y;
    int[] z1 = p.z;
    int[] x2 = q.x;
    int[] y2 = q.y;
    int[] z2 = q.z;

    int[] t0 = f.mul(x1, x2);
    int[] t1 = f.mul(y1, y2);
    int[] t2 = f.mul(z1, z2);
    int[] t3 = f.add(x1, y1);
    int[] t4 = f.add(x2, y2);
    t3 = f.mul(t3, t4);
    t4 = f.add(t0, t1);
    t3 = f.sub(t3, t4);
    t4 = f.add(x1, z1);
    int[] t5 = f.add(x2, z2);
    t4 = f.mul(t4, t5);
    t5 = f.add(t0, t2);
    t4 = f.sub(t4, t5);
    t5 = f.add(y1, z1);
    int[] x3 = f.add(y2, z2);
    t5 = f.mul(t5, x3);
    x3 = f.add(t1, t2);
    t5 = f.sub(t5, x3);
    int[] z3 = f.mul(a, t4);
    x3 = f.mul(b3, t2);
    z3 = f.add(x3, z3);
    x3 = f.sub(t1, z3);
    z3 = f.add(t1, z3);
    int[] y3 = f.mul(x3, z3);
    t1 = f.add(t0, t0);
    t1 = f.add(t1, t0);
    t2 = f.mul(a, t2);
    t4 = f.mul(b3, t4);
    t1 = f.add(t1, t2);
    t2 = f.sub(t0, t2);
    t2 = f.mul(a, t2);
    t4 = f.add(t4, t2);
    t0 = f.mul(t1, t4);
    y3 = f.add(y3, t0);
    t0 = f.mul(t5, t4);
    x3 = f.mul(t3, x3);
    x3 = f.sub(x3, t0);
    t0 = f.mul(t3, t1);
    z3 = f.mul(t5, z3);
    z3 = f.add(z3, t0);

    return new WeierstrassPoint(c, x3, y3, z3);
  }

}
