// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import java.math.BigInteger;

/**
 * Short Weierstrass curve y^2 = x^3 + ax + b over GF(p) with prime order (cofactor 1).
 * <p>
 * Point addition uses the complete formulas of Renes, Costello and Batina ("Complete addition
 * formulas for prime order elliptic curves", 2016, Algorithm 1) in homogeneous projective
 * coordinates. Together with the Montgomery ladder in {@link WeierstrassPoint#multiply}, scalar
 * multiplication has no branches or memory accesses that depend on the scalar bits.
 *
 * @author Lijun Liao (xipki)
 */
public final class WeierstrassCurve {

  final PrimeField field;

  final int[] a;

  final int[] b;

  final int[] b3;

  private final BigInteger order;

  private final ModN scalars;

  private final WeierstrassPoint g;

  WeierstrassCurve(BigInteger p, BigInteger a, BigInteger b,
                   BigInteger gx, BigInteger gy, BigInteger order) {
    this.field = new PrimeField(p);
    this.a = field.fromBigInteger(a);
    this.b = field.fromBigInteger(b);
    this.b3 = field.add(field.add(this.b, this.b), this.b);
    this.order = order;
    this.scalars = new ModN(order);

    int[] x = field.fromBigInteger(gx);
    int[] y = field.fromBigInteger(gy);
    if (!isOnCurve(x, y)) {
      throw new IllegalArgumentException("base point is not on the curve");
    }
    this.g = new WeierstrassPoint(this, x, y, field.one());
  }

  public WeierstrassPoint getG() {
    return g;
  }

  public BigInteger getOrder() {
    return order;
  }

  /**
   * Returns the arithmetic modulo the order n, for secret scalars.
   * @return the arithmetic modulo n.
   */
  public ModN scalars() {
    return scalars;
  }

  public int getFieldSize() {
    return field.p.bitLength();
  }

  public WeierstrassPoint infinity() {
    return new WeierstrassPoint(this, field.zero(), field.one(), field.zero());
  }

  /**
   * Decodes a point (SEC 1, section 2.3.4) and checks that it is on the curve.
   */
  public WeierstrassPoint decodePoint(byte[] encoded) {
    if (encoded == null || encoded.length == 0) {
      throw new IllegalArgumentException("empty encoded point");
    }

    int len = field.byteLength;
    byte type = encoded[0];
    if (type == 0x00) {
      if (encoded.length != 1) {
        throw new IllegalArgumentException("invalid encoding of the point at infinity");
      }
      return infinity();
    } else if (type == 0x04) {
      if (encoded.length != 1 + 2 * len) {
        throw new IllegalArgumentException("invalid length of uncompressed point");
      }
      int[] x = decodeCoordinate(encoded, 1, len);
      int[] y = decodeCoordinate(encoded, 1 + len, len);
      if (!isOnCurve(x, y)) {
        throw new IllegalArgumentException("point is not on the curve");
      }
      return new WeierstrassPoint(this, x, y, field.one());
    } else if (type == 0x02 || type == 0x03) {
      if (encoded.length != 1 + len) {
        throw new IllegalArgumentException("invalid length of compressed point");
      }
      int[] x = decodeCoordinate(encoded, 1, len);
      int[] y = field.sqrt(rhs(x));
      if (y == null) {
        throw new IllegalArgumentException("point is not on the curve");
      }

      boolean odd = field.toBigInteger(y).testBit(0);
      if (odd != (type == 0x03)) {
        if (field.isZero(y)) {
          throw new IllegalArgumentException("invalid compressed point");
        }
        y = field.neg(y);
      }
      return new WeierstrassPoint(this, x, y, field.one());
    } else {
      throw new IllegalArgumentException("invalid point encoding 0x" + Integer.toHexString(type));
    }
  }

  private int[] decodeCoordinate(byte[] encoded, int off, int len) {
    byte[] bytes = new byte[len];
    System.arraycopy(encoded, off, bytes, 0, len);
    BigInteger v = new BigInteger(1, bytes);
    if (v.compareTo(field.p) >= 0) {
      throw new IllegalArgumentException("coordinate out of range");
    }
    return field.fromBigInteger(v);
  }

  private int[] rhs(int[] x) {
    // x^3 + ax + b
    int[] r = field.mul(field.sqr(x), x);
    r = field.add(r, field.mul(a, x));
    return field.add(r, b);
  }

  boolean isOnCurve(int[] x, int[] y) {
    return field.equal(field.sqr(y), rhs(x));
  }

}
