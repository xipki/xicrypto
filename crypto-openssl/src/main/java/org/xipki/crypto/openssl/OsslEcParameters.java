// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.X9ECParameters;

import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.lang.ref.Reference;
import java.math.BigInteger;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The arithmetic of a Weierstrass curve on EC_GROUP and EC_POINT of OpenSSL. The scalar
 * multiplication of a single point is constant-time in OpenSSL (Montgomery ladder).
 *
 * @author Lijun Liao (xipki)
 */
final class OsslEcParameters implements X9ECParameters, ECCurve {

  private static final Cleaner CLEANER = Cleaner.create();

  private static final Map<Asn1Oid, OsslEcParameters> INSTANCES = new ConcurrentHashMap<>();

  private final OsslCurves.Curve curve;

  private final MemorySegment group;

  private final BigInteger order;

  private final int fieldSize;

  private OsslEcParameters(OsslCurves.Curve curve) {
    this.curve = curve;
    this.group = curve.group();
    this.order = curve.spec().getOrder();
    this.fieldSize = OpenSsl.ecDegree(group);
  }

  /**
   * Returns the parameters of the curve.
   * @return the parameters, or null if the curve is not supported.
   */
  static OsslEcParameters of(Asn1Oid oid) {
    OsslCurves.Curve curve = OsslCurves.byName(oid.getId());
    return (curve == null) ? null
        : INSTANCES.computeIfAbsent(oid, k -> new OsslEcParameters(curve));
  }

  @Override
  public ECCurve getCurve() {
    return this;
  }

  @Override
  public ECPoint getG() {
    return new Point(OpenSsl.ecPointMul(group, BigInteger.ONE, MemorySegment.NULL, null));
  }

  /**
   * u1·G + u2·Q with one EC_POINT_mul.
   */
  @Override
  public ECPoint sumOfTwoMultiplies(BigInteger u1, BigInteger u2, ECPoint q) {
    Point p = point(q);
    try {
      return new Point(OpenSsl.ecPointMul(group, mod(u1), p.point, mod(u2)));
    } finally {
      Reference.reachabilityFence(p);
    }
  }

  @Override
  public BigInteger getOrder() {
    return order;
  }

  @Override
  public int getFieldSize() {
    return fieldSize;
  }

  @Override
  public ECPoint decodePoint(byte[] bytes) {
    MemorySegment point = OpenSsl.ecPointDecode(group, bytes);
    if (OpenSsl.isNull(point)) {
      throw new IllegalArgumentException("invalid point of the curve " + curve.name());
    }
    return new Point(point);
  }

  private Point point(ECPoint p) {
    if (p instanceof Point pt && pt.owner() == this) {
      return pt;
    }
    throw new IllegalArgumentException("point is not on the same curve");
  }

  /** The scalars are reduced modulo the order: OpenSSL requires non-negative values. */
  private BigInteger mod(BigInteger k) {
    return (k.signum() < 0 || k.compareTo(order) >= 0) ? k.mod(order) : k;
  }

  /**
   * A point (EC_POINT), freed when unreachable. The points are immutable.
   */
  private final class Point implements ECPoint {

    private final MemorySegment point;

    Point(MemorySegment point) {
      this.point = point;
      // the action must not reference this object
      CLEANER.register(this, () -> OpenSsl.ecPointFree(point));
    }

    OsslEcParameters owner() {
      return OsslEcParameters.this;
    }

    @Override
    public ECPoint multiply(BigInteger k) {
      try {
        return new Point(OpenSsl.ecPointMul(group, null, point, mod(k)));
      } finally {
        Reference.reachabilityFence(this);
      }
    }

    @Override
    public ECPoint add(ECPoint other) {
      Point o = point(other);
      try {
        return new Point(OpenSsl.ecPointAdd(group, point, o.point));
      } finally {
        Reference.reachabilityFence(this);
        Reference.reachabilityFence(o);
      }
    }

    /** The coordinates are always returned as affine coordinates. */
    @Override
    public ECPoint normalize() {
      return this;
    }

    @Override
    public BigInteger getXCoordBigInt() {
      return coordinate(true);
    }

    @Override
    public BigInteger getYCoordBigInt() {
      return coordinate(false);
    }

    private BigInteger coordinate(boolean x) {
      byte[] encoded = getEncoded(false);
      if (encoded.length == 1) {
        throw new IllegalStateException("the point at infinity has no coordinates");
      }
      int len = (encoded.length - 1) / 2;
      return new BigInteger(1, encoded, x ? 1 : 1 + len, len);
    }

    @Override
    public byte[] getEncoded(boolean compressed) {
      try {
        return OpenSsl.ecPointEncode(group, point, compressed);
      } finally {
        Reference.reachabilityFence(this);
      }
    }

  }

}
