// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal.ec;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.X9ECParameters;
import org.xipki.crypto.jdk.internal.ec.math.EcCurve;
import org.xipki.crypto.jdk.internal.ec.math.WeierstrassCurve;
import org.xipki.crypto.jdk.internal.ec.math.WeierstrassPoint;

import java.math.BigInteger;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Adapter of the curve arithmetic of xicrypto to {@link X9ECParameters} and {@link ECCurve}: the
 * JDK has no public EC arithmetic.
 *
 * @author Lijun Liao (xipki)
 */
public final class XiEcParameters implements X9ECParameters, ECCurve {

  private static final Map<Asn1Oid, X9ECParameters> CACHE = new ConcurrentHashMap<>();

  private final EcCurve curve;

  private final WeierstrassCurve wc;

  /**
   * Returns the parameters of the curve, with the arithmetic of xicrypto.
   * @param oid the curve OID.
   * @return the parameters, or null if the curve is not supported.
   */
  public static X9ECParameters of(Asn1Oid oid) {
    EcCurve curve = EcCurve.ofOid(oid);
    return (curve == null) ? null : CACHE.computeIfAbsent(oid, k -> new XiEcParameters(curve));
  }

  private XiEcParameters(EcCurve curve) {
    this.curve = curve;
    this.wc = curve.weierstrassCurve();
  }

  @Override
  public ECCurve getCurve() {
    return this;
  }

  @Override
  public ECPoint getG() {
    return new Point(wc.getG());
  }

  @Override
  public BigInteger getOrder() {
    return wc.getOrder();
  }

  @Override
  public int getFieldSize() {
    return wc.getFieldSize();
  }

  @Override
  public ECPoint decodePoint(byte[] bytes) {
    return new Point(wc.decodePoint(bytes));
  }

  /**
   * Variable-time u1·G + u2·Q of xicrypto.
   */
  @Override
  public ECPoint sumOfTwoMultiplies(BigInteger u1, BigInteger u2, ECPoint q) {
    ECPoint nq = q.normalize();
    java.security.spec.ECPoint r = curve.sumOfTwoMultiplies(u1, u2,
        new java.security.spec.ECPoint(nq.getXCoordBigInt(), nq.getYCoordBigInt()));
    if (java.security.spec.ECPoint.POINT_INFINITY.equals(r)) {
      return new Point(wc.infinity());
    }
    return decodePoint(curve.encodePoint(r));
  }

  private final class Point implements ECPoint {

    private final WeierstrassPoint p;

    Point(WeierstrassPoint p) {
      this.p = p;
    }

    @Override
    public ECPoint multiply(BigInteger k) {
      return new Point(p.multiply(k));
    }

    @Override
    public ECPoint add(ECPoint other) {
      if (!(other instanceof Point)) {
        throw new IllegalArgumentException("point is not on the same curve");
      }
      return new Point(p.add(((Point) other).p));
    }

    @Override
    public ECPoint normalize() {
      return new Point(p.normalize());
    }

    @Override
    public BigInteger getXCoordBigInt() {
      return p.getXCoordBigInt();
    }

    @Override
    public BigInteger getYCoordBigInt() {
      return p.getYCoordBigInt();
    }

    @Override
    public byte[] getEncoded(boolean compressed) {
      return p.getEncoded(compressed);
    }

  }

}
