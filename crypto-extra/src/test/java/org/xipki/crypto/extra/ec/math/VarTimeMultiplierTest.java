// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;

/**
 * Compares the variable-time u1·G + u2·Q ({@link VarTimeMultiplier}) with the constant-time
 * ladder, including the exceptional cases of the addition formulas.
 *
 * @author Lijun Liao (xipki)
 */
public class VarTimeMultiplierTest {

  private static final Asn1Oid[] CURVES = {
      CurveOIDs.secp256r1, CurveOIDs.secp384r1, CurveOIDs.secp521r1,
      CurveOIDs.brainpoolP256r1, CurveOIDs.brainpoolP384r1, CurveOIDs.brainpoolP512r1,
      CurveOIDs.sm2p256v1, CurveOIDs.frp256v1};

  private static final SecureRandom RND = new SecureRandom();

  @Test
  public void testWnaf() {
    for (int w = 2; w <= 8; w++) {
      for (int i = 0; i < 200; i++) {
        BigInteger k = new BigInteger(1 + RND.nextInt(530), RND);
        int[] naf = VarTimeMultiplier.wnaf(k, w);
        BigInteger sum = BigInteger.ZERO;
        int lastNonZero = -w;
        for (int j = 0; j < naf.length; j++) {
          int d = naf[j];
          if (d != 0) {
            Assert.assertTrue("digit must be odd", (d & 1) != 0);
            Assert.assertTrue("digit out of range", Math.abs(d) < (1 << (w - 1)));
            Assert.assertTrue("not non-adjacent", j - lastNonZero >= w);
            lastNonZero = j;
          }
          sum = sum.add(BigInteger.valueOf(d).shiftLeft(j));
        }
        Assert.assertEquals(k, sum);
      }
    }
    Assert.assertEquals(0, VarTimeMultiplier.wnaf(BigInteger.ZERO, 5).length);
  }

  @Test
  public void testRandom() {
    for (Asn1Oid oid : CURVES) {
      EcCurve curve = EcCurve.ofOid(oid);
      if (curve == null) {
        // SM2 with xipki.crypto.disableSm=true
        continue;
      }
      BigInteger n = curve.order();
      for (int i = 0; i < 20; i++) {
        ECPoint q = curve.multiplyG(scalar(n));
        BigInteger u1 = scalar(n);
        BigInteger u2 = scalar(n);
        Assert.assertEquals(oid.getId(), ladder(curve, u1, u2, q),
            curve.sumOfTwoMultiplies(u1, u2, q));
      }
    }
  }

  @Test
  public void testExceptionalCases() {
    for (Asn1Oid oid : CURVES) {
      EcCurve curve = EcCurve.ofOid(oid);
      if (curve == null) {
        // SM2 with xipki.crypto.disableSm=true
        continue;
      }
      BigInteger n = curve.order();
      ECPoint g = curve.parameterSpec().getGenerator();
      ECPoint minusG = curve.multiplyG(n.subtract(BigInteger.ONE));
      ECPoint q = curve.multiplyG(scalar(n));
      BigInteger u = scalar(n);
      BigInteger[] scalars = {BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, u,
          n.subtract(BigInteger.ONE), n.subtract(u)};

      for (ECPoint p : new ECPoint[]{g, minusG, q}) {
        for (BigInteger u1 : scalars) {
          for (BigInteger u2 : scalars) {
            Assert.assertEquals(oid.getId() + " u1=" + u1 + " u2=" + u2,
                ladder(curve, u1, u2, p),
                curve.sumOfTwoMultiplies(u1, u2, p));
          }
        }
      }

      // results at infinity: u·G + (n-u)·G and u·G + u·(-G)
      Assert.assertEquals(ECPoint.POINT_INFINITY, curve.sumOfTwoMultiplies(u, n.subtract(u), g));
      Assert.assertEquals(ECPoint.POINT_INFINITY, curve.sumOfTwoMultiplies(u, u, minusG));
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testInvalidPoint() {
    EcCurve curve = EcCurve.ofOid(CurveOIDs.brainpoolP256r1);
    ECPoint g = curve.parameterSpec().getGenerator();
    curve.sumOfTwoMultiplies(BigInteger.ONE, BigInteger.ONE,
        new ECPoint(g.getAffineX(), g.getAffineY().add(BigInteger.ONE)));
  }

  private static BigInteger scalar(BigInteger n) {
    BigInteger k;
    do {
      k = new BigInteger(n.bitLength(), RND);
    } while (k.signum() == 0 || k.compareTo(n) >= 0);
    return k;
  }

  /**
   * Returns u1·G + u2·Q with the constant-time ladder, as reference.
   */
  private static ECPoint ladder(EcCurve curve, BigInteger u1, BigInteger u2, ECPoint q) {
    WeierstrassCurve wc = curve.weierstrassCurve();
    WeierstrassPoint r = wc.getG().multiply(u1)
        .add(wc.decodePoint(curve.encodePoint(q)).multiply(u2));
    return r.isInfinity() ? ECPoint.POINT_INFINITY
        : new ECPoint(r.getXCoordBigInt(), r.getYCoordBigInt());
  }

}
