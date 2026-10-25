// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Tests the backend-neutral Weierstrass curve arithmetic against BouncyCastle.
 *
 * @author Lijun Liao (xipki)
 */
public class EcFallbackTest {

  private static final Asn1Oid[] CURVES = {
      CurveOIDs.secp256r1, CurveOIDs.secp384r1, CurveOIDs.secp521r1,
      CurveOIDs.brainpoolP256r1, CurveOIDs.brainpoolP384r1, CurveOIDs.brainpoolP512r1,
      CurveOIDs.sm2p256v1, CurveOIDs.frp256v1};

  private static final SecureRandom RND = new SecureRandom();

  @Test
  public void testParameters() {
    for (Asn1Oid oid : CURVES) {
      WeierstrassCurve params = EcCurve.ofOid(oid).weierstrassCurve();
      org.bouncycastle.asn1.x9.X9ECParameters bc = bcParams(oid);

      WeierstrassCurve curve = params;
      Assert.assertEquals(oid.getId(), bc.getN(), curve.getOrder());
      Assert.assertEquals(oid.getId(), bc.getCurve().getFieldSize(), curve.getFieldSize());
      Assert.assertArrayEquals(oid.getId(), bc.getG().getEncoded(false),
          params.getG().getEncoded(false));
      Assert.assertArrayEquals(oid.getId(), bc.getG().getEncoded(true),
          params.getG().getEncoded(true));
    }
  }

  @Test
  public void testMultiplyAndAdd() {
    for (Asn1Oid oid : CURVES) {
      WeierstrassCurve params = EcCurve.ofOid(oid).weierstrassCurve();
      org.bouncycastle.asn1.x9.X9ECParameters bc = bcParams(oid);
      BigInteger n = bc.getN();

      for (int i = 0; i < 5; i++) {
        BigInteger k1 = new BigInteger(n.bitLength() + 8, RND);
        BigInteger k2 = new BigInteger(n.bitLength() - 1, RND);

        WeierstrassPoint p1 = params.getG().multiply(k1);
        WeierstrassPoint p2 = params.getG().multiply(k2);
        org.bouncycastle.math.ec.ECPoint bc1 = bc.getG().multiply(k1.mod(n)).normalize();
        org.bouncycastle.math.ec.ECPoint bc2 = bc.getG().multiply(k2).normalize();

        Assert.assertArrayEquals(oid.getId(), bc1.getEncoded(false), p1.getEncoded(false));
        Assert.assertEquals(oid.getId(), bc1.getAffineXCoord().toBigInteger(),
            p1.normalize().getXCoordBigInt());
        Assert.assertEquals(oid.getId(), bc1.getAffineYCoord().toBigInteger(),
            p1.getYCoordBigInt());

        // add, including doubling
        Assert.assertArrayEquals(oid.getId(), bc1.add(bc2).normalize().getEncoded(false),
            p1.add(p2).getEncoded(false));
        Assert.assertArrayEquals(oid.getId(), bc1.twice().normalize().getEncoded(false),
            p1.add(p1).getEncoded(false));

        // multiply a decoded point (as in ECDH)
        WeierstrassPoint decoded = params.decodePoint(bc2.getEncoded(true));
        Assert.assertArrayEquals(oid.getId(), bc2.multiply(k1.mod(n)).normalize().getEncoded(false),
            decoded.multiply(k1).normalize().getEncoded(false));
      }
    }
  }

  @Test
  public void testSpecialPoints() {
    for (Asn1Oid oid : CURVES) {
      WeierstrassCurve params = EcCurve.ofOid(oid).weierstrassCurve();
      WeierstrassPoint g = params.getG();
      BigInteger n = params.getOrder();

      // n * G = infinity, encoded as 0x00
      WeierstrassPoint inf = g.multiply(n);
      Assert.assertArrayEquals(oid.getId(), new byte[1], inf.getEncoded(false));
      Assert.assertArrayEquals(oid.getId(), new byte[1], g.multiply(BigInteger.ZERO)
          .getEncoded(false));

      // G + infinity = G
      Assert.assertArrayEquals(oid.getId(), g.getEncoded(false), g.add(inf).getEncoded(false));
      Assert.assertArrayEquals(oid.getId(), g.getEncoded(false), inf.add(g).getEncoded(false));

      // G + (n-1) G = infinity
      WeierstrassPoint minusG = g.multiply(n.subtract(BigInteger.ONE));
      Assert.assertArrayEquals(oid.getId(), new byte[1], g.add(minusG).getEncoded(false));

      // (n-1) G = -G: same x, y' = p - y
      Assert.assertEquals(oid.getId(), g.getXCoordBigInt(), minusG.getXCoordBigInt());

      // decode infinity
      Assert.assertArrayEquals(oid.getId(), new byte[1],
          params.decodePoint(new byte[1]).getEncoded(true));
    }
  }

  @Test
  public void testInvalidPoints() {
    for (Asn1Oid oid : CURVES) {
      WeierstrassCurve params = EcCurve.ofOid(oid).weierstrassCurve();
      WeierstrassCurve curve = params;
      byte[] encoded = params.getG().getEncoded(false);

      // not on the curve
      byte[] invalid = encoded.clone();
      invalid[invalid.length - 1] ^= 1;
      assertInvalid(curve, invalid);

      // wrong length
      assertInvalid(curve, java.util.Arrays.copyOf(encoded, encoded.length - 1));

      // invalid type
      invalid = encoded.clone();
      invalid[0] = 0x05;
      assertInvalid(curve, invalid);

      // x >= p
      int len = (curve.getFieldSize() + 7) / 8;
      byte[] tooLarge = new byte[1 + len];
      tooLarge[0] = 0x02;
      java.util.Arrays.fill(tooLarge, 1, tooLarge.length, (byte) 0xFF);
      assertInvalid(curve, tooLarge);
    }
  }

  @Test
  public void testCurveLookup() {
    for (Asn1Oid oid : CURVES) {
      Assert.assertNotNull(oid.getId(), EcCurve.ofOid(oid));
    }
    // secp256k1 is not supported
    Assert.assertNull(EcCurve.ofOid(new Asn1Oid("1.3.132.0.10")));

    Assert.assertEquals(CurveOIDs.brainpoolP256r1, EcCurve.ofName("brainpoolP256r1").oid());
    Assert.assertEquals(CurveOIDs.secp256r1, EcCurve.ofName("P-256").oid());
    Assert.assertEquals(CurveOIDs.sm2p256v1, EcCurve.ofName("SM2").oid());
    Assert.assertEquals(CurveOIDs.frp256v1,
        EcCurve.ofName(CurveOIDs.frp256v1.getId()).oid());
    Assert.assertNull(EcCurve.ofName("unknown"));
  }

  private static void assertInvalid(WeierstrassCurve curve, byte[] encoded) {
    try {
      curve.decodePoint(encoded);
      Assert.fail("expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  private static org.bouncycastle.asn1.x9.X9ECParameters bcParams(Asn1Oid oid) {
    return ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(oid.getId()));
  }

}
