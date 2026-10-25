// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * Tests the constant-time arithmetic ({@link ModN}, the byte conversions of {@link PrimeField},
 * the encoding of points and the ladder with limbs) against {@link BigInteger}.
 *
 * @author Lijun Liao (xipki)
 */
public class ModNTest {

  private static final SecureRandom RND = new SecureRandom();

  /** the curves; sm2p256v1 only if the SM algorithms are not disabled. */
  private static final String[] CURVES = EcCurve.isSmDisabled()
      ? new String[] {"secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1",
          "brainpoolP512r1", "frp256v1"}
      : new String[] {"secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1",
          "brainpoolP512r1", "frp256v1", "sm2p256v1"};

  @Test
  public void testArithmetic() {
    for (String name : CURVES) {
      ModN m = curve(name).scalarField();
      BigInteger n = m.modulus();
      for (int i = 0; i < 200; i++) {
        BigInteger a = random(n);
        BigInteger b = random(n);
        ModN.Element ea = m.fromBigInteger(a);
        ModN.Element eb = m.fromBigInteger(b);
        Assert.assertEquals(name, a, m.toBigInteger(ea));
        Assert.assertEquals(name, a.add(b).mod(n), m.toBigInteger(m.add(ea, eb)));
        Assert.assertEquals(name, a.subtract(b).mod(n), m.toBigInteger(m.sub(ea, eb)));
        Assert.assertEquals(name, a.multiply(b).mod(n), m.toBigInteger(m.mul(ea, eb)));
        if (a.signum() != 0) {
          Assert.assertEquals(name, a.modInverse(n), m.toBigInteger(m.inv(ea)));
        }
      }
      Assert.assertTrue(m.isZero(m.fromBigInteger(BigInteger.ZERO)));
      Assert.assertTrue(m.isZero(m.fromBigInteger(n)));
      Assert.assertTrue(m.isZero(m.inv(m.fromBigInteger(BigInteger.ZERO))));
      Assert.assertEquals(BigInteger.ONE, m.toBigInteger(m.one()));
    }
  }

  @Test
  public void testBytes() {
    for (String name : CURVES) {
      ModN m = curve(name).scalarField();
      BigInteger n = m.modulus();
      int len = m.byteLength();
      int maxLen = 4 * ((n.bitLength() + 31) / 32);
      BigInteger[] values = {BigInteger.ZERO, BigInteger.ONE, n.subtract(BigInteger.ONE), n,
          n.add(BigInteger.ONE), n.shiftLeft(1).subtract(BigInteger.ONE),
          BigInteger.ONE.shiftLeft(8 * maxLen).subtract(BigInteger.ONE),
          BigInteger.ONE.shiftLeft(8 * (len - 1) - 1)};
      for (BigInteger v : values) {
        int vlen = Math.max(len, (v.bitLength() + 7) / 8);
        if (vlen > maxLen) {
          // e.g. 2n - 1 for P-256: only values below 2^(32 * limbs) are accepted
          continue;
        }
        Assert.assertEquals(name + " " + v.toString(16), v.mod(n),
            m.toBigInteger(m.fromBytes(fixed(v, vlen))));
      }

      for (int i = 0; i < 100; i++) {
        BigInteger v = random(n);
        byte[] b = m.toBytes(m.fromBigInteger(v));
        Assert.assertEquals(len, b.length);
        Assert.assertArrayEquals(fixed(v, len), b);
      }
      // leading zero bytes
      BigInteger small = BigInteger.valueOf(0x1234);
      Assert.assertArrayEquals(fixed(small, len), m.toBytes(m.fromBigInteger(small)));
    }
  }

  @Test
  public void testRange() {
    for (String name : CURVES) {
      ModN m = curve(name).scalarField();
      BigInteger n = m.modulus();
      int len = m.byteLength();
      Assert.assertFalse(m.isInRange(new byte[len]));
      Assert.assertTrue(m.isInRange(fixed(BigInteger.ONE, len)));
      Assert.assertTrue(m.isInRange(fixed(n.subtract(BigInteger.ONE), len)));
      Assert.assertFalse(m.isInRange(fixed(n, len)));
      Assert.assertFalse(m.isInRange(fixed(n.add(BigInteger.ONE), len)));
      byte[] ff = new byte[len];
      Arrays.fill(ff, (byte) 0xFF);
      Assert.assertFalse(m.isInRange(ff));

      for (int i = 0; i < 100; i++) {
        BigInteger r = m.toBigInteger(m.random(RND));
        Assert.assertTrue(r.signum() > 0 && r.compareTo(n) < 0);
      }
    }
  }

  @Test
  public void testLadderAndEncoding() {
    for (String name : CURVES) {
      EcCurve c = curve(name);
      WeierstrassCurve wc = c.weierstrassCurve();
      ModN m = c.scalarField();
      boolean leadingZero = false;
      for (int i = 0; i < 3000 && (i < 10 || !leadingZero); i++) {
        BigInteger k = random(m.modulus());
        WeierstrassPoint p1 = wc.getG().multiply(m.fromBigInteger(k));
        byte[] enc = p1.getEncoded(false);
        if (i >= 10 && enc[1] != 0) {
          // only searching a point with a leading zero byte in x
          continue;
        }
        Assert.assertArrayEquals(name, enc, wc.getG().multiply(k).getEncoded(false));
        if (p1.isInfinity()) {
          continue;
        }

        ECPoint jca = c.multiplyG(m.fromBigInteger(k));
        Assert.assertEquals(name, c.multiplyG(k), jca);
        Assert.assertArrayEquals(name, c.encodePoint(jca), enc);
        Assert.assertArrayEquals(name, fixed(jca.getAffineX(), c.fieldByteLength()),
            p1.getXCoordBytes());

        byte[] comp = p1.getEncoded(true);
        Assert.assertEquals(name, jca.getAffineY().testBit(0) ? 3 : 2, comp[0]);
        Assert.assertArrayEquals(name, enc, wc.decodePoint(comp).getEncoded(false));
        leadingZero |= (enc[1] == 0);
      }
      Assert.assertTrue(name + ": no point with a leading zero byte in x tested", leadingZero);
    }
  }

  @Test
  public void testScalarOutOfRange() {
    EcCurve c = curve("secp256r1");
    BigInteger n = c.order();
    BigInteger k = random(n);
    Assert.assertEquals(c.multiplyG(k), c.multiplyG(k.add(n)));
    Assert.assertEquals(c.multiplyG(n.subtract(k)), c.multiplyG(k.negate()));
    Assert.assertEquals(ECPoint.POINT_INFINITY, c.multiplyG(n));
  }

  private static EcCurve curve(String name) {
    EcCurve c = EcCurve.ofName(name);
    Assert.assertNotNull(name, c);
    return c;
  }

  private static BigInteger random(BigInteger n) {
    return new BigInteger(n.bitLength() + 8, RND).mod(n);
  }

  private static byte[] fixed(BigInteger v, int len) {
    byte[] b = v.toByteArray();
    byte[] r = new byte[len];
    int n = Math.min(b.length, len);
    System.arraycopy(b, b.length - n, r, len - n, n);
    return r;
  }

}
