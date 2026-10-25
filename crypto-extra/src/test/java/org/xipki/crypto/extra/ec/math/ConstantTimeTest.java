// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * Statistical timing test in the style of dudect (Reparaz, Balasch, Verbauwhede: "Dude, is my
 * code constant time?", 2017): the running times of an operation for two classes of inputs (a
 * fixed value, and random values), measured in random order, are compared with Welch's t-test
 * after cropping the slowest measurements. |t| above {@value #T_LEAK} indicates a timing leak.
 * <p>
 * The test is a sanity check, not a proof: the JVM gives no constant-time guarantee and the
 * measurements are noisy. The sensitivity check runs the same test on the variable-time
 * multiplier, which must be detected as leaking.
 * <p>
 * Opt-in, because it takes about a minute: {@code mvn -pl xicrypto test
 * -Dtest=ConstantTimeTest -Dxipki.timingTest=true}.
 *
 * @author Lijun Liao (xipki)
 */
public class ConstantTimeTest {

  private static final String PROP = "xipki.timingTest";

  private static final double T_LEAK = 10.0;

  /** keep the fastest 90 % of the measurements of both classes (pooled). */
  private static final double CROP = 0.90;

  private static final int WARMUP = 2_000;

  private static final int MEASUREMENTS = 10_000;

  private static final SecureRandom RND = new SecureRandom();

  private static EcCurve curve;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("timing test disabled, enable with -D" + PROP + "=true",
        Boolean.getBoolean(PROP));
    curve = EcCurve.ofName("secp256r1");
  }

  /**
   * The ladder with a fixed scalar (1: all but one bit zero, many leading zero limbs) versus
   * random scalars.
   */
  @Test
  public void testLadder() {
    WeierstrassCurve wc = curve.weierstrassCurve();
    ModN m = curve.scalarField();
    int[] fixed = m.plainLimbs(m.one());
    int[][] random = new int[MEASUREMENTS][];
    for (int i = 0; i < MEASUREMENTS; i++) {
      random[i] = m.plainLimbs(m.random(RND));
    }
    WeierstrassPoint g = wc.getG();
    double t = measure("ladder", (cls, i) -> g.multiplyLimbs(cls == 0 ? fixed : random[i]));
    Assert.assertTrue("ladder: |t| = " + t, Math.abs(t) < T_LEAK);
  }

  /**
   * The inversion mod n with a fixed value (1) versus random values.
   */
  @Test
  public void testInversion() {
    ModN m = curve.scalarField();
    ModN.Element fixed = m.one();
    ModN.Element[] random = new ModN.Element[MEASUREMENTS];
    for (int i = 0; i < MEASUREMENTS; i++) {
      random[i] = m.random(RND);
    }
    double t = measure("ModN.inv", (cls, i) -> m.inv(cls == 0 ? fixed : random[i]));
    Assert.assertTrue("ModN.inv: |t| = " + t, Math.abs(t) < T_LEAK);
  }

  /**
   * Sensitivity check: the variable-time multiplier (u1·G + 0·G) with a fixed small scalar
   * versus random scalars must be detected as leaking.
   */
  @Test
  public void testSensitivityVarTime() {
    BigInteger n = curve.order();
    BigInteger fixed = BigInteger.ONE;
    BigInteger[] random = new BigInteger[MEASUREMENTS];
    for (int i = 0; i < MEASUREMENTS; i++) {
      random[i] = new BigInteger(n.bitLength() + 8, RND).mod(n);
    }
    ECPoint g = curve.parameterSpec().getGenerator();
    double t = measure("VarTimeMultiplier (sensitivity)",
        (cls, i) -> curve.sumOfTwoMultiplies(cls == 0 ? fixed : random[i], BigInteger.ZERO, g));
    Assert.assertTrue("variable-time multiplier not detected: |t| = " + t,
        Math.abs(t) > T_LEAK);
  }

  @FunctionalInterface
  private interface Op {
    Object run(int cls, int index);
  }

  /**
   * Measures the operation for both classes in random order and returns Welch's t.
   */
  private static double measure(String name, Op op) {
    Object sink = null;
    for (int i = 0; i < WARMUP; i++) {
      sink = op.run(i & 1, i % MEASUREMENTS);
    }

    int[] classes = new int[MEASUREMENTS];
    long[] times = new long[MEASUREMENTS];
    for (int i = 0; i < MEASUREMENTS; i++) {
      classes[i] = RND.nextInt(2);
    }
    for (int i = 0; i < MEASUREMENTS; i++) {
      long start = System.nanoTime();
      sink = op.run(classes[i], i);
      times[i] = System.nanoTime() - start;
    }
    Assert.assertNotNull(sink);

    long[] sorted = times.clone();
    Arrays.sort(sorted);
    long threshold = sorted[(int) (CROP * (MEASUREMENTS - 1))];

    double[] sum = new double[2];
    double[] sumSq = new double[2];
    int[] count = new int[2];
    for (int i = 0; i < MEASUREMENTS; i++) {
      if (times[i] > threshold) {
        continue;
      }
      int c = classes[i];
      count[c]++;
      sum[c] += times[i];
      sumSq[c] += (double) times[i] * times[i];
    }

    double mean0 = sum[0] / count[0];
    double mean1 = sum[1] / count[1];
    double var0 = (sumSq[0] - count[0] * mean0 * mean0) / (count[0] - 1);
    double var1 = (sumSq[1] - count[1] * mean1 * mean1) / (count[1] - 1);
    double t = (mean0 - mean1) / Math.sqrt(var0 / count[0] + var1 / count[1]);
    System.out.printf("%s: fixed %.0f ns, random %.0f ns (n = %d / %d), t = %.2f%n",
        name, mean0, mean1, count[0], count[1], t);
    return t;
  }

}
