// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;

/**
 * Tests that the provider offers no SM algorithms but all others if the SM algorithms are
 * disabled. Maven runs it in its own JVM with the system property
 * {@value EcCurve#PROP_DISABLE_SM} set to true. If it is run alone (e.g. in the IDE or with
 * -Dtest), the test sets the property itself.
 *
 * @author Lijun Liao (xipki)
 */
public class SmDisabledTest {

  private static final boolean propertySetByTest;

  static {
    // PROP_DISABLE_SM is a compile-time constant, using it does not initialize EcCurve.
    propertySetByTest = !Boolean.getBoolean(EcCurve.PROP_DISABLE_SM);
    if (propertySetByTest) {
      System.setProperty(EcCurve.PROP_DISABLE_SM, "true");
    }
  }

  @AfterClass
  public static void cleanup() {
    if (propertySetByTest) {
      System.clearProperty(EcCurve.PROP_DISABLE_SM);
    }
  }

  @Test
  public void testSmDisabled() throws Exception {
    Assert.assertTrue(EcCurve.isSmDisabled());

    Provider xi = new XiPKIProvider();
    Assert.assertNull(xi.getService("MessageDigest", "SM3"));
    Assert.assertNull(xi.getService("Signature", "SM3WITHSM2"));
    Assert.assertNull(EcCurve.ofOid(CurveOIDs.sm2p256v1));
    Assert.assertNull(EcCurve.ofName("SM2"));

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", xi);
    try {
      kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));
      Assert.fail("SM2 must not be supported");
    } catch (java.security.InvalidAlgorithmParameterException e) {
      // expected
    }

    // the other curves and algorithms work
    kpGen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
    Assert.assertNotNull(kpGen.generateKeyPair());
    Assert.assertNotNull(xi.getService("Signature", "SHAKE128WITHRSAPSS"));
  }

}
