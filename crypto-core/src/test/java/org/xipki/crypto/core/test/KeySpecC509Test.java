// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.crypto.core.KeySpec;

/**
 * Tests of the mapping between KeySpec and the C509 public key algorithms.
 *
 * @author Lijun Liao (xipki)
 */
public class KeySpecC509Test {

  @Test
  public void testRoundTrip() {
    for (KeySpec spec : KeySpec.values()) {
      Integer code = spec.c509AlgId();
      if (spec.isRSA()) {
        Assert.assertNull(spec.name(), code);
        continue;
      }

      Assert.assertNotNull(spec.name(), code);
      Assert.assertSame(spec.name(), spec, KeySpec.ofC509AlgorithmIdentifier(code));
      Assert.assertEquals(spec.name(), spec.algorithmIdentifier(),
          ConstPublicKeyAlgorithm.getX509AlgorithmIdentifier(code));
    }
  }

  @Test
  public void testComposite() {
    Assert.assertSame(KeySpec.MLDSA44_RSA2048, KeySpec.ofC509AlgorithmIdentifier(
        ConstPublicKeyAlgorithm.MLDSA44_RSA2048_PSS_SHA256));
    Assert.assertSame(KeySpec.MLKEM1024_P521, KeySpec.ofC509AlgorithmIdentifier(
        ConstPublicKeyAlgorithm.MLKEM1024_ECDH_P521_SHA3_256));
  }

  @Test
  public void testNoKeySpec() {
    Assert.assertNull(KeySpec.ofC509AlgorithmIdentifier(ConstPublicKeyAlgorithm.rsaEncryption));
    Assert.assertNull(KeySpec.ofC509AlgorithmIdentifier(ConstPublicKeyAlgorithm.ec_frp256v1));
    Assert.assertNull(KeySpec.ofC509AlgorithmIdentifier(
        ConstPublicKeyAlgorithm.MLDSA44_RSA2048_PKCS15_SHA256));
    Assert.assertNull(KeySpec.ofC509AlgorithmIdentifier(-1));
  }

}
