// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeyInfoUtil;

/**
 * Tests the HKDF with the test vectors of RFC 5869, Appendix A.
 *
 * @author Lijun Liao (xipki)
 */
public class HkdfTest {

  @Test
  public void testCase1() {
    // A.1: basic test case with SHA-256
    execute(HashAlgo.SHA256,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            + "34007208d5b887185865");
  }

  @Test
  public void testCase2() {
    // A.2: test with SHA-256 and longer inputs/outputs
    execute(HashAlgo.SHA256,
        range(0x00, 0x50),
        range(0x60, 0xb0),
        range(0xb0, 0x100),
        82,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            + "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            + "cc30c58179ec3e87c14c01d5c1f3434f1d87");
  }

  @Test
  public void testCase3() {
    // A.3: test with SHA-256 and zero-length salt/info
    execute(HashAlgo.SHA256,
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "",
        "",
        42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            + "9d201395faa4b61a96c8");
  }

  @Test
  public void testCase4() {
    // A.4: basic test case with SHA-1
    execute(HashAlgo.SHA1,
        "0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2"
            + "c22e422478d305f3f896");
  }

  @Test
  public void testCase7() {
    // A.7: test with SHA-1, salt not provided (defaults to HashLen zero octets),
    // zero-length info
    byte[] ikm = Hex.decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    byte[] okm = KeyInfoUtil.hkdf(HashAlgo.SHA1, null, ikm, null, 42);
    Assert.assertEquals("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5"
        + "673a081d70cce7acfc48", Hex.encode(okm));
  }

  @Test
  public void testInvalidOutSize() {
    byte[] ikm = new byte[32];
    Assert.assertThrows(IllegalArgumentException.class,
        () -> KeyInfoUtil.hkdf(HashAlgo.SHA256, null, ikm, null, 0));
    Assert.assertThrows(IllegalArgumentException.class,
        () -> KeyInfoUtil.hkdf(HashAlgo.SHA256, null, ikm, null, 255 * 32 + 1));
    Assert.assertEquals(255 * 32,
        KeyInfoUtil.hkdf(HashAlgo.SHA256, null, ikm, null, 255 * 32).length);
  }

  private static void execute(HashAlgo hashAlgo, String ikm, String salt, String info,
                              int outSize, String expectedOkm) {
    byte[] okm = KeyInfoUtil.hkdf(hashAlgo, Hex.decode(salt), Hex.decode(ikm), Hex.decode(info),
        outSize);
    Assert.assertEquals(expectedOkm, Hex.encode(okm));
  }

  private static String range(int from, int to) {
    byte[] bytes = new byte[to - from];
    for (int i = from; i < to; i++) {
      bytes[i - from] = (byte) i;
    }
    return Hex.encode(bytes);
  }

}
