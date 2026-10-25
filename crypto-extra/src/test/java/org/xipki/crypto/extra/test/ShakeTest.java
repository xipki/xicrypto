// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.test;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.crypto.extra.Shake;

import java.security.SecureRandom;

/**
 * Tests {@link Shake} against FIPS 202 vectors and BouncyCastle, and its streaming input.
 *
 * @author Lijun Liao (xipki)
 */
public class ShakeTest {

  @Test
  public void testEmptyInputVectors() {
    Assert.assertEquals("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        Hex.encode(Shake.shake(128, new byte[0], 32)).toLowerCase());
    Assert.assertEquals("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        Hex.encode(Shake.shake(256, new byte[0], 64)).toLowerCase());
  }

  @Test
  public void testAgainstBouncyCastle() {
    SecureRandom rnd = new SecureRandom();
    int[] inLens = {0, 1, 135, 136, 137, 167, 168, 169, 500, 1000};
    int[] outLens = {0, 1, 32, 64, 136, 168, 169, 400};
    for (int strength : new int[]{128, 256}) {
      for (int inLen : inLens) {
        byte[] data = new byte[inLen];
        rnd.nextBytes(data);
        for (int outLen : outLens) {
          SHAKEDigest bc = new SHAKEDigest(strength);
          bc.update(data, 0, data.length);
          byte[] expected = new byte[outLen];
          bc.doFinal(expected, 0, outLen);
          Assert.assertArrayEquals("SHAKE" + strength + ", in=" + inLen + ", out=" + outLen,
              expected, Shake.shake(strength, data, outLen));
        }
      }
    }
  }

  @Test
  public void testStreaming() {
    SecureRandom rnd = new SecureRandom();
    byte[] data = new byte[1000];
    rnd.nextBytes(data);
    int[] chunks = {1, 7, 135, 136, 137, 168, 169};
    for (int strength : new int[]{128, 256}) {
      byte[] expected = Shake.shake(strength, data, 64);
      Shake shake = new Shake(strength, 64);
      for (int chunk : chunks) {
        // reused instance: digest() resets it
        for (int off = 0; off < data.length; off += chunk) {
          int len = Math.min(chunk, data.length - off);
          if (len == 1) {
            shake.update(data[off]);
          } else {
            shake.update(data, off, len);
          }
        }
        Assert.assertArrayEquals("SHAKE" + strength + ", chunk=" + chunk, expected,
            shake.digest());
      }
    }
  }

}
