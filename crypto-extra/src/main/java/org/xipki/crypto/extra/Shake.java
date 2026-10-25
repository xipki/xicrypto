// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import org.xipki.codec.util.Args;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * SHAKE128 and SHAKE256 extendable-output functions (FIPS 202), as {@link MessageDigest} with a
 * fixed output length, and as one-shot function {@link #shake(int, byte[], int)}.
 * <p>
 * Fallback used when the crypto backend does not support XOF.
 *
 * @author Lijun Liao (xipki)
 */
public final class Shake extends MessageDigest {

  private static final long[] RC = {
      0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
      0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
      0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
      0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
      0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
      0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};

  private static final int[] ROTC = {
      1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

  private static final int[] PILN = {
      10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

  private final int rate;

  private final int outLen;

  private final long[] state = new long[25];

  /** the input not yet absorbed, less than one block. */
  private final byte[] buf;

  private int bufOff;

  /**
   * Constructor.
   * @param securityStrength 128 (SHAKE128) or 256 (SHAKE256).
   * @param outLen the output length in bytes.
   */
  public Shake(int securityStrength, int outLen) {
    super("SHAKE" + securityStrength);
    if (securityStrength != 128 && securityStrength != 256) {
      throw new IllegalArgumentException("invalid securityStrength " + securityStrength);
    }
    this.outLen = Args.notNegative(outLen, "outLen");
    this.rate = 200 - 2 * (securityStrength / 8);
    this.buf = new byte[rate];
  }

  /**
   * Computes SHAKE128 or SHAKE256.
   * @param securityStrength 128 or 256.
   * @param data the input.
   * @param length the output length in bytes.
   * @return the output.
   */
  public static byte[] shake(int securityStrength, byte[] data, int length) {
    Args.notNull(data, "data");
    Shake shake = new Shake(securityStrength, length);
    shake.update(data);
    return shake.digest();
  }

  @Override
  protected int engineGetDigestLength() {
    return outLen;
  }

  @Override
  protected void engineUpdate(byte input) {
    buf[bufOff++] = input;
    if (bufOff == rate) {
      absorbBlock();
    }
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) {
    while (len > 0) {
      int n = Math.min(len, rate - bufOff);
      System.arraycopy(input, offset, buf, bufOff, n);
      bufOff += n;
      offset += n;
      len -= n;
      if (bufOff == rate) {
        absorbBlock();
      }
    }
  }

  @Override
  protected byte[] engineDigest() {
    // pad: the domain separation bits 1111 of SHAKE, then pad10*1
    Arrays.fill(buf, bufOff, rate, (byte) 0);
    buf[bufOff] ^= 0x1F;
    buf[rate - 1] ^= (byte) 0x80;
    absorbBlock();

    // squeeze
    byte[] out = new byte[outLen];
    int outOff = 0;
    while (true) {
      int n = Math.min(rate, outLen - outOff);
      for (int i = 0; i < n; i++) {
        out[outOff + i] = (byte) (state[i >>> 3] >>> (8 * (i & 7)));
      }
      outOff += n;
      if (outOff == outLen) {
        break;
      }
      keccakF(state);
    }

    engineReset();
    return out;
  }

  @Override
  protected void engineReset() {
    Arrays.fill(state, 0);
    bufOff = 0;
  }

  private void absorbBlock() {
    for (int i = 0; i < rate; i++) {
      state[i >>> 3] ^= (buf[i] & 0xFFL) << (8 * (i & 7));
    }
    keccakF(state);
    bufOff = 0;
  }

  private static void keccakF(long[] st) {
    long[] bc = new long[5];
    for (int round = 0; round < 24; round++) {
      // theta
      for (int i = 0; i < 5; i++) {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      }

      for (int i = 0; i < 5; i++) {
        long t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
        for (int j = 0; j < 25; j += 5) {
          st[j + i] ^= t;
        }
      }

      // rho and pi
      long t = st[1];
      for (int i = 0; i < 24; i++) {
        int j = PILN[i];
        long tmp = st[j];
        st[j] = Long.rotateLeft(t, ROTC[i]);
        t = tmp;
      }

      // chi
      for (int j = 0; j < 25; j += 5) {
        for (int i = 0; i < 5; i++) {
          bc[i] = st[j + i];
        }
        for (int i = 0; i < 5; i++) {
          st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
      }

      // iota
      st[0] ^= RC[round];
    }
  }

}
