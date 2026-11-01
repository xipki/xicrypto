// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal.rsa;

import org.xipki.crypto.jdk.internal.Primitives;
import org.xipki.crypto.jdk.internal.digest.Shake;

import java.security.SignatureException;
import java.util.Arrays;

/**
 * RSASSA-PSS (RFC 8017, section 8.1) with SHAKE128 or SHAKE256 as hash and MGF (RFC 8702), the
 * parameters are fixed.
 *
 * @author Lijun Liao (xipki)
 */
public class RSAPSSSignatureSpi extends RsaSignatureSpi {

  private final PssEncoder pss;

  /**
   * Constructor for RSASSA-PSS with SHAKE128 or SHAKE256 (RFC 8702).
   * @param primitives the source of the raw RSA operation.
   * @param shakeStrength 128 (SHAKE128) or 256 (SHAKE256).
   */
  public RSAPSSSignatureSpi(Primitives primitives, int shakeStrength) {
    super(primitives, new Shake(shakeStrength, shakeStrength == 128 ? 32 : 64));
    this.pss = PssEncoder.shake(shakeStrength);
  }

  @Override
  protected byte[] encode(byte[] hash, int modBits) throws SignatureException {
    try {
      return pss.encode(hash, modBits, secureRandom());
    } catch (IllegalArgumentException e) {
      throw new SignatureException(e.getMessage(), e);
    }
  }

  @Override
  protected boolean matches(byte[] hash, byte[] m, int modBits) {
    // EM has emLen = ceil((modBits - 1) / 8) bytes, one byte less than m if modBits = 1 mod 8
    int emLen = (modBits - 1 + 7) / 8;
    int off = m.length - emLen;
    for (int i = 0; i < off; i++) {
      if (m[i] != 0) {
        return false;
      }
    }
    byte[] em = (off == 0) ? m : Arrays.copyOfRange(m, off, m.length);
    return pss.verify(hash, em, modBits);
  }

}
