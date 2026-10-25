// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import org.xipki.codec.util.BigIntegers;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;

/**
 * The raw RSA operation (RSASP1 / RSAVP1 of RFC 8017) through the cipher
 * {@code RSA/ECB/NoPadding} of the {@link Primitives}, for the signatures of xicrypto. The
 * private key operation is blinded by the JDK and by BC-FIPS.
 *
 * @author Lijun Liao (xipki)
 */
final class RsaRaw {

  private RsaRaw() {
  }

  /**
   * Returns input^d mod n (private key, {@link Cipher#DECRYPT_MODE}) or input^e mod n (public
   * key, {@link Cipher#ENCRYPT_MODE}), with the length of the modulus.
   * @param primitives the source of the cipher.
   * @param mode {@link Cipher#DECRYPT_MODE} or {@link Cipher#ENCRYPT_MODE}.
   * @param key the RSA key.
   * @param input the input, less than the modulus.
   * @return the result, with the length of the modulus.
   * @throws SignatureException if the RSA operation failed.
   */
  static byte[] apply(Primitives primitives, int mode, Key key, byte[] input)
      throws SignatureException {
    try {
      Cipher cipher = primitives.cipher("RSA/ECB/NoPadding");
      cipher.init(mode, key);
      byte[] out = cipher.doFinal(input);
      return BigIntegers.asUnsignedByteArray(modulusLength((RSAKey) key), new BigInteger(1, out));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new SignatureException("RSA operation failed: " + e.getMessage(), e);
    }
  }

  static int modulusLength(RSAKey key) {
    return (key.getModulus().bitLength() + 7) / 8;
  }

}
