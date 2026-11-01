// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * The SPIs of the secret keys and the random: KeyGenerator, SecretKeyFactory (PBKDF2) and
 * SecureRandom, all on OpenSSL.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslSecretSpis {

  private OsslSecretSpis() {
  }

  /**
   * PBKDF2 (PKCS#5) with HMAC and the password encoded in UTF-8, as the JDK does.
   *
   * @param password the password.
   * @param salt the salt.
   * @param iterations the iteration count.
   * @param keyLen the length of the derived key in bytes.
   * @param digest the digest of HMAC in OpenSSL, e.g. "SHA2-256".
   * @return the derived key.
   */
  static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLen, String digest) {
    ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] pass = new byte[bb.remaining()];
    bb.get(pass);
    Arrays.fill(bb.array(), (byte) 0);

    byte[] key = OpenSsl.kdfDerive("PBKDF2", new OsslParams()
        .secretOctets("pass", pass).octets("salt", salt)
        .integer("iter", iterations).utf8("digest", digest), keyLen);
    if (key == null) {
      throw new IllegalArgumentException("PBKDF2 failed: " + OpenSsl.errors());
    }
    return key;
  }

  /**
   * KeyGenerator of random keys: AES, DESede (with odd parity) and HMAC.
   * <p>
   * The DESede keys are 24 bytes K1‖K2‖K3: K3 = K1 for 112 bits (two keys). As in the JDK, the
   * keys with a weak or semi-weak DES key (FIPS 74, section 3.6), or equal K1 and K2, or (three
   * keys) equal K2 and K3 or K1 and K3, are not returned.
   */
  static final class KeyGen extends KeyGeneratorSpi {

    /** The 4 weak and 12 semi-weak DES keys, with odd parity. */
    static final long[] WEAK_DES_KEYS = {
        0x0101010101010101L, 0xFEFEFEFEFEFEFEFEL, 0xE0E0E0E0F1F1F1F1L, 0x1F1F1F1F0E0E0E0EL,
        0x01FE01FE01FE01FEL, 0xFE01FE01FE01FE01L, 0x1FE01FE00EF10EF1L, 0xE01FE01FF10EF10EL,
        0x01E001E001F101F1L, 0xE001E001F101F101L, 0x1FFE1FFE0EFE0EFEL, 0xFE1FFE1FFE0EFE0EL,
        0x011F011F010E010EL, 0x1F011F010E010E01L, 0xE0FEE0FEF1FEF1FEL, 0xFEE0FEE0FEF1FEF1L};

    private final String algorithm;

    private final int[] validBits;

    private int bits;

    /**
     * Constructor.
     * @param algorithm the algorithm of the generated keys, e.g. "AES".
     * @param defaultBits the default key size in bits.
     * @param validBits the valid key sizes in bits, or empty for any multiple of 8.
     */
    KeyGen(String algorithm, int defaultBits, int... validBits) {
      this.algorithm = algorithm;
      this.bits = defaultBits;
      this.validBits = validBits;
    }

    @Override
    protected void engineInit(SecureRandom random) {
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException {
      throw new InvalidAlgorithmParameterException("parameters are not supported");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
      boolean valid = (validBits.length == 0) ? keysize > 0 && keysize % 8 == 0
          : Arrays.stream(validBits).anyMatch(b -> b == keysize);
      if (!valid) {
        throw new InvalidParameterException("invalid key size " + keysize);
      }
      this.bits = keysize;
    }

    @Override
    protected SecretKey engineGenerateKey() {
      boolean desede = "DESede".equals(algorithm);
      byte[] key = new byte[desede ? 24 : bits / 8];
      try {
        if (desede) {
          do {
            OpenSsl.randomBytes(key, true);
            if (bits == 112) {
              System.arraycopy(key, 0, key, 16, 8);
            }
            setOddParity(key);
          } while (!isValidDesedeKey(key, bits == 112));
        } else {
          OpenSsl.randomBytes(key, true);
        }
        return new SecretKeySpec(key, algorithm);
      } finally {
        Arrays.fill(key, (byte) 0);
      }
    }

    private static void setOddParity(byte[] key) {
      for (int i = 0; i < key.length; i++) {
        int b = key[i] & 0xFE;
        key[i] = (byte) (b | ((Integer.bitCount(b) & 1) ^ 1));
      }
    }

    /**
     * Returns whether the DESede key (with odd parity) has no weak or semi-weak DES key, and
     * distinct K1 and K2, and for three keys also distinct K2 and K3, K1 and K3.
     */
    static boolean isValidDesedeKey(byte[] key, boolean twoKeys) {
      long k1 = desKey(key, 0);
      long k2 = desKey(key, 8);
      long k3 = desKey(key, 16);
      if (isWeakDesKey(k1) || isWeakDesKey(k2) || isWeakDesKey(k3) || k1 == k2) {
        return false;
      }
      return twoKeys || (k2 != k3 && k1 != k3);
    }

    private static long desKey(byte[] key, int off) {
      long k = 0;
      for (int i = 0; i < 8; i++) {
        k = (k << 8) | (key[off + i] & 0xFF);
      }
      return k;
    }

    private static boolean isWeakDesKey(long k) {
      for (long weak : WEAK_DES_KEYS) {
        if (k == weak) {
          return true;
        }
      }
      return false;
    }

  }

  /**
   * SecretKeyFactory PBKDF2WithHmac*: derives the key of a {@link PBEKeySpec}.
   */
  static final class Pbkdf2 extends SecretKeyFactorySpi {

    private final String algorithm;

    private final String digest;

    /**
     * Constructor.
     * @param algorithm the JCA name, e.g. "PBKDF2WithHmacSHA256".
     * @param digest the digest of HMAC in OpenSSL, e.g. "SHA2-256".
     */
    Pbkdf2(String algorithm, String digest) {
      this.algorithm = algorithm;
      this.digest = digest;
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
      if (!(keySpec instanceof PBEKeySpec spec)) {
        throw new InvalidKeySpecException("PBEKeySpec is required");
      }
      if (spec.getSalt() == null || spec.getIterationCount() <= 0 || spec.getKeyLength() <= 0
          || spec.getKeyLength() % 8 != 0) {
        throw new InvalidKeySpecException("salt, iteration count and key length are required");
      }

      char[] password = spec.getPassword();
      byte[] key = null;
      try {
        key = pbkdf2(password, spec.getSalt(), spec.getIterationCount(),
            spec.getKeyLength() / 8, digest);
        return new SecretKeySpec(key, algorithm);
      } catch (IllegalArgumentException e) {
        throw new InvalidKeySpecException(e.getMessage(), e);
      } finally {
        Arrays.fill(password, '\0');
        if (key != null) {
          Arrays.fill(key, (byte) 0);
        }
      }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec)
        throws InvalidKeySpecException {
      throw new InvalidKeySpecException("unsupported");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
      if (!algorithm.equalsIgnoreCase(key.getAlgorithm())) {
        throw new InvalidKeyException("not a key of " + algorithm);
      }
      return key;
    }

  }

  /**
   * SecureRandom on the DRBG of OpenSSL (RAND_bytes). The seeds are ignored: the DRBG of
   * OpenSSL seeds itself.
   */
  static final class Random extends SecureRandomSpi {

    @Override
    protected void engineSetSeed(byte[] seed) {
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
      OpenSsl.randomBytes(bytes, false);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
      byte[] seed = new byte[numBytes];
      OpenSsl.randomBytes(seed, true);
      return seed;
    }

  }

}
