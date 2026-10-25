// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import org.xipki.codec.util.Args;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * EMSA-PSS encoding (RFC 8017, section 9.1) with a pluggable hash and mask generation function:
 * <ul>
 *   <li>SHAKE128 / SHAKE256 as hash and as MGF (RFC 8702, section 3.2), see
 *       {@link #shake(int)};</li>
 *   <li>a hash of {@link MessageDigest} with MGF1 of the same hash (RFC 8017, B.2.1), see
 *       {@link #mgf1(MessageDigest, int)}.</li>
 * </ul>
 * The trailer field is 0xBC. Instances are not thread-safe.
 *
 * @author Lijun Liao (xipki)
 */
final class PssEncoder {

  @FunctionalInterface
  interface Hash {
    byte[] hash(byte[] data);
  }

  @FunctionalInterface
  interface Mgf {
    byte[] mask(byte[] seed, int length);
  }

  private final int hLen;

  private final int sLen;

  private final Hash hash;

  private final Mgf mgf;

  private PssEncoder(int hLen, int sLen, Hash hash, Mgf mgf) {
    Args.notNegative(sLen, "sLen");
    this.hLen = hLen;
    this.sLen = sLen;
    this.hash = hash;
    this.mgf = mgf;
  }

  /**
   * RSASSA-PSS with SHAKE (RFC 8702): output and salt length 32 bytes for SHAKE128 and 64 bytes
   * for SHAKE256.
   * @param securityStrength 128 (SHAKE128) or 256 (SHAKE256).
   * @return the encoder.
   */
  static PssEncoder shake(int securityStrength) {
    int len = securityStrength == 128 ? 32 : 64;
    return new PssEncoder(len, len, data -> Shake.shake(securityStrength, data, len),
        (seed, length) -> Shake.shake(securityStrength, seed, length));
  }

  /**
   * RSASSA-PSS with the hash of the digest and MGF1 with the same hash.
   * @param digest the digest, used for the hash and for MGF1.
   * @param saltLength the length of the salt in bytes.
   * @return the encoder.
   */
  static PssEncoder mgf1(MessageDigest digest, int saltLength) {
    int len = digest.getDigestLength();
    return new PssEncoder(len, saltLength, data -> {
      digest.reset();
      return digest.digest(data);
    }, (seed, length) -> mgf1(digest, seed, length));
  }

  /**
   * MGF1 (RFC 8017, B.2.1).
   */
  private static byte[] mgf1(MessageDigest digest, byte[] seed, int length) {
    int hashLen = digest.getDigestLength();
    byte[] mask = new byte[length];
    byte[] counter = new byte[4];
    for (int off = 0, i = 0; off < length; i++) {
      counter[0] = (byte) (i >>> 24);
      counter[1] = (byte) (i >>> 16);
      counter[2] = (byte) (i >>> 8);
      counter[3] = (byte) i;
      digest.reset();
      digest.update(seed);
      digest.update(counter);
      byte[] t = digest.digest();
      int n = Math.min(hashLen, length - off);
      System.arraycopy(t, 0, mask, off, n);
      off += n;
    }
    return mask;
  }

  byte[] hash(byte[] data) {
    return hash.hash(data);
  }

  /**
   * EMSA-PSS-ENCODE.
   * @param mHash the hash of the message.
   * @param modulusBitLength the bit length of the RSA modulus.
   * @param random the source of the salt.
   * @return the encoded message EM.
   * @throws IllegalArgumentException if the key is too small.
   */
  byte[] encode(byte[] mHash, int modulusBitLength, SecureRandom random) {
    int emBits = modulusBitLength - 1;
    if (mHash.length != hLen) {
      throw new IllegalArgumentException("invalid length of the hash " + mHash.length);
    }
    int emLen = (emBits + 7) / 8;
    if (emLen < hLen + sLen + 2) {
      throw new IllegalArgumentException("key too small for the hash and salt lengths");
    }

    byte[] salt = new byte[sLen];
    random.nextBytes(salt);

    // H = Hash(00 00 00 00 00 00 00 00 || mHash || salt)
    byte[] mDash = new byte[8 + hLen + sLen];
    System.arraycopy(mHash, 0, mDash, 8, hLen);
    System.arraycopy(salt, 0, mDash, 8 + hLen, sLen);
    byte[] h = hash(mDash);

    // DB = PS || 0x01 || salt
    byte[] em = new byte[emLen];
    int dbLen = emLen - hLen - 1;
    em[dbLen - sLen - 1] = 0x01;
    System.arraycopy(salt, 0, em, dbLen - sLen, sLen);

    // maskedDB = DB xor MGF(H, dbLen)
    byte[] dbMask = mgf.mask(h, dbLen);
    for (int i = 0; i < dbLen; i++) {
      em[i] ^= dbMask[i];
    }
    em[0] &= (byte) (0xFF >>> (8 * emLen - emBits));

    System.arraycopy(h, 0, em, dbLen, hLen);
    em[emLen - 1] = (byte) 0xBC;
    return em;
  }

  /**
   * EMSA-PSS-VERIFY.
   * @param mHash the hash of the message.
   * @param em the encoded message EM, emLen = ceil((modulusBitLength - 1) / 8) bytes.
   * @param modulusBitLength the bit length of the RSA modulus.
   * @return whether the encoding is consistent with the hash.
   */
  boolean verify(byte[] mHash, byte[] em, int modulusBitLength) {
    int emBits = modulusBitLength - 1;
    int emLen = (emBits + 7) / 8;
    if (mHash.length != hLen || em.length != emLen || emLen < hLen + sLen + 2) {
      return false;
    }

    if ((em[emLen - 1] & 0xFF) != 0xBC) {
      return false;
    }
    if (((em[0] & 0xFF) & (0xFF << (8 - (8 * emLen - emBits)))) != 0) {
      return false;
    }

    int dbLen = emLen - hLen - 1;
    byte[] h = Arrays.copyOfRange(em, dbLen, dbLen + hLen);
    byte[] db = mgf.mask(h, dbLen);
    for (int i = 0; i < dbLen; i++) {
      db[i] ^= em[i];
    }
    db[0] &= (byte) (0xFF >>> (8 * emLen - emBits));

    for (int i = 0; i < dbLen - sLen - 1; i++) {
      if (db[i] != 0) {
        return false;
      }
    }

    if (db[dbLen - sLen - 1] != 0x01) {
      return false;
    }

    byte[] mDash = new byte[8 + hLen + sLen];
    System.arraycopy(mHash, 0, mDash, 8, hLen);
    System.arraycopy(db, dbLen - sLen, mDash, 8 + hLen, sLen);
    return MessageDigest.isEqual(h, hash(mDash));
  }

}
