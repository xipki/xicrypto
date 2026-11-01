// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.MemorySegment;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * RSASSA-PSS with SHAKE128 or SHAKE256 (RFC 8702): the hash and the MGF are SHAKE128 (256-bit
 * hash, 32-byte salt) or SHAKE256 (512-bit hash, 64-byte salt), the trailer field is 0xBC.
 * <p>
 * OpenSSL does not support XOFs in RSA-PSS. The cryptographic primitives are those of OpenSSL:
 * the SHAKE (as hash and as MGF), the salt (DRBG of OpenSSL), and the RSA operation without
 * padding (RSASP1 / RSAVP1). Only the byte layout of EMSA-PSS (RFC 8017, section 9.1) is done
 * here.
 * <p>
 * Since the padding is done outside of OpenSSL, this is not an approved service of a FIPS
 * module. It is disabled in the FIPS mode of OpenSSL, and can be disabled with the system
 * property {@value #PROP_ENABLED}{@code =false}.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslRsaPssShake extends OpensslSignature {

  /** System property to disable this algorithm, enabled by default. */
  static final String PROP_ENABLED = "xipki.openssl.rsaPssShake";

  private final MemorySegment md;

  private final int hLen;

  /**
   * Constructor.
   * @param shake "SHAKE128" or "SHAKE256".
   */
  OsslRsaPssShake(String shake) {
    super("RSA");
    this.md = OpenSsl.md(shake);
    this.hLen = "SHAKE128".equals(shake) ? 32 : 64;
  }

  /**
   * Returns whether the algorithm is enabled: not in the FIPS mode, and not disabled by the
   * system property {@value #PROP_ENABLED}.
   */
  static boolean isEnabled() {
    return !"false".equalsIgnoreCase(System.getProperty(PROP_ENABLED))
        && !OpenSsl.isFipsEnabled();
  }

  @Override
  MemorySegment newCtx() {
    throw new UnsupportedOperationException();
  }

  private byte[] shake(byte[] data, int len) {
    return OpenSsl.digest(md, MemorySegment.ofArray(data), len, true);
  }

  /** H = SHAKE(0x00 * 8 || mHash || salt), with the hash length. */
  private byte[] hashOfMPrime(byte[] mHash, byte[] salt) {
    byte[] mPrime = new byte[8 + mHash.length + salt.length];
    System.arraycopy(mHash, 0, mPrime, 8, mHash.length);
    System.arraycopy(salt, 0, mPrime, 8 + mHash.length, salt.length);
    return shake(mPrime, hLen);
  }

  @Override
  byte[] sign(MemorySegment msg) throws SignatureException {
    int modBits = key.apply(OpenSsl::pkeyBits);
    int k = (modBits + 7) / 8;
    int emBits = modBits - 1;
    int emLen = (emBits + 7) / 8;
    int sLen = hLen;
    if (emLen < hLen + sLen + 2) {
      throw new SignatureException("key too short");
    }

    // EMSA-PSS-ENCODE
    byte[] mHash = OpenSsl.digest(md, msg, hLen, true);
    byte[] salt = new byte[sLen];
    OpenSsl.randomBytes(salt, false);
    byte[] h = hashOfMPrime(mHash, salt);

    // DB = PS || 0x01 || salt, maskedDB = DB xor SHAKE(H, emLen - hLen - 1)
    int dbLen = emLen - hLen - 1;
    byte[] db = new byte[dbLen];
    db[dbLen - sLen - 1] = 0x01;
    System.arraycopy(salt, 0, db, dbLen - sLen, sLen);
    byte[] dbMask = shake(h, dbLen);
    for (int i = 0; i < dbLen; i++) {
      db[i] ^= dbMask[i];
    }
    // clear the leftmost 8 * emLen - emBits bits
    db[0] &= (byte) (0xFF >>> (8 * emLen - emBits));

    // EM = maskedDB || H || 0xBC, as integer of k bytes
    byte[] em = new byte[k];
    int off = k - emLen;
    System.arraycopy(db, 0, em, off, dbLen);
    System.arraycopy(h, 0, em, off + dbLen, hLen);
    em[k - 1] = (byte) 0xBC;

    // RSASP1: the RSA private key operation without padding
    byte[] sig = key.apply(pkey -> OpenSsl.pkeyOp(OpenSsl.PkeyOp.DECRYPT, pkey,
        new OsslParams().utf8("pad-mode", "none"), em));
    if (sig == null) {
      throw new SignatureException("RSA operation failed: " + OpenSsl.errors());
    }
    return sig;
  }

  @Override
  boolean verify(MemorySegment msg, byte[] sig) {
    int modBits = key.apply(OpenSsl::pkeyBits);
    int k = (modBits + 7) / 8;
    int emBits = modBits - 1;
    int emLen = (emBits + 7) / 8;
    int sLen = hLen;
    if (sig.length != k || emLen < hLen + sLen + 2) {
      return false;
    }

    // RSAVP1: the RSA public key operation without padding
    byte[] m = key.apply(pkey -> OpenSsl.pkeyOp(OpenSsl.PkeyOp.ENCRYPT, pkey,
        new OsslParams().utf8("pad-mode", "none"), sig));
    if (m == null || m.length != k) {
      OpenSsl.clearErrors();
      return false;
    }
    for (int i = 0; i < k - emLen; i++) {
      if (m[i] != 0) {
        return false;
      }
    }

    // EMSA-PSS-VERIFY
    int off = k - emLen;
    if (m[k - 1] != (byte) 0xBC) {
      return false;
    }
    int dbLen = emLen - hLen - 1;
    byte[] db = Arrays.copyOfRange(m, off, off + dbLen);
    byte[] h = Arrays.copyOfRange(m, off + dbLen, off + dbLen + hLen);
    int unusedBits = 8 * emLen - emBits;
    if ((db[0] & (0xFF << (8 - unusedBits)) & 0xFF) != 0) {
      return false;
    }

    byte[] dbMask = shake(h, dbLen);
    for (int i = 0; i < dbLen; i++) {
      db[i] ^= dbMask[i];
    }
    db[0] &= (byte) (0xFF >>> unusedBits);

    // DB = PS (zeros) || 0x01 || salt
    int psLen = dbLen - sLen - 1;
    for (int i = 0; i < psLen; i++) {
      if (db[i] != 0) {
        return false;
      }
    }
    if (db[psLen] != 0x01) {
      return false;
    }

    byte[] salt = Arrays.copyOfRange(db, dbLen - sLen, dbLen);
    byte[] mHash = OpenSsl.digest(md, msg, hLen, true);
    return MessageDigest.isEqual(h, hashOfMPrime(mHash, salt));
  }

}
