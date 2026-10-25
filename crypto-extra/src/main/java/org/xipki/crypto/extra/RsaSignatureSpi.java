// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Base of the RSA signatures: the subclass encodes the hash into the message representative
 * EM, the raw RSA operation is the cipher {@code RSA/ECB/NoPadding} of the {@link Primitives}
 * (with blinding in the JDK and BC-FIPS), see {@link RsaRaw}.
 *
 * @author Lijun Liao (xipki)
 */
abstract class RsaSignatureSpi extends XiSignatureSpi {

  private final Primitives primitives;

  private RSAPrivateKey privateKey;

  private RSAPublicKey publicKey;

  RsaSignatureSpi(Primitives primitives, MessageDigest digest) {
    super(digest);
    this.primitives = primitives;
  }

  /**
   * Returns the encoded message EM for the hash.
   * @param hash the hash of the message.
   * @param modBits the bit length of the RSA modulus.
   * @return EM.
   * @throws SignatureException if the key is too small.
   */
  abstract byte[] encode(byte[] hash, int modBits) throws SignatureException;

  /**
   * Returns whether the result of the public key operation matches the hash.
   * @param hash the hash of the message.
   * @param m the signature raised to e, with the length of the modulus.
   * @param modBits the bit length of the RSA modulus.
   * @return whether the signature is valid.
   */
  abstract boolean matches(byte[] hash, byte[] m, int modBits);

  @Override
  protected void initVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof RSAPublicKey)) {
      throw new InvalidKeyException("not an RSA public key");
    }
    this.publicKey = (RSAPublicKey) publicKey;
    this.privateKey = null;
  }

  @Override
  protected void initSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof RSAPrivateKey)) {
      throw new InvalidKeyException("not an RSA private key");
    }
    this.privateKey = (RSAPrivateKey) privateKey;
    this.publicKey = null;
  }

  @Override
  protected byte[] sign(byte[] hash) throws SignatureException {
    // signature = EM^d mod n, with the length of the modulus
    byte[] em = encode(hash, privateKey.getModulus().bitLength());
    return RsaRaw.apply(primitives, Cipher.DECRYPT_MODE, privateKey, em);
  }

  @Override
  protected boolean verify(byte[] hash, byte[] sigBytes) throws SignatureException {
    BigInteger n = publicKey.getModulus();
    if (sigBytes.length != RsaRaw.modulusLength(publicKey)
        || new BigInteger(1, sigBytes).compareTo(n) >= 0) {
      return false;
    }

    byte[] m = RsaRaw.apply(primitives, Cipher.ENCRYPT_MODE, publicKey, sigBytes);
    return matches(hash, m, n.bitLength());
  }

}
