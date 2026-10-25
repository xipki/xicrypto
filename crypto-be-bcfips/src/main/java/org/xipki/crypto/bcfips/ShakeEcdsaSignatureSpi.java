// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.bcfips;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.exception.CodecException;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * ECDSA with SHAKE128 or SHAKE256 (RFC 8692) on the primitives of BC-FIPS: the message is hashed
 * with SHAKE128 (256 bits) or SHAKE256 (512 bits) of BC-FIPS, and the hash is signed with
 * NONEwithECDSA of BC-FIPS.
 * <p>
 * The nonce is random (X9.62 / SEC1), not deterministic as recommended by RFC 8692 for CAs, which
 * permits it under a stated policy. Verification is independent of the nonce. Only DER encoded
 * signatures are accepted.
 *
 * @author Lijun Liao (xipki)
 */
public class ShakeEcdsaSignatureSpi extends SignatureSpi {

  private static final String PROVIDER = BouncyCastleFipsProvider.PROVIDER_NAME;

  private final MessageDigest digest;

  private final Signature ecdsa;

  private boolean signing;

  private boolean initialized;

  /**
   * Constructor.
   * @param digestAlg "SHAKE128" (256 bits output) or "SHAKE256" (512 bits output).
   * @throws NoSuchAlgorithmException if BC-FIPS does not support the algorithms.
   * @throws NoSuchProviderException if BC-FIPS is not registered.
   */
  public ShakeEcdsaSignatureSpi(String digestAlg)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    this.digest = MessageDigest.getInstance(digestAlg, PROVIDER);
    this.ecdsa = Signature.getInstance("NONEwithECDSA", PROVIDER);
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof ECPublicKey)) {
      throw new InvalidKeyException("not an EC public key");
    }
    ecdsa.initVerify(publicKey);
    digest.reset();
    signing = false;
    initialized = true;
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    if (!(privateKey instanceof ECPrivateKey)) {
      throw new InvalidKeyException("not an EC private key");
    }
    if (random == null) {
      ecdsa.initSign(privateKey);
    } else {
      ecdsa.initSign(privateKey, random);
    }
    digest.reset();
    signing = true;
    initialized = true;
  }

  @Override
  protected void engineUpdate(byte b) {
    digest.update(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    digest.update(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (!initialized || !signing) {
      throw new SignatureException("not initialized for signing");
    }
    ecdsa.update(digest.digest());
    return ecdsa.sign();
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (!initialized || signing) {
      throw new SignatureException("not initialized for verification");
    }

    byte[] hash = digest.digest();

    // only DER: the encoding must be the canonical one
    try {
      DssSigValue sigValue = DssSigValue.fromEncoded(sigBytes);
      if (!Arrays.equals(sigBytes, sigValue.getEncoded())) {
        return false;
      }
    } catch (CodecException | RuntimeException e) {
      return false;
    }

    ecdsa.update(hash);
    try {
      return ecdsa.verify(sigBytes);
    } catch (SignatureException e) {
      return false;
    }
  }

  @Override
  @Deprecated
  protected void engineSetParameter(String param, Object value) {
    throw new InvalidParameterException("parameters are not supported");
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(String param) {
    throw new InvalidParameterException("parameters are not supported");
  }

}
