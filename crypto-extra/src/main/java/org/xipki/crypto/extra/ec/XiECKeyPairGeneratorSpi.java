// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.crypto.extra.ec.math.EcCurve;
import org.xipki.crypto.extra.ec.math.ModN;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

/**
 * KeyPairGenerator "EC" for the named curves of {@link EcCurve}. The curve must be given as
 * {@link ECGenParameterSpec} (OID or name) or {@link java.security.spec.ECParameterSpec}, a key
 * size alone is ambiguous and not supported.
 *
 * @author Lijun Liao (xipki)
 */
public class XiECKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

  private EcCurve curve;

  private SecureRandom random;

  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new InvalidParameterException(
        "key size is not supported, use ECGenParameterSpec with the curve name");
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    EcCurve c = EcKeys.curveOf(params);
    if (c == null) {
      String desc = (params instanceof ECGenParameterSpec)
          ? "curve " + ((ECGenParameterSpec) params).getName()
          : "AlgorithmParameterSpec " + (params == null ? "null" : params.getClass().getName());
      throw new InvalidAlgorithmParameterException("unsupported " + desc);
    }

    this.curve = c;
    this.random = (random != null) ? random : new SecureRandom();
  }

  @Override
  public KeyPair generateKeyPair() {
    if (curve == null) {
      throw new IllegalStateException("not initialized");
    }

    // uniform in [1, n-1], constant-time (ModN); the BigInteger of the private key object is
    // created at the end (JCA boundary)
    ModN modN = curve.scalarField();
    ModN.Element d = modN.random(random);
    ECPoint q = curve.multiplyG(d);
    BigInteger s = modN.toBigInteger(d);
    return new KeyPair(new XiECPublicKey(curve, q), new XiECPrivateKey(curve, s, q));
  }

}
