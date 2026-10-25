// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.crypto.extra.ec.math.EcCurve;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactory "EC" for the named curves of {@link EcCurve}.
 *
 * @author Lijun Liao (xipki)
 */
public class XiECKeyFactorySpi extends KeyFactorySpi {

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof X509EncodedKeySpec) {
      return EcKeys.parsePublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
    } else if (keySpec instanceof ECPublicKeySpec) {
      ECPublicKeySpec spec = (ECPublicKeySpec) keySpec;
      return EcKeys.newPublicKey(EcKeys.curveOf(spec.getParams()), spec.getW());
    } else {
      throw new InvalidKeySpecException("unsupported KeySpec " + className(keySpec));
    }
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof PKCS8EncodedKeySpec) {
      return EcKeys.parsePrivateKey(((PKCS8EncodedKeySpec) keySpec).getEncoded());
    } else if (keySpec instanceof ECPrivateKeySpec) {
      ECPrivateKeySpec spec = (ECPrivateKeySpec) keySpec;
      return EcKeys.newPrivateKey(EcKeys.curveOf(spec.getParams()), spec.getS(), null);
    } else {
      throw new InvalidKeySpecException("unsupported KeySpec " + className(keySpec));
    }
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    Key k;
    try {
      k = engineTranslateKey(key);
    } catch (InvalidKeyException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }

    if (k instanceof XiECPublicKey) {
      XiECPublicKey pk = (XiECPublicKey) k;
      if (keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
        return keySpec.cast(new ECPublicKeySpec(pk.getW(), pk.getParams()));
      } else if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
        return keySpec.cast(new X509EncodedKeySpec(pk.getEncoded()));
      }
    } else {
      XiECPrivateKey sk = (XiECPrivateKey) k;
      if (keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
        return keySpec.cast(new ECPrivateKeySpec(sk.getS(), sk.getParams()));
      } else if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
        return keySpec.cast(new PKCS8EncodedKeySpec(sk.getEncoded()));
      }
    }

    throw new InvalidKeySpecException("unsupported KeySpec " + keySpec.getName());
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    if (key instanceof ECPublicKey) {
      return EcKeys.toXiPublicKey((ECPublicKey) key);
    } else if (key instanceof ECPrivateKey) {
      return EcKeys.toXiPrivateKey((ECPrivateKey) key);
    } else {
      throw new InvalidKeyException("not an EC key");
    }
  }

  private static String className(KeySpec keySpec) {
    return keySpec == null ? "null" : keySpec.getClass().getName();
  }

}
