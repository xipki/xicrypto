// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.PrivateKeyInfo;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.crypto.core.KeySpec;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Composite Key Info Converter.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeKeyInfoConverter {

  public static boolean supportsPrivateKey(AlgorithmIdentifier algId) {
    KeySpec ks = KeySpec.ofAlgorithmIdentifier(algId);
    return ks != null && (ks.isCompositeMLDSA() || ks.isCompositeMLKEM());
  }

  public static boolean supportsPublicKey(AlgorithmIdentifier algId) {
    KeySpec ks = KeySpec.ofAlgorithmIdentifier(algId);
    return ks != null && (ks.isCompositeMLDSA() || ks.isCompositeMLKEM());
  }

  public static boolean supportsC509PublicKey(int keyAlgId) {
    KeySpec ks = KeySpec.ofC509AlgorithmIdentifier(keyAlgId);
    return ks != null && (ks.isCompositeMLDSA() || ks.isCompositeMLKEM());
  }

  public static PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
      throws InvalidKeySpecException {
    KeySpec ks = KeySpec.ofAlgorithmIdentifier(keyInfo.getPrivateKeyAlgorithm());
    if (ks != null && ks.isCompositeMLDSA()) {
      return new CompositeMLDSAPrivateKey(keyInfo);
    } else if (ks != null && ks.isCompositeMLKEM()) {
      return new CompositeMLKEMPrivateKey(keyInfo);
    } else {
      throw new InvalidKeySpecException("invalid keyInfo " + keyInfo);
    }
  }

  public static PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
      throws InvalidKeySpecException {
    KeySpec ks = KeySpec.ofAlgorithmIdentifier(keyInfo.getAlgorithm());
    if (ks != null && ks.isCompositeMLDSA()) {
      return new CompositeMLDSAPublicKey(keyInfo);
    } else if (ks != null && ks.isCompositeMLKEM()) {
      return new CompositeMLKEMPublicKey(keyInfo);
    } else {
      throw new InvalidKeySpecException("invalid keyInfo " + keyInfo);
    }
  }

  public static PublicKey generatePublic(C509SubjectPublicKey keyInfo)
      throws InvalidKeySpecException {
    KeySpec ks = KeySpec.ofC509AlgorithmIdentifier(keyInfo.algorithm());
    if (ks != null && ks.isCompositeMLDSA()) {
      return new CompositeMLDSAPublicKey(keyInfo);
    } else if (ks != null && ks.isCompositeMLKEM()) {
      return new CompositeMLKEMPublicKey(keyInfo);
    } else {
      throw new InvalidKeySpecException("invalid keyInfo " + keyInfo);
    }
  }

}
