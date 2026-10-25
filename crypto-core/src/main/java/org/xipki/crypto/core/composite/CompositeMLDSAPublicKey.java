// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Composite MLDSAPublic Key.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAPublicKey implements PublicKey {

  private final PublicKey pqcKey;

  private final PublicKey tradKey;

  private final CompositeSigSuite suite;

  private final byte[] keyValue;

  public CompositeMLDSAPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    this.suite = CompositeSigSuite.getAlgoSuite(publicKeyInfo.getAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = publicKeyInfo.subjectPublicKey();

    CompSigMldsaVariant pqcVariant = suite.pqcVariant();

    byte[] mlkemPk = Arrays.copyOfRange(keyValue, 0, pqcVariant.pkSize());
    SubjectPublicKeyInfo pqcPkInfo = new SubjectPublicKeyInfo(
        pqcVariant.keySpec().algorithmIdentifier(), mlkemPk);

    int off = pqcVariant.pkSize();
    byte[] tradPk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    SubjectPublicKeyInfo tradPkInfo = new SubjectPublicKeyInfo(
        suite.tradVariant().keySpec().algorithmIdentifier(), tradPk);

    this.pqcKey = KeyInfoUtil.getPublicKey(pqcPkInfo);
    this.tradKey = KeyInfoUtil.getPublicKey(tradPkInfo);
  }

  public CompositeMLDSAPublicKey(PublicKey pqcKey, PublicKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    SubjectPublicKeyInfo pqcSpki, tradPkInfo;
    try {
      pqcSpki = SubjectPublicKeyInfo.fromPublicKey(pqcKey);
      tradPkInfo = SubjectPublicKeyInfo.fromPublicKey(tradKey);
    } catch (CodecException e) {
      throw new RuntimeException("could not parse PublicKey", e);
    }

    CompSigMldsaVariant pqcVariant = CompositeMLDSAPrivateKey.getMldsaVariant(
        pqcSpki.getAlgorithm().getAlgorithm());

    CompSigTradVariant tradVariant = null;
    if (tradKey instanceof RSAPublicKey) {
      tradVariant = CompositeMLDSAPrivateKey.getRsaTradVariant(
          ((RSAPublicKey) tradKey).getModulus().bitLength());
    } else {
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(tradPkInfo.getAlgorithm());
      if (keySpec != null) {
        tradVariant = CompSigTradVariant.ofKeySpec(keySpec);
      }
    }

    if (tradVariant == null) {
      throw new IllegalArgumentException("could not find SigTradVariant for given key");
    }

    this.suite = CompositeSigSuite.ofVariants(pqcVariant, tradVariant);
    if (this.suite == null) {
      throw new IllegalArgumentException("illegal combination of " +
          pqcVariant + " and " + tradKey);
    }

    this.keyValue = org.xipki.codec.util.Arrays.concatenate(
        pqcSpki.subjectPublicKey(), tradPkInfo.subjectPublicKey());
  }

  public PublicKey pqcKey() {
    return pqcKey;
  }

  public PublicKey tradKey() {
    return tradKey;
  }

  public byte[] keyValue() {
    return keyValue;
  }

  public CompositeSigSuite suite() {
    return suite;
  }

  @Override
  public String getAlgorithm() {
    return suite.name().replace('_', '-');
  }

  @Override
  public String getFormat() {
    return "X509";
  }

  @Override
  public byte[] getEncoded() {
    return new SubjectPublicKeyInfo(suite.algId(), keyValue).getEncoded();
  }

}
