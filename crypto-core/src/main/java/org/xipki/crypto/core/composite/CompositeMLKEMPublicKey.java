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
 * Composite MLKEMPublic Key.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPublicKey implements PublicKey {

  private final PublicKey pqcKey;

  private final PublicKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws InvalidKeySpecException {
    this.suite = CompositeKemSuite.getAlgoSuite(publicKeyInfo.getAlgorithm());
    Args.notNull(suite, "suite");
    this.keyValue = publicKeyInfo.subjectPublicKey();
    CompKemMlkemVariant pqcVariant = suite.pqcVariant();

    byte[] mlkemPk = Arrays.copyOfRange(keyValue, 0, pqcVariant.pkSize());
    SubjectPublicKeyInfo pqcPkInfo = new SubjectPublicKeyInfo(
        pqcVariant.keySpec().algorithmIdentifier(), mlkemPk);

    int off = pqcVariant.pkSize();
    byte[] tradPk  = Arrays.copyOfRange(keyValue, off, keyValue.length);
    SubjectPublicKeyInfo tradPkInfo = new SubjectPublicKeyInfo(
        suite.tradVariant().keySpec().algorithmIdentifier(), tradPk);

    this.pqcKey =  KeyInfoUtil.getPublicKey(pqcPkInfo);
    this.tradKey = KeyInfoUtil.getPublicKey(tradPkInfo);
  }

  public CompositeMLKEMPublicKey(PublicKey pqcKey, PublicKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    SubjectPublicKeyInfo pqcPkInfo, tradPkInfo;
    try {
      pqcPkInfo = SubjectPublicKeyInfo.fromPublicKey(pqcKey);
      tradPkInfo = SubjectPublicKeyInfo.fromPublicKey(tradKey);
    } catch (CodecException e) {
      throw new IllegalArgumentException("could not parse encoded PublicKey", e);
    }

    CompKemMlkemVariant pqcVariant = CompositeMLKEMPrivateKey.getPqcVariant(
        pqcPkInfo.getAlgorithm().getAlgorithm());

    CompKemTradVariant tradVariant = null;
    if (tradKey instanceof RSAPublicKey) {
      tradVariant = CompositeMLKEMPrivateKey.getRsaTradVariant(
          ((RSAPublicKey) tradKey).getModulus().bitLength());
    } else {
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(tradPkInfo.getAlgorithm());
      if (keySpec != null) {
        tradVariant = CompKemTradVariant.ofKeySpec(keySpec);
      }
    }

    if (tradVariant == null) {
      throw new IllegalArgumentException("invalid tradKey");
    }

    this.suite = CompositeKemSuite.ofVariants(pqcVariant, tradVariant);
    if (this.suite == null) {
      throw new IllegalArgumentException("illegal combination of " +
          pqcVariant + " and " + tradKey);
    }

    this.keyValue = org.xipki.codec.util.Arrays.concatenate(
        pqcPkInfo.subjectPublicKey(), tradPkInfo.subjectPublicKey());
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
