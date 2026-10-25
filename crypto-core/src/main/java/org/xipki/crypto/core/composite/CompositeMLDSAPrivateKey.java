// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Composite MLDSAPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAPrivateKey implements PrivateKey {

  private final PrivateKey pqcKey;

  private final PrivateKey tradKey;

  private final CompositeSigSuite suite;

  private final byte[] keyValue;

  public CompositeMLDSAPrivateKey(PrivateKeyInfo privateKeyInfo) throws InvalidKeySpecException {
    this.suite = CompositeSigSuite.getAlgoSuite(privateKeyInfo.getPrivateKeyAlgorithm());
    Args.notNull(suite, "suite");
    byte[] encodedKeyValue = privateKeyInfo.privateKey();

    CompSigMldsaVariant pqcVariant = suite.pqcVariant();
    int off = pqcVariant.skSize();
    if (encodedKeyValue.length <= off) {
      throw new InvalidKeySpecException("composite private key too short");
    }

    byte[] pqcSk = Arrays.copyOfRange(encodedKeyValue, 0, off);
    byte[] tradSk = Arrays.copyOfRange(encodedKeyValue, off, encodedKeyValue.length);

    // EdDSA: the draft specifies the raw key, the CurvePrivateKey (RFC 8410)
    // requires the OCTET STRING wrapper.
    int rawEdSkSize = rawEdSkSize(suite.tradVariant());
    this.keyValue = encodedKeyValue;
    if (rawEdSkSize > 0) {
      if (tradSk.length != rawEdSkSize) {
        throw new InvalidKeySpecException("invalid length of EdDSA private key: "
            + tradSk.length);
      }
      tradSk = wrapOctetString(tradSk);
    }

    PrivateKeyInfo pqcSkInfo, tradSkInfo;
    try {
      pqcSkInfo = KeyInfoUtil.buildPrivateKeyInfo(
          pqcVariant.keySpec().algorithmIdentifier(),
          // RFC 9881: seed [0] OCTET STRING
          new MldsaPrivateKey(pqcSk, null).getEncoded());

      tradSkInfo = KeyInfoUtil.buildPrivateKeyInfo(
          suite.tradVariant().keySpec().algorithmIdentifier(), tradSk);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(e);
    }

    this.pqcKey  = KeyInfoUtil.getPrivateKey(pqcSkInfo);
    this.tradKey = KeyInfoUtil.getPrivateKey(tradSkInfo);
  }

  public CompositeMLDSAPrivateKey(PrivateKey pqcKey, PrivateKey tradKey) throws CodecException {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    PrivateKeyInfo pqcSkInfo = PrivateKeyInfo.fromEncoded(pqcKey.getEncoded());

    CompSigMldsaVariant pqcVariant =
        getMldsaVariant(pqcSkInfo.getPrivateKeyAlgorithm().getAlgorithm());

    PrivateKeyInfo tradSkInfo = PrivateKeyInfo.fromEncoded(tradKey.getEncoded());

    CompSigTradVariant tradVariant = null;
    if (tradKey instanceof RSAPrivateKey) {
      tradVariant = getRsaTradVariant(((RSAPrivateKey) tradKey).getModulus().bitLength());
    } else {
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(tradSkInfo.getPrivateKeyAlgorithm());
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
          pqcVariant + " and " + tradVariant);
    }

    byte[] tradSk = tradSkInfo.privateKey();
    int rawEdSkSize = rawEdSkSize(tradVariant);
    if (rawEdSkSize > 0) {
      // EdDSA: remove the OCTET STRING wrapper of CurvePrivateKey (RFC 8410)
      if (tradSk.length != rawEdSkSize + 2 || tradSk[0] != 0x04
          || (tradSk[1] & 0xFF) != rawEdSkSize) {
        throw new CodecException("invalid EdDSA CurvePrivateKey");
      }
      tradSk = Arrays.copyOfRange(tradSk, 2, tradSk.length);
    }

    this.keyValue = org.xipki.codec.util.Arrays.concatenate(
                      KeyInfoUtil.getPqcSeed(pqcSkInfo), tradSk);
  }

  private static int rawEdSkSize(CompSigTradVariant tradVariant) {
    switch (tradVariant) {
      case Ed25519:
        return 32;
      case Ed448:
        return 57;
      default:
        return -1;
    }
  }

  private static byte[] wrapOctetString(byte[] raw) {
    // raw.length is 32 or 57, short-form length is sufficient.
    byte[] ret = new byte[2 + raw.length];
    ret[0] = 0x04;
    ret[1] = (byte) raw.length;
    System.arraycopy(raw, 0, ret, 2, raw.length);
    return ret;
  }

  public CompositeSigSuite suite() {
    return suite;
  }

  public byte[] keyValue() {
    return keyValue.clone();
  }

  public PrivateKey pqcKey() {
    return pqcKey;
  }

  public PrivateKey tradKey() {
    return tradKey;
  }

  @Override
  public String getAlgorithm() {
    return suite.name().replace('_', '-');
  }

  @Override
  public String getFormat() {
    return "PKCS#8";
  }

  @Override
  public byte[] getEncoded() {
    try {
      return KeyInfoUtil.buildPrivateKeyInfo(suite.algId(), keyValue).getEncoded();
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
  }

  static CompSigMldsaVariant getMldsaVariant(Asn1Oid oid) {
    if (AlgorithmOIDs.id_ml_dsa_44.equals(oid)) {
      return CompSigMldsaVariant.mldsa44;
    } else if (AlgorithmOIDs.id_ml_dsa_65.equals(oid)) {
      return CompSigMldsaVariant.mldsa65;
    } else if (AlgorithmOIDs.id_ml_dsa_87.equals(oid)) {
      return CompSigMldsaVariant.mldsa87;
    } else {
      throw new IllegalArgumentException("invalid pqcKey");
    }
  }

  static CompSigTradVariant getRsaTradVariant(int modulusBitLen) {
    CompSigTradVariant ret =
            (modulusBitLen == 2048) ? CompSigTradVariant.RSA2048_PSS
          : (modulusBitLen == 3072) ? CompSigTradVariant.RSA3072_PSS
          : (modulusBitLen == 4096) ? CompSigTradVariant.RSA4096_PSS
          : null;
    if (ret == null) {
      throw new IllegalArgumentException("invalid RSA modulusBitLen " + modulusBitLen);
    }
    return ret;
  }

}
