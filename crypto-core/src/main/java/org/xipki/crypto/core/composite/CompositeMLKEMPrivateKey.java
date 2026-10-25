// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
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
 * Composite MLKEMPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLKEMPrivateKey implements PrivateKey {

  private final PrivateKey pqcKey;

  private final PrivateKey tradKey;

  private final CompositeKemSuite suite;

  private final byte[] keyValue;

  public CompositeMLKEMPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws InvalidKeySpecException {
    this.suite = CompositeKemSuite.getAlgoSuite(privateKeyInfo.getPrivateKeyAlgorithm());
    Args.notNull(suite, "suite");
    byte[] encodedKeyValue = privateKeyInfo.privateKey();

    CompKemMlkemVariant pqcVariant = suite.pqcVariant();
    int off = pqcVariant.skSize();
    if (encodedKeyValue.length <= off) {
      throw new InvalidKeySpecException("composite private key too short");
    }

    byte[] pqcSk = Arrays.copyOfRange(encodedKeyValue, 0, off);
    byte[] tradSk = Arrays.copyOfRange(encodedKeyValue, off, encodedKeyValue.length);

    // XDH: the draft specifies the raw key, the CurvePrivateKey (RFC 8410)
    // requires the OCTET STRING wrapper.
    int rawXdhSkSize = rawXdhSkSize(suite.tradVariant());
    this.keyValue = encodedKeyValue;
    if (rawXdhSkSize > 0) {
      if (tradSk.length != rawXdhSkSize) {
        throw new InvalidKeySpecException("invalid length of XDH private key: "
            + tradSk.length);
      }
      tradSk = wrapOctetString(tradSk);
    }

    PrivateKeyInfo pqcSkInfo, tradSkInfo;
    try {
      pqcSkInfo = KeyInfoUtil.buildPrivateKeyInfo(
          pqcVariant.keySpec().algorithmIdentifier(),
          // RFC 9935: seed [0] OCTET STRING
          new MlkemPrivateKey(pqcSk, null).getEncoded());

      tradSkInfo = KeyInfoUtil.buildPrivateKeyInfo(
          suite.tradVariant().keySpec().algorithmIdentifier(), tradSk);
    } catch (CodecException e) {
      throw new InvalidKeySpecException(e);
    }

    this.pqcKey =  KeyInfoUtil.getPrivateKey(pqcSkInfo);
    this.tradKey = KeyInfoUtil.getPrivateKey(tradSkInfo);
  }

  public CompositeMLKEMPrivateKey(PrivateKey pqcKey, PrivateKey tradKey) {
    this.pqcKey = Args.notNull(pqcKey, "pqcKey");
    this.tradKey  = Args.notNull(tradKey, "tradKey");

    PrivateKeyInfo pqcSkInfo, tradSkInfo;
    try {
      pqcSkInfo = PrivateKeyInfo.fromPrivateKey(pqcKey);
      tradSkInfo = PrivateKeyInfo.fromPrivateKey(tradKey);
    } catch (CodecException e) {
      throw new IllegalArgumentException("could not parse encoded PrivateKey", e);
    }

    CompKemMlkemVariant pqcVariant =
        getPqcVariant(pqcSkInfo.getPrivateKeyAlgorithm().getAlgorithm());
    CompKemTradVariant tradVariant = null;

    if (tradKey instanceof RSAPrivateKey) {
      tradVariant = getRsaTradVariant(((RSAPrivateKey) tradKey).getModulus().bitLength());
    } else {
      KeySpec keySpec = KeySpec.ofAlgorithmIdentifier(tradSkInfo.getPrivateKeyAlgorithm());
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
          pqcVariant + " and " + tradVariant);
    }

    byte[] tradSk = tradSkInfo.privateKey();
    int rawXdhSkSize = rawXdhSkSize(tradVariant);
    if (rawXdhSkSize > 0) {
      // XDH: remove the OCTET STRING wrapper of CurvePrivateKey (RFC 8410)
      if (tradSk.length != rawXdhSkSize + 2 || tradSk[0] != 0x04
          || (tradSk[1] & 0xFF) != rawXdhSkSize) {
        throw new IllegalArgumentException("invalid XDH CurvePrivateKey");
      }
      tradSk = Arrays.copyOfRange(tradSk, 2, tradSk.length);
    }

    try {
      this.keyValue = org.xipki.codec.util.Arrays.concatenate(
                        KeyInfoUtil.getPqcSeed(pqcSkInfo), tradSk);
    } catch (CodecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private static int rawXdhSkSize(CompKemTradVariant tradVariant) {
    switch (tradVariant) {
      case X25519:
        return 32;
      case X448:
        return 56;
      default:
        return -1;
    }
  }

  private static byte[] wrapOctetString(byte[] raw) {
    // raw.length is 32 or 56, short-form length is sufficient.
    byte[] ret = new byte[2 + raw.length];
    ret[0] = 0x04;
    ret[1] = (byte) raw.length;
    System.arraycopy(raw, 0, ret, 2, raw.length);
    return ret;
  }

  public CompositeKemSuite suite() {
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

  static CompKemMlkemVariant getPqcVariant(Asn1Oid oid) {
    if (AlgorithmOIDs.id_ml_kem_768.equals(oid)) {
      return CompKemMlkemVariant.mlkem768;
    } else if (AlgorithmOIDs.id_ml_kem_1024.equals(oid)) {
      return CompKemMlkemVariant.mlkem1024;
    } else {
      throw new IllegalArgumentException("invalid pqcKey");
    }
  }

  static CompKemTradVariant getRsaTradVariant(int modulusBitLen) {
    CompKemTradVariant ret =
            (modulusBitLen == 2048) ? CompKemTradVariant.RSA2048_OAEP
          : (modulusBitLen == 3072) ? CompKemTradVariant.RSA3072_OAEP
          : (modulusBitLen == 4096) ? CompKemTradVariant.RSA4096_OAEP
          : null;
    if (ret == null) {
      throw new IllegalArgumentException("invalid RSA modulusBitLen " + modulusBitLen);
    }
    return ret;
  }

}
