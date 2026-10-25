// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.asn1.crypto.ECPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Conversion and validation of EC keys for the JCA services of the XiPKI provider.
 *
 * @author Lijun Liao (xipki)
 */
final class EcKeys {

  private EcKeys() {
  }

  /**
   * Returns the curve of the {@link ECGenParameterSpec} (OID or name) or
   * {@link ECParameterSpec}.
   * @param spec the parameters.
   * @return the curve, or null if the parameters or the curve are not supported.
   */
  static EcCurve curveOf(AlgorithmParameterSpec spec) {
    if (spec instanceof ECGenParameterSpec) {
      return EcCurve.ofName(((ECGenParameterSpec) spec).getName());
    } else if (spec instanceof ECParameterSpec) {
      return EcCurve.ofParameterSpec((ECParameterSpec) spec);
    } else {
      return null;
    }
  }

  static EcCurve curveOf(ECParameterSpec spec) throws InvalidKeySpecException {
    EcCurve curve = EcCurve.ofParameterSpec(spec);
    if (curve == null) {
      throw new InvalidKeySpecException("unsupported EC parameters");
    }
    return curve;
  }

  /**
   * Decodes the signature SEQUENCE { r INTEGER, s INTEGER }, only DER.
   * @param sigBytes the encoded signature.
   * @return the signature, or null if it is not DER encoded.
   */
  static DssSigValue decodeSignature(byte[] sigBytes) {
    DssSigValue sig;
    try {
      sig = DssSigValue.fromEncoded(sigBytes);
    } catch (CodecException | RuntimeException e) {
      return null;
    }
    // only DER: the encoding must be the canonical one
    return Arrays.equals(sigBytes, sig.getEncoded()) ? sig : null;
  }

  /**
   * Returns the curve of the key algorithm: id-ecPublicKey with a named curve. As the key
   * algorithm, the OID sm2p256v1 without parameters is accepted, too.
   */
  static EcCurve curveOf(AlgorithmIdentifier keyAlgId) throws InvalidKeySpecException {
    Asn1Oid alg = keyAlgId.getAlgorithm();
    Asn1Primitive params = keyAlgId.getParameters();

    Asn1Oid curveOid;
    if (AlgorithmOIDs.id_ecPublicKey.equals(alg)) {
      if (!(params instanceof Asn1Oid)) {
        throw new InvalidKeySpecException("only named curves are supported");
      }
      curveOid = (Asn1Oid) params;
    } else if (CurveOIDs.sm2p256v1.equals(alg)) {
      curveOid = CurveOIDs.sm2p256v1;
    } else {
      throw new InvalidKeySpecException("not an EC key: " + alg.getId());
    }

    EcCurve curve = EcCurve.ofOid(curveOid);
    if (curve == null) {
      throw new InvalidKeySpecException("unsupported curve " + curveOid.getId());
    }
    return curve;
  }

  static XiECPublicKey newPublicKey(EcCurve curve, ECPoint w) throws InvalidKeySpecException {
    try {
      curve.checkPublicPoint(w);
    } catch (IllegalArgumentException e) {
      throw new InvalidKeySpecException("invalid public key: " + e.getMessage(), e);
    }
    return new XiECPublicKey(curve, w);
  }

  static XiECPrivateKey newPrivateKey(EcCurve curve, BigInteger s, ECPoint w)
      throws InvalidKeySpecException {
    if (s.signum() <= 0 || s.compareTo(curve.order()) >= 0) {
      throw new InvalidKeySpecException("private value out of range");
    }

    ECPoint expected = curve.multiplyG(s);
    if (w != null && !w.equals(expected)) {
      throw new InvalidKeySpecException("public key does not match the private key");
    }
    return new XiECPrivateKey(curve, s, expected);
  }

  static XiECPublicKey parsePublicKey(byte[] encoded) throws InvalidKeySpecException {
    SubjectPublicKeyInfo pkInfo;
    try {
      pkInfo = SubjectPublicKeyInfo.fromEncoded(encoded);
    } catch (CodecException | RuntimeException e) {
      throw new InvalidKeySpecException("invalid SubjectPublicKeyInfo", e);
    }

    EcCurve curve = curveOf(pkInfo.getAlgorithm());
    ECPoint w;
    try {
      w = curve.decodePublicPoint(pkInfo.subjectPublicKey());
    } catch (IllegalArgumentException e) {
      throw new InvalidKeySpecException("invalid public key: " + e.getMessage(), e);
    }
    return new XiECPublicKey(curve, w);
  }

  static XiECPrivateKey parsePrivateKey(byte[] encoded) throws InvalidKeySpecException {
    PrivateKeyInfo skInfo;
    ECPrivateKey sk;
    try {
      skInfo = PrivateKeyInfo.fromEncoded(encoded);
      sk = ECPrivateKey.fromEncoded(skInfo.privateKey());
    } catch (CodecException | RuntimeException e) {
      throw new InvalidKeySpecException("invalid PKCS#8 EC private key", e);
    }

    EcCurve curve = curveOf(skInfo.getPrivateKeyAlgorithm());
    if (sk.getParameters() != null) {
      Asn1Oid inner = sk.getParameters().getNamedCurve();
      if (inner != null && !inner.equals(curve.oid())) {
        throw new InvalidKeySpecException("inconsistent curves in the private key");
      }
    }

    byte[] pkData = sk.publicKey();
    if (pkData == null && skInfo.getPublicKey() != null) {
      pkData = skInfo.publicKey();
    }

    ECPoint w = null;
    if (pkData != null) {
      try {
        w = curve.decodePublicPoint(pkData);
      } catch (IllegalArgumentException e) {
        throw new InvalidKeySpecException("invalid public key: " + e.getMessage(), e);
      }
    }

    return newPrivateKey(curve, sk.bnPrivateKey(), w);
  }

  static XiECPublicKey toXiPublicKey(PublicKey key) throws InvalidKeyException {
    if (key instanceof XiECPublicKey) {
      return (XiECPublicKey) key;
    }

    if (!(key instanceof ECPublicKey)) {
      throw new InvalidKeyException("not an EC public key");
    }

    ECPublicKey ecKey = (ECPublicKey) key;
    try {
      return newPublicKey(curveOf(ecKey.getParams()), ecKey.getW());
    } catch (InvalidKeySpecException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    }
  }

  static XiECPrivateKey toXiPrivateKey(PrivateKey key) throws InvalidKeyException {
    if (key instanceof XiECPrivateKey) {
      return (XiECPrivateKey) key;
    }

    if (!(key instanceof java.security.interfaces.ECPrivateKey)) {
      throw new InvalidKeyException("not an EC private key");
    }

    java.security.interfaces.ECPrivateKey ecKey = (java.security.interfaces.ECPrivateKey) key;
    try {
      return newPrivateKey(curveOf(ecKey.getParams()), ecKey.getS(), null);
    } catch (InvalidKeySpecException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    }
  }

}
