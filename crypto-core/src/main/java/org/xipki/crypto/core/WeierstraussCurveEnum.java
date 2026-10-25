// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.ECCurve;
import org.xipki.crypto.api.ECPoint;
import org.xipki.crypto.api.X9ECParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Weierstrauss Curve Enum enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum WeierstraussCurveEnum {

  P256 (CurveOIDs.secp256r1),
  P384 (CurveOIDs.secp384r1),
  P521 (CurveOIDs.secp521r1),
  BP256(CurveOIDs.brainpoolP256r1),
  BP384(CurveOIDs.brainpoolP384r1),
  BP512(CurveOIDs.brainpoolP512r1),
  SM2  (CurveOIDs.sm2p256v1),
  FRP256V1(CurveOIDs.frp256v1);

  private final Asn1Oid asn1Oid;

  private final byte[] encodedOid;

  private final String oid;

  /**
   * Resolved lazily, so that an unsupported curve (e.g. SM2 if the SM algorithms are
   * disabled) does not prevent the use of the other curves.
   */
  private volatile X9ECParameters params;

  WeierstraussCurveEnum(Asn1Oid oid) {
    this.asn1Oid = oid;
    this.oid = oid.getId();
    this.encodedOid = oid.getEncoded();
  }

  private X9ECParameters params() {
    X9ECParameters p = params;
    if (p == null) {
      p = (this == SM2 && KeyInfoUtil.isSmDisabled()) ? null
          : CryptoApiFactory.get().getByOID(asn1Oid);
      if (p == null) {
        throw new IllegalStateException("unsupported curve " + name() + " (" + oid + ")");
      }
      params = p;
    }
    return p;
  }

  private ECCurve curve() {
    return params().getCurve();
  }

  /**
   * Returns whether this curve is supported in the current runtime.
   * @return true if supported, false otherwise.
   */
  public boolean isSupported() {
    try {
      params();
      return true;
    } catch (IllegalStateException e) {
      return false;
    }
  }

  public String getOid() {
    return oid;
  }

  public BigInteger getOrder() {
    return curve().getOrder();
  }

  public int getFieldBitSize() {
    return curve().getFieldSize();
  }

  public int getFieldByteSize() {
    return (curve().getFieldSize() + 7) / 8;
  }

  public byte[] getEncodedOid() {
    return encodedOid.clone();
  }

  /**
   * Returns the supported curve with the given order and x coordinate of the base point.
   * @param order the order of the curve.
   * @param baseX the x coordinate of the base point.
   * @return the curve, or null if no supported curve matches.
   */
  public static WeierstraussCurveEnum ofOrderAndBaseX(BigInteger order, BigInteger baseX) {
    for (WeierstraussCurveEnum m : WeierstraussCurveEnum.values()) {
      if (m.isSupported() && m.getOrder().equals(order)
          && m.params().getG().normalize().getXCoordBigInt().equals(baseX)) {
        return m;
      }
    }
    return null;
  }

  public static WeierstraussCurveEnum ofEcParams(byte[] ecParams) {
    for (WeierstraussCurveEnum v : values()) {
      if (Arrays.equals(v.encodedOid, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static WeierstraussCurveEnum ofEcParamsNonNull(byte[] ecParams)
      throws XiSecurityException {
    WeierstraussCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new XiSecurityException("Unknown ecParams " + Hex.encode(ecParams));
    }
    return curve;
  }

  public ECPoint decodePoint(byte[] encoded) throws XiSecurityException {
    try {
      return curve().decodePoint(encoded);
    } catch (RuntimeException e) {
      throw new XiSecurityException("invalid encoded EC point", e);
    }
  }

  public ECPoint multiplyBase(BigInteger k) {
    return params().getG().multiply(k).normalize();
  }

  public byte[] encodePoint(ECPoint point) {
    int fieldByteSize = (getFieldBitSize() + 7) / 8;
    byte[] r = new byte[1 + 2 * fieldByteSize];
    r[0] = 4;
    BigIntegers.asUnsignedByteArray(point.getXCoordBigInt(), r, 1, fieldByteSize);
    BigIntegers.asUnsignedByteArray(point.getYCoordBigInt(), r, 1 + fieldByteSize,
        fieldByteSize);
    return r;
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    BigInteger order = getOrder();
    int fieldByteSize = (getFieldBitSize() + 7) / 8;

    BigInteger sk;
    while (true) {
      byte[] bytes = new byte[fieldByteSize];
      random.nextBytes(bytes);

      sk = new BigInteger(1, bytes).mod(order);
      if (sk.signum() != 0) {
        break;
      }
    }

    ECPoint pk = multiplyBase(sk);
    return new byte[][] {BigIntegers.asUnsignedByteArray(fieldByteSize, sk), encodePoint(pk)};
  }

}
