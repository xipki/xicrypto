// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.crypt;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.util.HsmException;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Montgomery Curve Enum enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum MontgomeryCurveEnum {

  X25519(CurveOIDs.id_X25519, "curve25519", 32, 32),
  X448(CurveOIDs.id_X448, "curve448", 56, 56);

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final int privateKeySize;

  private final int publicKeySize;

  private final byte[] encodedOid;

  private final String oid;

  private final String curveName;

  private final byte[] encodedCurveName;

  MontgomeryCurveEnum(Asn1Oid oid, String curveName,
                      int privateKeySize, int publicKeySize) {
    this.oid = oid.getId();
    this.curveName = curveName;
    this.privateKeySize = privateKeySize;
    this.publicKeySize = publicKeySize;
    this.encodedOid = oid.getEncoded();
    this.encodedCurveName = new Asn1PrintableString(curveName).getEncoded();
  }

  public String getCurveName() {
    return curveName;
  }

  public String getOid() {
    return oid;
  }

  public byte[] getEncodedOid() {
    return encodedOid.clone();
  }

  public int getPublicKeySize() {
    return publicKeySize;
  }

  public static MontgomeryCurveEnum ofEcParams(byte[] ecParams) {
    for (MontgomeryCurveEnum v : values()) {
      if (Arrays.equals(v.encodedOid, ecParams) || Arrays.equals(v.encodedCurveName, ecParams)) {
        return v;
      }
    }
    return null;
  }

  public static MontgomeryCurveEnum ofEcParamsNonNull(byte[] ecParams) throws HsmException {
    MontgomeryCurveEnum curve = ofEcParams(ecParams);
    if (curve == null) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "Unknown ecParams " + Hex.encode(ecParams));
    }
    return curve;
  }

  public byte[][] generateKeyPair(SecureRandom random) {
    byte[] sk;
    byte[] pk;
    if (this == X25519) {
      sk = cryptoApi.generateX25519PrivateKey(random);
      pk = cryptoApi.generateX25519PublicKey(sk);
    } else {
      sk = cryptoApi.generateX448PrivateKey(random);
      pk = cryptoApi.generateX448PublicKey(sk);
    }
    return new byte[][]{sk, pk};
  }

}
