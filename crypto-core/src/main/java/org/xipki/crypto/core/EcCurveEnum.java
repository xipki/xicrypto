// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.x509.AlgorithmIdentifier;
import org.xipki.codec.x509.id.AlgorithmOIDs;
import org.xipki.codec.x509.id.CurveOIDs;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * EC Curve Enum enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum EcCurveEnum {

  // EC
  P256(CurveOIDs.secp256r1, ConstPublicKeyAlgorithm.ec_secp256r1, 256, "P256", "SECP256R1"),
  P384(CurveOIDs.secp384r1, ConstPublicKeyAlgorithm.ec_secp384r1, 384, "P384", "SECP384R1"),
  P521(CurveOIDs.secp521r1, ConstPublicKeyAlgorithm.ec_secp521r1, 521, "P521", "SECP521R1"),
  /**
   * BrainPool P256R1 EC Key
   */
  BRAINPOOLP256R1(CurveOIDs.brainpoolP256r1, ConstPublicKeyAlgorithm.ec_brainpoolP256r1,
      256, "BRAINPOOLP256R1"),
  /**
   * BrainPool P384R1 EC Key
   */
  BRAINPOOLP384R1(CurveOIDs.brainpoolP384r1, ConstPublicKeyAlgorithm.ec_brainpoolP384r1,
      384, "BRAINPOOLP384R1"),
  /**
   * BrainPool P512R1 EC Key
   */
  BRAINPOOLP512R1(CurveOIDs.brainpoolP512r1, ConstPublicKeyAlgorithm.ec_brainpoolP512r1,
      512, "BRAINPOOLP512R1"),
  SM2(CurveOIDs.sm2p256v1, ConstPublicKeyAlgorithm.ec_sm2p256v1,
      256, "SM2P256V1", "SM2"),
  ED25519(false, CurveOIDs.id_ED25519, ConstPublicKeyAlgorithm.ed25519,
      256, "ED25519", "EDWARDS25519"),
  ED448(false,   CurveOIDs.id_ED448, ConstPublicKeyAlgorithm.ed448,
      448, "ED448", "EDWARDS448"),
  X25519(false,  CurveOIDs.id_X25519, ConstPublicKeyAlgorithm.x25519,
      256, "X25519", "CURVE25519"),
  X448(false,    CurveOIDs.id_X448, ConstPublicKeyAlgorithm.x448,
      448, "X448", "CURVE448");

  private final int fieldByteSize;

  private final int fieldBitSize;

  private final List<String> aliases;

  private final Asn1Oid oid;

  private final AlgorithmIdentifier algId;

  private final Integer c509AlgId;

  private final byte[] encodedOid;

  EcCurveEnum(Asn1Oid oid, Integer c509AlgId, int fieldBitSize, String... aliases) {
    this(true, oid, c509AlgId, fieldBitSize, aliases);
  }

  EcCurveEnum(boolean weierstrauss, Asn1Oid oid, Integer c509AlgId,
              int fieldBitSize, String... aliases) {
    this.oid = oid;
    this.c509AlgId = c509AlgId;
    this.fieldBitSize = fieldBitSize;
    this.fieldByteSize = (fieldBitSize + 7) / 8;
    this.aliases = new ArrayList<>(1);
    this.aliases.addAll(Arrays.asList(aliases));
    this.aliases.add(oid.getId());
    this.algId = weierstrauss ? new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, oid)
                              : new AlgorithmIdentifier(oid);

    this.encodedOid = oid.getEncoded();
  }

  public Asn1Oid oid() {
    return oid;
  }

  public Integer c509AlgId() {
    return c509AlgId;
  }

  public String mainAlias() {
    return aliases.get(0);
  }

  public int fieldBitSize() {
    return fieldBitSize;
  }

  public int fieldByteSize() {
    return fieldByteSize;
  }

  public AlgorithmIdentifier algId() {
    return algId;
  }

  public static EcCurveEnum ofOid(Asn1Oid oid) {
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (m.oid.equals(oid)) {
        return m;
      }
    }
    return null;
  }

  public static EcCurveEnum ofC509KeyAlg(int keyAlg) {
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (m.c509AlgId != null && m.c509AlgId == keyAlg) {
        return m;
      }
    }
    return null;
  }

  public static EcCurveEnum ofAlias(String alias) {
    alias = alias.toUpperCase(Locale.US).replace("-", "").replace("_", "");
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (m.aliases.contains(alias)) {
        return m;
      }
    }
    return null;
  }

  public static EcCurveEnum ofEncodedOid(byte[] encodedOid) {
    for (EcCurveEnum m : EcCurveEnum.values()) {
      if (Arrays.equals(m.encodedOid, encodedOid)) {
        return m;
      }
    }

    throw new IllegalArgumentException("found no EcCurveEnum for OID " + Hex.encode(encodedOid));
  }

}
