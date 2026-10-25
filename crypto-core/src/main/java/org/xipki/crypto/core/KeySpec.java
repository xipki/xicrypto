// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.exception.CodecException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Key Spec enumeration.
 *
 * @author Lijun Liao (xipki)
 */
public enum KeySpec {
  // RSA
  RSA2048("RSA2048", 2048),
  RSA3072("RSA3072", 3072),
  RSA4096("RSA4096", 4096),
  // EC
  P256("P256", Kind.WEIERSTRASS, CurveOIDs.secp256r1),
  P384("P384", Kind.WEIERSTRASS, CurveOIDs.secp384r1),
  P521("P521", Kind.WEIERSTRASS, CurveOIDs.secp521r1),
  /** BrainPool P256R1 EC Key */
  BRAINPOOLP256R1("BRAINPOOLP256R1", Kind.WEIERSTRASS, CurveOIDs.brainpoolP256r1),
  /** BrainPool P384R1 EC Key */
  BRAINPOOLP384R1("BRAINPOOLP384R1", Kind.WEIERSTRASS, CurveOIDs.brainpoolP384r1),
  /** BrainPool P512R1 EC Key */
  BRAINPOOLP512R1("BRAINPOOLP512R1", Kind.WEIERSTRASS, CurveOIDs.brainpoolP512r1),
  SM2("SM2", Kind.WEIERSTRASS, CurveOIDs.sm2p256v1),
  FRP256V1 ("FRP256V1", Kind.WEIERSTRASS, CurveOIDs.frp256v1),
  // Edwards and Montgomery EC key
  X25519 ("X25519",  Kind.MONTGOMERY, CurveOIDs.id_X25519),
  X448   ("X448",    Kind.MONTGOMERY, CurveOIDs.id_X448),
  ED25519("ED25519", Kind.EDWARDS,    CurveOIDs.id_ED25519),
  ED448  ("ED448",   Kind.EDWARDS,    CurveOIDs.id_ED448),
  // PQC MLDSA (Dilithium)
  MLDSA44("MLDSA44", Kind.MLDSA, AlgorithmOIDs.id_ml_dsa_44),
  MLDSA65("MLDSA65", Kind.MLDSA, AlgorithmOIDs.id_ml_dsa_65),
  MLDSA87("MLDSA87", Kind.MLDSA, AlgorithmOIDs.id_ml_dsa_87),
  // PQC ML-KEM (Kyber)
  MLKEM512 ("MLKEM512",  Kind.MLKEM, AlgorithmOIDs.id_ml_kem_512),
  MLKEM768 ("MLKEM768",  Kind.MLKEM, AlgorithmOIDs.id_ml_kem_768),
  MLKEM1024("MLKEM1024", Kind.MLKEM, AlgorithmOIDs.id_ml_kem_1024),

  // Composite MLDSA + Trad key
  MLDSA44_RSA2048(MLDSA44, RSA2048, AlgorithmOIDs.id_MLDSA44_RSA2048_PSS_SHA256),
  MLDSA44_ED25519(MLDSA44, ED25519, AlgorithmOIDs.id_MLDSA44_Ed25519_SHA512),
  MLDSA44_P256(MLDSA44, P256, AlgorithmOIDs.id_MLDSA44_ECDSA_P256_SHA256),
  MLDSA65_RSA3072(MLDSA65, RSA3072, AlgorithmOIDs.id_MLDSA65_RSA3072_PSS_SHA512),
  MLDSA65_RSA4096(MLDSA65, RSA4096, AlgorithmOIDs.id_MLDSA65_RSA4096_PSS_SHA512),
  MLDSA65_P256(MLDSA65, P256, AlgorithmOIDs.id_MLDSA65_ECDSA_P256_SHA512),
  MLDSA65_P384(MLDSA65, P384, AlgorithmOIDs.id_MLDSA65_ECDSA_P384_SHA512),
  MLDSA65_BP256(MLDSA65, BRAINPOOLP256R1, AlgorithmOIDs.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512),
  MLDSA65_ED25519(MLDSA65, ED25519, AlgorithmOIDs.id_MLDSA65_Ed25519_SHA512),
  MLDSA87_P384(MLDSA87, P384, AlgorithmOIDs.id_MLDSA87_ECDSA_P384_SHA512),
  MLDSA87_BP384(MLDSA87, BRAINPOOLP384R1, AlgorithmOIDs.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512),
  MLDSA87_ED448(MLDSA87, ED448, AlgorithmOIDs.id_MLDSA87_Ed448_SHAKE256),
  MLDSA87_RSA3072(MLDSA87, RSA3072, AlgorithmOIDs.id_MLDSA87_RSA3072_PSS_SHA512),
  MLDSA87_RSA4096(MLDSA87, RSA4096, AlgorithmOIDs.id_MLDSA87_RSA4096_PSS_SHA512),
  MLDSA87_P521(MLDSA87, P521, AlgorithmOIDs.id_MLDSA87_ECDSA_P521_SHA512),

  // Composite KEM + Trad key
  MLKEM768_RSA2048(MLKEM768, RSA2048, AlgorithmOIDs.id_MLKEM768_RSA2048_SHA3_256),
  MLKEM768_RSA3072(MLKEM768, RSA3072, AlgorithmOIDs.id_MLKEM768_RSA3072_SHA3_256),
  MLKEM768_RSA4096(MLKEM768, RSA4096, AlgorithmOIDs.id_MLKEM768_RSA4096_SHA3_256),
  MLKEM768_X25519(MLKEM768, X25519, AlgorithmOIDs.id_MLKEM768_X25519_SHA3_256),
  MLKEM768_P256(MLKEM768, P256, AlgorithmOIDs.id_MLKEM768_ECDH_P256_SHA3_256),
  MLKEM768_P384(MLKEM768, P384, AlgorithmOIDs.id_MLKEM768_ECDH_P384_SHA3_256),
  MLKEM768_BP256(MLKEM768, BRAINPOOLP256R1,
      AlgorithmOIDs.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256),
  MLKEM1024_RSA3072(MLKEM1024, RSA3072, AlgorithmOIDs.id_MLKEM1024_RSA3072_SHA3_256),
  MLKEM1024_P384(MLKEM1024, P384, AlgorithmOIDs.id_MLKEM1024_ECDH_P384_SHA3_256),
  MLKEM1024_BP384(MLKEM1024, BRAINPOOLP384R1,
      AlgorithmOIDs.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256),
  MLKEM1024_X448(MLKEM1024, X448, AlgorithmOIDs.id_MLKEM1024_X448_SHA3_256),
  MLKEM1024_P521(MLKEM1024, P521, AlgorithmOIDs.id_MLKEM1024_ECDH_P521_SHA3_256);

  private enum Kind {
    RSA,
    WEIERSTRASS,
    EDWARDS,
    MONTGOMERY,
    MLDSA,
    MLKEM
  }

  private final String text;

  private final AlgorithmIdentifier algId;

  /** null for composite keys. */
  private final Kind kind;

  private final Integer rsaModulusBits;

  private final KeySpec compositePqcVariant;

  private final KeySpec compositeTradVariant;

  KeySpec(KeySpec compositePqcVariant, KeySpec compositeTradVariant, Asn1Oid oid) {
    this.text = name().replace('_', '-');
    this.compositePqcVariant  = compositePqcVariant;
    this.compositeTradVariant = compositeTradVariant;
    this.algId = new AlgorithmIdentifier(oid);
    this.kind = null;
    this.rsaModulusBits = null;
  }

  KeySpec(String text, int rsaModulusBits) {
    this.compositePqcVariant  = null;
    this.compositeTradVariant = null;
    this.text = text;
    this.kind = Kind.RSA;
    this.rsaModulusBits = rsaModulusBits;
    this.algId = AlgorithmIdentifier.ofNullParams(AlgorithmOIDs.id_rsaEncryption);
  }

  /**
   * Constructor for the non-RSA keys.
   * @param text the text.
   * @param kind the kind of the key.
   * @param oid the curve OID for EC keys, the algorithm OID otherwise.
   */
  KeySpec(String text, Kind kind, Asn1Oid oid) {
    this.compositePqcVariant  = null;
    this.compositeTradVariant = null;
    this.text = text;
    this.kind = kind;
    this.rsaModulusBits = null;
    this.algId = (kind == Kind.WEIERSTRASS)
        ? new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, oid)
        : new AlgorithmIdentifier(oid);
  }

  public boolean isRSA() {
    return kind == Kind.RSA;
  }

  public Integer RSAKeyBitSize() {
    return rsaModulusBits;
  }

  public boolean isWeierstrassEC() {
    return kind == Kind.WEIERSTRASS;
  }

  public boolean isEdwardsEC() {
    return kind == Kind.EDWARDS;
  }

  public boolean isMontgomeryEC() {
    return kind == Kind.MONTGOMERY;
  }

  public boolean isMldsa() {
    return kind == Kind.MLDSA;
  }

  public boolean isMlkem() {
    return kind == Kind.MLKEM;
  }

  public boolean isCompositeMLDSA() {
    String name = name();
    if (name.startsWith("MLDSA")) {
      return name.startsWith("MLDSA44_") ||
          name.startsWith("MLDSA65_") || name.startsWith("MLDSA87_");
    }
    return false;
  }

  public boolean isCompositeMLKEM() {
    String name = name();
    if (name.startsWith("MLKEM")) {
      return name.startsWith("MLKEM512_") ||
          name.startsWith("MLKEM768_") || name.startsWith("MLKEM1024_");
    }
    return false;
  }

  public boolean isComposite() {
    return isCompositeMLDSA() ||isCompositeMLKEM();
  }

  public EcCurveEnum ecCurve() {
    switch (this) {
      case P256:
        return EcCurveEnum.P256;
      case P384:
        return EcCurveEnum.P384;
      case P521:
        return EcCurveEnum.P521;
      case BRAINPOOLP256R1:
        return EcCurveEnum.BRAINPOOLP256R1;
      case BRAINPOOLP384R1:
        return EcCurveEnum.BRAINPOOLP384R1;
      case BRAINPOOLP512R1:
        return EcCurveEnum.BRAINPOOLP512R1;
      case SM2:
        return EcCurveEnum.SM2;
      case FRP256V1:
        return EcCurveEnum.FRP256V1;
      case ED25519:
        return EcCurveEnum.ED25519;
      case ED448:
        return EcCurveEnum.ED448;
      case X25519:
        return EcCurveEnum.X25519;
      case X448:
        return EcCurveEnum.X448;
      default:
        return null;
    }
  }

  public Integer ecCurveFieldByteSize() {
    EcCurveEnum curve = ecCurve();
    return curve == null ? null : curve.fieldByteSize();
  }

  public String text() {
    return text;
  }

  public AlgorithmIdentifier algorithmIdentifier() {
    return algId;
  }

  public KeySpec compositePqcVariant() {
    return compositePqcVariant;
  }

  public KeySpec compositeTradVariant() {
    return compositeTradVariant;
  }

  public static KeySpec ofPublicKey(SubjectPublicKeyInfo keyInfo) throws CodecException {
    AlgorithmIdentifier keyAlgId = keyInfo.getAlgorithm();

    if (keyAlgId.getAlgorithm().equals(AlgorithmOIDs.id_rsaEncryption)) {
      RSAPublicKey rsa = RSAPublicKey.fromEncoded(keyInfo.subjectPublicKey());

      return ofRSA(rsa.modulus().bitLength());
    } else {
      return ofAlgorithmIdentifier(keyInfo.getAlgorithm());
    }
  }

  public static KeySpec ofAlgorithmIdentifier(AlgorithmIdentifier keyAlgId) {
    Asn1Oid keyAlgOid = keyAlgId.getAlgorithm();

    if (keyAlgOid.equals(AlgorithmOIDs.id_ecPublicKey)) {
      Asn1Oid curveOid;
      try {
        curveOid = keyAlgId.getParameters().asOid();
      } catch (CodecException e) {
        throw new IllegalStateException(e);
      }

      for (KeySpec spec : KeySpec.values()) {
        if (spec.isWeierstrassEC()) {
          if (curveOid.equals(spec.algId.getParameters())) {
            return spec;
          }
        }
      }
    } else {
      for (KeySpec spec : KeySpec.values()) {
        if (spec.isRSA() || spec.isWeierstrassEC()) {
          continue;
        }

        if (spec.algId.getAlgorithm().equals(keyAlgOid)) {
          return spec;
        }
      }
    }

    return null;
  }

  public static KeySpec ofRSA(int modulusBitLength) {
    switch (modulusBitLength) {
      case 2048: return KeySpec.RSA2048;
      case 3072: return KeySpec.RSA3072;
      case 4096: return KeySpec.RSA4096;
      default: return null;
    }
  }

  public static KeySpec ofEcCurve(EcCurveEnum curve) {
    switch (curve) {
      case P256: return KeySpec.P256;
      case P384: return KeySpec.P384;
      case P521: return KeySpec.P521;
      case BRAINPOOLP256R1: return KeySpec.BRAINPOOLP256R1;
      case BRAINPOOLP384R1: return KeySpec.BRAINPOOLP384R1;
      case BRAINPOOLP512R1: return KeySpec.BRAINPOOLP512R1;
      case SM2:       return KeySpec.SM2;
      case FRP256V1:  return KeySpec.FRP256V1;
      case ED25519:   return KeySpec.ED25519;
      case ED448:     return KeySpec.ED448;
      case X25519:    return KeySpec.X25519;
      case X448:      return KeySpec.X448;
      default:        return null;
    }
  }

  public static List<KeySpec> ofKeySpecs(List<String> names) throws NoSuchAlgorithmException {
    List<KeySpec> list = new ArrayList<>(names.size());
    for (String name : names) {
      list.add(ofKeySpec(name));
    }
    return list;
  }

  public static KeySpec ofKeySpec(String name) throws NoSuchAlgorithmException {
    name = name.trim().toUpperCase(Locale.ROOT);
    String name2 = name.replace('_', '-');
    String name3 = name2.replaceAll("-", "").replace("/", "");

    switch (name3) {
      case "SECP256R1":
        return P256;
      case "SECP384R1":
        return P384;
      case "SECP521R1":
        return P521;
      case "SM2P256V1":
        return SM2;
    }

    for (KeySpec m : KeySpec.values()) {
      String n = m.name();
      if (     n.equals(name) || n.equals(name2) || n.equals(name3) ||
          m.text.equals(name) || m.text.equals(name2) || m.text.equals(name3)) {
        return m;
      }
    }

    throw new NoSuchAlgorithmException("unknown KeySpec " + name);
  }

}
