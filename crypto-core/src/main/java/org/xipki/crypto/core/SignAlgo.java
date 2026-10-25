// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Integer;
import org.xipki.codec.asn1.Asn1Null;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.crypto.GCMParameters;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.RSASSAPSSParams;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.crypto.core.composite.CompositeMLDSAPrivateKey;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;

import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.xipki.crypto.core.HashAlgo.*;

/**
 * Sign Algo enumeration.
 *
 * @author Lijun Liao (xipki)
 */
// See https://www.itu.int/ITU-T/formal-language/itu-t/x/x509/2019/AlgorithmObjectIdentifiers.html
public enum SignAlgo {

  // RSA PKCS#1v1.5
  RSA_SHA1("SHA1WITHRSA",  0x01, AlgorithmOIDs.sha1WithRSAEncryption, SHA1, true),
  RSA_SHA224("SHA224WITHRSA", 0x02, AlgorithmOIDs.sha224WithRSAEncryption, SHA224, true),
  RSA_SHA256("SHA256WITHRSA", 0x03, AlgorithmOIDs.sha256WithRSAEncryption, SHA256, true),
  RSA_SHA384("SHA384WITHRSA", 0x04, AlgorithmOIDs.sha384WithRSAEncryption, SHA384, true),
  RSA_SHA512("SHA512WITHRSA", 0x05, AlgorithmOIDs.sha512WithRSAEncryption, SHA512, true),

  RSA_SHA3_224("SHA3-224WITHRSA", 0x06,
      AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_224, SHA3_224, true),
  RSA_SHA3_256("SHA3-256WITHRSA", 0x07,
      AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_256, SHA3_256, true),
  RSA_SHA3_384("SHA3-384WITHRSA", 0x08,
      AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_384, SHA3_384, true),
  RSA_SHA3_512("SHA3-512WITHRSA", 0x09,
      AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_512, SHA3_512, true),

  // RSA PSS with MGF1
  RSAPSS_SHA1  ("SHA1WITHRSAANDMGF1",   0x11, SHA1),
  RSAPSS_SHA224("SHA224WITHRSAANDMGF1", 0x12, SHA224),
  RSAPSS_SHA256("SHA256WITHRSAANDMGF1", 0x13, SHA256),
  RSAPSS_SHA384("SHA384WITHRSAANDMGF1", 0x14, SHA384),
  RSAPSS_SHA512("SHA512WITHRSAANDMGF1", 0x15, SHA512),

  RSAPSS_SHA3_224("SHA3-224WITHRSAANDMGF1", 0x16, SHA3_224),
  RSAPSS_SHA3_256("SHA3-256WITHRSAANDMGF1", 0x17, SHA3_256),
  RSAPSS_SHA3_384("SHA3-384WITHRSAANDMGF1", 0x18, SHA3_384),
  RSAPSS_SHA3_512("SHA3-512WITHRSAANDMGF1", 0x19, SHA3_512),

  // RSA PSS with SHAKE

  RSAPSS_SHAKE128("SHAKE128WITHRSAPSS", 0x1A,
      AlgorithmOIDs.id_RSASSA_PSS_SHAKE128, SHAKE128, false),
  RSAPSS_SHAKE256("SHAKE256WITHRSAPSS", 0x1B,
      AlgorithmOIDs.id_RSASSA_PSS_SHAKE256, SHAKE256, false),

  // ECDSA
  ECDSA_SHA1("SHA1WITHECDSA",     0x31, AlgorithmOIDs.ecdsa_with_SHA1,   SHA1,   false),
  ECDSA_SHA224("SHA224WITHECDSA", 0x32, AlgorithmOIDs.ecdsa_with_SHA224, SHA224, false),
  ECDSA_SHA256("SHA256WITHECDSA", 0x33, AlgorithmOIDs.ecdsa_with_SHA256, SHA256, false),
  ECDSA_SHA384("SHA384WITHECDSA", 0x34, AlgorithmOIDs.ecdsa_with_SHA384, SHA384, false),
  ECDSA_SHA512("SHA512WITHECDSA", 0x35, AlgorithmOIDs.ecdsa_with_SHA512, SHA512, false),

  ECDSA_SHA3_224("SHA3-224WITHECDSA", 0x36,
      AlgorithmOIDs.id_ecdsa_with_sha3_224, SHA3_224, false),
  ECDSA_SHA3_256("SHA3-256WITHECDSA", 0x37,
      AlgorithmOIDs.id_ecdsa_with_sha3_256, SHA3_256, false),
  ECDSA_SHA3_384("SHA3-384WITHECDSA", 0x38,
      AlgorithmOIDs.id_ecdsa_with_sha3_384, SHA3_384, false),
  ECDSA_SHA3_512("SHA3-512WITHECDSA", 0x39,
      AlgorithmOIDs.id_ecdsa_with_sha3_512, SHA3_512, false),

  // SM2
  SM2_SM3("SM3WITHSM2", 0x3A, AlgorithmOIDs.sm2sign_with_sm3, SM3, false),

  // ECDSA with SHAKE
  ECDSA_SHAKE128("SHAKE128WITHECDSA", 0x3B,
      AlgorithmOIDs.id_ecdsa_with_shake128, SHAKE128, false),
  ECDSA_SHAKE256("SHAKE256WITHECDSA", 0x3C,
      AlgorithmOIDs.id_ecdsa_with_shake256, SHAKE256, false),

  // EdDSA
  ED25519("ED25519", 0x46, CurveOIDs.id_ED25519, null, false),

  ED448("ED448", 0x47, CurveOIDs.id_ED448, null, false),

  // HMAC
  HMAC_SHA1("HMACSHA1",     0x51, AlgorithmOIDs.id_hmacWithSHA1,   SHA1, true),
  HMAC_SHA224("HMACSHA224", 0x52,
      AlgorithmOIDs.id_hmacWithSHA224, SHA224, true),
  HMAC_SHA256("HMACSHA256", 0x53,
      AlgorithmOIDs.id_hmacWithSHA256, SHA256, true),
  HMAC_SHA384("HMACSHA384", 0x54,
      AlgorithmOIDs.id_hmacWithSHA384, SHA384, true),
  HMAC_SHA512("HMACSHA512", 0x55,
      AlgorithmOIDs.id_hmacWithSHA512, SHA512, true),
  HMAC_SHA3_224("HMACSHA3-224", 0x56,
      AlgorithmOIDs.id_hmacWithSHA3_224, SHA3_224, true),
  HMAC_SHA3_256("HMACSHA3-256", 0x57,
      AlgorithmOIDs.id_hmacWithSHA3_256, SHA3_256, true),
  HMAC_SHA3_384("HMACSHA3-384", 0x58,
      AlgorithmOIDs.id_hmacWithSHA3_384, SHA3_384, true),
  HMAC_SHA3_512("HMACSHA3-512", 0x59,
      AlgorithmOIDs.id_hmacWithSHA3_512, SHA3_512, true),

  // AES-GMAC
  // we ignore there the params of GMAC
  GMAC_AES128("AES-GMAC", 0x61, AlgorithmOIDs.AES128_GMAC),
  GMAC_AES192("AES-GMAC", 0x62, AlgorithmOIDs.AES192_GMAC),
  GMAC_AES256("AES-GMAC", 0x63, AlgorithmOIDs.AES256_GMAC),

  //DHPOP-MAC
  DHPOP_X25519("DHPOP-X25519", 0x5A,
      XipkiOIDs.id_alg_dhPop_x25519, SHA512, false),
  DHPOP_X448("DHPOP-X448", 0x5B,
      XipkiOIDs.id_alg_dhPop_x448, SHA512, false),

  // MLDSA
  MLDSA44("ML-DSA-44", 0x60, AlgorithmOIDs.id_ml_dsa_44, null, false),
  MLDSA65("ML-DSA-65", 0x61, AlgorithmOIDs.id_ml_dsa_65, null, false),
  MLDSA87("ML-DSA-87", 0x62, AlgorithmOIDs.id_ml_dsa_87, null, false),

  // KEM: decrypt the ciphertext using HPKE to get the shared secret key, using
  // it to compute the MAC value. The jceName KEM-AEW-GMAC is just a dummy
  // value.
  KEM_HMAC_SHA256("KEM-HMAC-SHA256", 0x84,
      XipkiOIDs.id_alg_KEM_HMAC_SHA256, null, false),

  // composite algorithms
  MLDSA44_RSA2048("MLDSA44-RSA2048-PSS-SHA256",
      0x85, CompositeSigSuite.MLDSA44_RSA2048_PSS_SHA256),

  MLDSA44_ED25519("MLDSA44-Ed25519-SHA512",
      0x86, CompositeSigSuite.MLDSA44_Ed25519_SHA512),

  MLDSA44_P256("MLDSA44-ECDSA-P256-SHA256",
      0x87, CompositeSigSuite.MLDSA44_ECDSA_P256_SHA256),

  MLDSA65_RSA3072("MLDSA65-RSA3072-PSS-SHA512",
      0x88, CompositeSigSuite.MLDSA65_RSA3072_PSS_SHA512),

  MLDSA65_RSA4096("MLDSA65-RSA4096-PSS-SHA512",
      0x89, CompositeSigSuite.MLDSA65_RSA4096_PSS_SHA512),

  MLDSA65_P256("MLDSA65-ECDSA-P256-SHA512",
      0x8a, CompositeSigSuite.MLDSA65_ECDSA_P256_SHA512),

  MLDSA65_P384("MLDSA65-ECDSA-P384-SHA512",
      0x8b, CompositeSigSuite.MLDSA65_ECDSA_P384_SHA512),

  MLDSA65_BP256("MLDSA65-ECDSA-brainpoolP256r1-SHA512",
      0x8c, CompositeSigSuite.MLDSA65_ECDSA_BP256_SHA512),

  MLDSA65_ED25519("MLDSA65-Ed25519-SHA512",
      0x8d, CompositeSigSuite.MLDSA65_Ed25519_SHA512),

  MLDSA87_P384("MLDSA87-ECDSA-P384-SHA512",
      0x8e, CompositeSigSuite.MLDSA87_ECDSA_P384_SHA512),

  MLDSA87_BP384("MLDSA87-ECDSA-brainpoolP384r1-SHA512",
      0x8f, CompositeSigSuite.MLDSA87_ECDSA_BP384_SHA512),

  MLDSA87_ED448("MLDSA87-Ed448-SHAKE256",
      0x90, CompositeSigSuite.MLDSA87_Ed448_SHAKE256),

  MLDSA87_RSA3072("MLDSA87-RSA3072-PSS-SHA512",
      0x91, CompositeSigSuite.MLDSA87_RSA3072_PSS_SHA512),

  MLDSA87_RSA4096("MLDSA87-RSA4096-PSS-SHA512",
      0x92, CompositeSigSuite.MLDSA87_RSA4096_PSS_SHA512),

  MLDSA87_P521("MLDSA87-ECDSA-P521-SHA512",
      0x93, CompositeSigSuite.MLDSA87_ECDSA_P521_SHA512);

  private static final CryptoApi crypto = CryptoApiFactory.get();

  private static final int TRAILER_FIELD_BC = 1;

  private static final Map<String, SignAlgo> map = new HashMap<>();

  private static final Map<HashAlgo, SignAlgo> mgf1HashToSigMap = new HashMap<>();

  private final Asn1Oid oid;

  private final AlgorithmIdentifier algId;

  private final String jceName;

  private final byte code;

  private final HashAlgo hashAlgo;

  private final CompositeSigSuite compositeSigAlgoSuite;

  static {
    for (SignAlgo type : SignAlgo.values()) {
      String upperName = type.name().toUpperCase(Locale.ROOT);
      map.put(upperName, type);
      String upperName2 = upperName.replace("_", "-");
      if (!upperName.equals(upperName2)) {
        map.put(upperName2, type);
      }

      String upperName3 = upperName.replace("_", "");
      if (!upperName.equals(upperName3)) {
        map.put(upperName3, type);
      }

      if (AlgorithmOIDs.id_RSASSA_PSS.equals(type.oid)) {
        mgf1HashToSigMap.put(type.hashAlgo, type);
      } else {
        map.put(type.oid.getId(), type);
      }

      String jceName = type.jceName().toUpperCase(Locale.ROOT);

      List<String> names = new LinkedList<>();
      names.add(jceName);
      if (jceName.endsWith("RSAANDMGF1")) {
        // RSAANDMGF1: alias RSAPSS
        names.add(jceName.replace("RSAANDMGF1", "RSAPSS"));
      }

      for (String name : names) {
        map.put(name, type);

        boolean withMinus = name.indexOf('-') != -1;
        if (withMinus) {
          map.put(name.replace("-", ""), type);
        }

        int index = name.indexOf("WITH");
        if (index != -1) {
          String inverseName = name.substring(index + "WITH".length())
                                + "WITH" + name.substring(0, index);
          map.put(inverseName, type);
          if (withMinus) {
            map.put(inverseName.replace("-", ""), type);
          }
        }
      }
    }
  }

  SignAlgo(String jceName, int code, Asn1Oid oid,
          HashAlgo hashAlgo, boolean withNullParams) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.oid = oid;
    this.hashAlgo = hashAlgo;
    this.compositeSigAlgoSuite = null;
    this.algId = withNullParams ? AlgorithmIdentifier.ofNullParams(this.oid)
                                : new AlgorithmIdentifier(this.oid);
  }

  // RSA PSS with MGF1
  SignAlgo(String jceName, int code, HashAlgo hashAlgo) {
    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.hashAlgo = hashAlgo;

    AlgorithmIdentifier digAlgId = hashAlgo.algIdWithNullParams();
    int saltSize = hashAlgo.length();
    RSASSAPSSParams params = new RSASSAPSSParams(digAlgId,
        AlgorithmIdentifier.build(AlgorithmOIDs.id_mgf1, digAlgId),
        new Asn1Integer(BigInteger.valueOf(saltSize)), RSASSAPSSParams.DEFAULT_TRAILER_FIELD);

    this.oid = AlgorithmOIDs.id_RSASSA_PSS;
    this.algId = AlgorithmIdentifier.build(this.oid, params);
    this.compositeSigAlgoSuite = null;
  }

  // For GMAC: See https://tools.ietf.org/html/draft-ietf-lamps-cms-aes-gmac-alg-03
  SignAlgo(String jceName, int code, Asn1Oid oid) {
    if (!(jceName.startsWith("AES") && jceName.endsWith("GMAC"))) {
      throw new IllegalArgumentException("not AES*GMAC: " + jceName);
    }

    this.code = (byte) Args.range(code, "code", 0, 255);
    this.jceName = jceName.toUpperCase();
    this.oid = oid;
    this.hashAlgo = null;

    final int tagLen = 12;
    final int nonceLen = 12;

    /*
     * GMACParameters ::= SEQUENCE {
     *   nonce        OCTET STRING, -- recommended size is 12 octets
     *   length       MACLength DEFAULT 12 }
     *
     * MACLength ::= INTEGER (12 | 13 | 14 | 15 | 16)
     *
     */

    // nonce here is only placeholder, must be replaced before use: we use
    // default length (MACLength).
    // GMACParameters has exactly the same definition as GCMParameters
    // (see RFC 5084) so we use GCMParameters here (GMACParameters is not
    // defined in BouncyCastle)
    GCMParameters params = new GCMParameters(new byte[nonceLen], tagLen);
    this.algId = AlgorithmIdentifier.build(oid, params);
    this.compositeSigAlgoSuite = null;
  }

  // Composite Signature
  SignAlgo(String jceName, int code, CompositeSigSuite algoSuite) {
    this.code     = (byte) Args.range(code, "code", 0, 255);
    this.jceName  = jceName;
    this.algId    = algoSuite.algId();
    this.oid      = algoSuite.oid();
    this.hashAlgo = null;
    this.compositeSigAlgoSuite = algoSuite;
  }

  public HashAlgo hashAlgo() {
    return hashAlgo;
  }

  public CompositeSigSuite compositeSigAlgoSuite() {
    return compositeSigAlgoSuite;
  }

  public byte code() {
    return code;
  }

  public Asn1Oid oid() {
    return oid;
  }

  public String jceName() {
    return jceName;
  }

  public AlgorithmIdentifier algorithmIdentifier() {
    return algId;
  }

  public Signature newSignature() throws NoSuchAlgorithmException, NoSuchProviderException {
    return crypto.newSignature(jceName);
  }

  public boolean isECDSASigAlgo() {
    return this == ECDSA_SHA1
        || this == ECDSA_SHAKE128 || this == ECDSA_SHAKE256
        || this == ECDSA_SHA224   || this == ECDSA_SHA256
        || this == ECDSA_SHA384   || this == ECDSA_SHA512
        || this == ECDSA_SHA3_224 || this == ECDSA_SHA3_256
        || this == ECDSA_SHA3_384 || this == ECDSA_SHA3_512;
  } // method isECDSASigAlg

  public boolean isSM2SigAlgo() {
    Asn1Oid oid = Args.notNull(algId, "algId").getAlgorithm();
    return AlgorithmOIDs.sm2sign_with_sm3.equals(oid);
    // other algorithms not supported yet.
  } // method isSM2SigAlg

  public boolean isRSASigAlgo() {
    return isRSAPSSSigAlgo() || isRSAPkcs1SigAlgo();
  } // method isRSAPSSSigAlgo

  public boolean isRSAPkcs1SigAlgo() {
    return this == RSA_SHA1     || this == RSA_SHA224   || this == RSA_SHA256
        || this == RSA_SHA384   || this == RSA_SHA512   || this == RSA_SHA3_224
        || this == RSA_SHA3_256 || this == RSA_SHA3_384 || this == RSA_SHA3_512;
  } // method isRSASigAlgo

  public boolean isRSAPSSSigAlgo() {
    if (isRSAPSSMGF1SigAlgo()) {
      return true;
    }

    return this == RSAPSS_SHAKE128 || this == RSAPSS_SHAKE256;
  } // method isRSAPSSSigAlgo

  public boolean isRSAPSSMGF1SigAlgo() {
    return this == RSAPSS_SHA1     || this == RSAPSS_SHA224   || this == RSAPSS_SHA256
        || this == RSAPSS_SHA384   || this == RSAPSS_SHA512   || this == RSAPSS_SHA3_224
        || this == RSAPSS_SHA3_256 || this == RSAPSS_SHA3_384 || this == RSAPSS_SHA3_512;
  } // method isRSAPSSMGF1SigAlgo

  public boolean isCompositeMLDSA() {
    switch (this) {
      case MLDSA44_RSA2048:
      case MLDSA44_ED25519:
      case MLDSA44_P256:
      case MLDSA65_RSA3072:
      case MLDSA65_RSA4096:
      case MLDSA65_P256:
      case MLDSA65_P384:
      case MLDSA65_BP256:
      case MLDSA65_ED25519:
      case MLDSA87_P384:
      case MLDSA87_BP384:
      case MLDSA87_ED448:
      case MLDSA87_RSA3072:
      case MLDSA87_RSA4096:
      case MLDSA87_P521:
      return true;
      default:
        return false;
    }
  }

  public boolean isHmac() {
    return this == HMAC_SHA1     || this == HMAC_SHA224   || this == HMAC_SHA256
        || this == HMAC_SHA384   || this == HMAC_SHA512   || this == HMAC_SHA3_224
        || this == HMAC_SHA3_256 || this == HMAC_SHA3_384 || this == HMAC_SHA3_512;
  }

  public boolean isGmac() {
    return this == GMAC_AES128 || this == GMAC_AES192 || this == GMAC_AES256;
  }

  public boolean isMac() {
    return isHmac() || isGmac();
  }

  public static SignAlgo getInstance(AlgorithmIdentifier algId)
      throws NoSuchAlgorithmException {
    Asn1Oid oid = algId.getAlgorithm();
    Asn1Primitive params = algId.getParameters();

    SignAlgo rv = null;
    if (AlgorithmOIDs.id_RSASSA_PSS.equals(oid)) {
      RSASSAPSSParams param;
      try {
        param = RSASSAPSSParams.fromAsn1(params.asSequence());
      } catch (CodecException e) {
        throw new NoSuchAlgorithmException(e);
      }
      AlgorithmIdentifier digestAlgId = param.getHashAlgorithm();

      AlgorithmIdentifier mgf = param.getMaskGenAlgorithm();
      Asn1Oid mgfOid = mgf.getAlgorithm();
      if (!AlgorithmOIDs.id_mgf1.equals(mgfOid)) {
        throw new NoSuchAlgorithmException("mgf != MGF1");
      }

      AlgorithmIdentifier mgfDigestAlgId;
      try {
        mgfDigestAlgId = AlgorithmIdentifier.fromAsn1(mgf.getParameters().asSequence());
      } catch (CodecException e) {
        throw new NoSuchAlgorithmException(e);
      }

      if (!digestAlgId.equals(mgfDigestAlgId)) {
        throw new NoSuchAlgorithmException("digestAlg != MGF1.digestAlg");
      }

      int trailerField = param.getTrailerField().intValueExact();
      if (TRAILER_FIELD_BC != param.getTrailerField().intValueExact()) {
        throw new NoSuchAlgorithmException("trailerField != 0xBC" + trailerField);
      }

      HashAlgo hashAlgo = HashAlgo.getInstance(digestAlgId);
      int saltLen = param.getSaltLength().intValueExact();
      if (hashAlgo.length() != saltLen) {
        throw new NoSuchAlgorithmException("saltLen != " + hashAlgo.length() + ": " + saltLen);
      }

      return mgf1HashToSigMap.get(hashAlgo);
    } else if (SignAlgo.GMAC_AES128.oid.equals(oid) || SignAlgo.GMAC_AES192.oid.equals(oid)
                || SignAlgo.GMAC_AES256.oid.equals(oid)) {
      return SignAlgo.GMAC_AES128.oid.equals(oid) ? SignAlgo.GMAC_AES128
          :  SignAlgo.GMAC_AES192.oid.equals(oid) ? SignAlgo.GMAC_AES192 :  SignAlgo.GMAC_AES256;
    } else {
      if (params != null) {
        if (!Asn1Null.INSTANCE.equals(params)) {
          throw new NoSuchAlgorithmException("algId.parameters != NULL");
        }
      }

      for (SignAlgo algo : values()) {
        if (algo.oid.equals(oid)) {
          rv = algo;
        }
      }
    }
    return rv;
  }

  /**
   * Returns the hash algorithm used together with the given signature algorithm, e.g. the
   * digest algorithm of the CMS signer, and of the certHash in CMP certConf (RFC 9481).
   * @param sigAlgId the signature algorithm.
   * @return the hash algorithm.
   * @throws NoSuchAlgorithmException if the signature algorithm is not supported.
   */
  public static HashAlgo getHashAlgo(AlgorithmIdentifier sigAlgId)
      throws NoSuchAlgorithmException {
    SignAlgo signAlgo = getInstance(Args.notNull(sigAlgId, "sigAlgId"));
    if (signAlgo == null) {
      throw new NoSuchAlgorithmException(
          "unknown signature algorithm " + sigAlgId.getAlgorithm().getId());
    }

    if (signAlgo.hashAlgo() != null) {
      return signAlgo.hashAlgo();
    }

    switch (signAlgo) {
      case ED25519:
        return SHA512;
      case ED448:
      case MLDSA44:
      case MLDSA65:
      case MLDSA87:
        return SHAKE256;
      default:
        throw new NoSuchAlgorithmException("no hash algorithm for " + signAlgo);
    }
  }

  public static SignAlgo getInstance(String nameOrOid) throws NoSuchAlgorithmException {
    String key = nameOrOid.toUpperCase().replace("-", "");
    SignAlgo alg = map.get(key);
    return Optional.ofNullable(alg).orElseThrow(
        () -> new NoSuchAlgorithmException("Unknown SignAlgo OID/name '" + nameOrOid + "'"));
  }

  /**
   * Returns the default signature algorithm of the key.
   *
   * @param keyspec the key specification.
   * @param mode the signature mode, e.g. RSA PKCS#1 v1.5 or RSA-PSS.
   * @return the default signature algorithm, or null if none is defined for the key.
   */
  public static SignAlgo getDefaultSignAlgo(KeySpec keyspec, SignAlgoMode mode) {
    switch (keyspec) {
      case RSA2048:
      case RSA3072:
      case RSA4096:
        return (mode == SignAlgoMode.RSAPKCS1)
            ? SignAlgo.RSA_SHA256 : SignAlgo.RSAPSS_SHA256;
      case P256:
      case BRAINPOOLP256R1:
      case FRP256V1:
        return SignAlgo.ECDSA_SHA256;
      case P384:
      case BRAINPOOLP384R1:
        return SignAlgo.ECDSA_SHA384;
      case P521:
      case BRAINPOOLP512R1:
        return SignAlgo.ECDSA_SHA512;
      case SM2:
        return SignAlgo.SM2_SM3;
      case ED25519:
        return SignAlgo.ED25519;
      case ED448:
        return SignAlgo.ED448;
      case MLDSA44:
        return SignAlgo.MLDSA44;
      case MLDSA65:
        return SignAlgo.MLDSA65;
      case MLDSA87:
        return SignAlgo.MLDSA87;
      case X25519:
        return SignAlgo.DHPOP_X25519;
      case X448:
        return SignAlgo.DHPOP_X448;
    }

    if (keyspec.isCompositeMLDSA()) {
      try {
        return SignAlgo.getInstance(keyspec.algorithmIdentifier());
      } catch (NoSuchAlgorithmException e) {
        return null;
      }
    } else if (keyspec.isMlkem() || keyspec.isCompositeMLKEM()) {
      return SignAlgo.KEM_HMAC_SHA256;
    }

    return null;
  }

  public static SignAlgo getInstance(Key key) throws NoSuchAlgorithmException {
    return getInstance(key, null, null, null);
  }

  /**
   * Returns the signature algorithm for the key.
   * @param key the key.
   * @param algo the configured signature algorithm, may be null.
   * @param mode the configured RSA signature mode, may be null. Ignored if algo is set.
   * @param hashAlgo the configured hash algorithm, may be null. Ignored if algo is set.
   * @return the signature algorithm.
   * @throws NoSuchAlgorithmException if no signature algorithm is allowed for the key.
   */
  public static SignAlgo getInstance(Key key, SignAlgo algo, SignAlgoMode mode, HashAlgo hashAlgo)
      throws NoSuchAlgorithmException {
    if (algo != null) {
      mode = null;
      hashAlgo = null;
    }

    if (key instanceof RSAKey) {
      int keyBitLen = ((RSAKey) key).getModulus().bitLength();
      return checkRSASignAlgo(algo, mode, hashAlgo, keyBitLen);
    } else if (key instanceof ECKey) {
      EcCurveEnum curve = KeyInfoUtil.getCurve(key);
      if (curve == null) {
        throw new NoSuchAlgorithmException("unsupported EC curve");
      }
      return checkECSignAlgo(algo, hashAlgo, curve);
    } else if (key instanceof CompositeMLDSAPublicKey) {
      // composite MLDSA
      return checkCompositeSignAlgo(algo, hashAlgo, (CompositeMLDSAPublicKey) key);
    } else if (key instanceof CompositeMLDSAPrivateKey) {
      // composite MLDSA
      return checkCompositeSignAlgo(algo, hashAlgo, (CompositeMLDSAPrivateKey) key);
    } else {
      // by the algorithm OID: Key.getAlgorithm() is provider-specific, e.g. the JDK returns
      // "EdDSA" for Ed25519 and Ed448, and "ML-DSA" without the parameter set.
      EcCurveEnum curve = KeyInfoUtil.getCurve(key);
      if (curve != null) {
        return checkECSignAlgo(algo, hashAlgo, curve);
      }

      try {
        return checkMLDSASignAlgo(algo, hashAlgo, mldsaParamSpec(key));
      } catch (NoSuchAlgorithmException e) {
      }
    }

    throw new NoSuchAlgorithmException("Unknown key '" + key.getClass().getName());
  } // method getInstance

  public static SignAlgo checkRSASignAlgo(SignAlgo algo, SignAlgoMode mode, HashAlgo hashAlgo,
                                          int keySize) throws NoSuchAlgorithmException {
    if (algo != null) {
      if (algo.isRSASigAlgo()) {
        return algo;
      } else {
        throw new NoSuchAlgorithmException(algo + " is not an RSA signature algorithm");
      }
    }

    if (hashAlgo == null) {
      hashAlgo = getDefaultRSAHashAlgo(keySize);
    }
    return getRSAInstance(hashAlgo, mode);
  }

  public static SignAlgo checkECSignAlgo(SignAlgo algo, HashAlgo hashAlgo, EcCurveEnum curve)
      throws NoSuchAlgorithmException {
    SignAlgo allowedSignAlgo;
    if (curve == EcCurveEnum.ED25519 || curve == EcCurveEnum.ED448) {
      if (hashAlgo != null) {
        throw new NoSuchAlgorithmException("EDDSA does not allow any hash algorithm");
      }

      allowedSignAlgo = (curve == EcCurveEnum.ED25519) ? SignAlgo.ED25519 : ED448;
    } else {
      HashAlgo allowedHashAlgo = getDefaultECHashAlgo(curve);
      boolean hashInvalid = (hashAlgo != null && hashAlgo != allowedHashAlgo);
      if (hashInvalid) {
        throw new NoSuchAlgorithmException("hash algo " + hashAlgo +
            " is not allowed for " + curve + " EC key");
      }

      allowedSignAlgo = getWeierstrassECSigAlgo(allowedHashAlgo);
    }

    if (algo != null && algo != allowedSignAlgo) {
      throw new NoSuchAlgorithmException(
          "Algo " + algo + " is not allowed for " + curve + " EC key");
    }

    return allowedSignAlgo;
  }

  /**
   * Returns the ML-DSA parameter set (ML-DSA-44, ML-DSA-65 or ML-DSA-87) from the algorithm
   * OID of the encoded key.
   */
  private static String mldsaParamSpec(Key key) throws NoSuchAlgorithmException {
    Asn1Oid oid;
    try {
      oid = KeyInfoUtil.getAlgorithmOid(key);
    } catch (java.security.InvalidKeyException e) {
      throw new NoSuchAlgorithmException(e.getMessage(), e);
    }

    return AlgorithmOIDs.id_ml_dsa_44.equals(oid) ? "ML-DSA-44"
        : AlgorithmOIDs.id_ml_dsa_65.equals(oid) ? "ML-DSA-65"
        : AlgorithmOIDs.id_ml_dsa_87.equals(oid) ? "ML-DSA-87"
        : key.getAlgorithm();
  }

  public static SignAlgo checkMLDSASignAlgo(
      SignAlgo algo, HashAlgo hashAlgo, String paramSpec) throws NoSuchAlgorithmException {
    if (hashAlgo != null) {
      throw new NoSuchAlgorithmException("MLDSA does not allow any hash algorithm");
    }
    SignAlgo allowedSignAlgo =
              "ML-DSA-44".equalsIgnoreCase(paramSpec) ? MLDSA44
            : "ML-DSA-65".equalsIgnoreCase(paramSpec) ? MLDSA65
            : "ML-DSA-87".equalsIgnoreCase(paramSpec) ? MLDSA87 : null;
    if (allowedSignAlgo == null) {
      throw new NoSuchAlgorithmException("unknown MLDSA paramSpec " + paramSpec);
    }

    if (algo != null && algo != allowedSignAlgo) {
      throw new NoSuchAlgorithmException("Algo " + algo +
          " is not allowed for MLDSA key with paramSpec " + paramSpec);
    }

    return allowedSignAlgo;
  }

  private static SignAlgo checkCompositeSignAlgo(SignAlgo algo, HashAlgo hashAlgo, Key key)
      throws NoSuchAlgorithmException {
    if (hashAlgo != null) {
      throw new NoSuchAlgorithmException("Composite MLDSA does not allow any hash algorithm");
    }

    AlgorithmIdentifier algId;
    try {
      algId = (key instanceof PublicKey)
          ? SubjectPublicKeyInfo.algorithmFromPublicKey((PublicKey) key)
          : PrivateKeyInfo.algorithmFromPrivateKey((PrivateKey) key);
    } catch (CodecException e) {
      throw new NoSuchAlgorithmException("could not parse the encoded Key", e);
    }

    SignAlgo allowedSignAlgo = SignAlgo.getInstance(algId);
    if (allowedSignAlgo == null) {
      throw new NoSuchAlgorithmException("unknown key OID " + algId.getAlgorithm());
    }

    if (algo != null) {
      if (algo != allowedSignAlgo) {
        throw new NoSuchAlgorithmException("Algo " + algo +
            " is not allowed for composite MLDSA key with OID " + algId.getAlgorithm());
      }
    } else {
      algo = allowedSignAlgo;
    }

    return algo;
  }

  private static HashAlgo getDefaultRSAHashAlgo(int keySize) {
    return keySize > 3084 ? SHA512 : keySize > 2048 ? SHA384 : SHA256;
  }

  private static HashAlgo getDefaultECHashAlgo(EcCurveEnum curve) {
    if (curve == EcCurveEnum.SM2) {
      return SM3;
    }

    int fieldBitSize = curve.fieldBitSize();
    return fieldBitSize > 384 + 8 ? SHA512 : // plus buffer 8
          fieldBitSize > 256 + 8 ? SHA384 : SHA256;
  }

  private static SignAlgo getRSAInstance(HashAlgo hashAlgo, SignAlgoMode mode)
      throws NoSuchAlgorithmException {
    Args.notNull(hashAlgo, "hashAlgo");
    boolean rsaPss = mode == SignAlgoMode.RSAPSS;

    switch (hashAlgo) {
      case SHAKE128:
        return RSAPSS_SHAKE128;
      case SHAKE256:
        return RSAPSS_SHAKE256;
      case SHA1:
        return rsaPss ? RSAPSS_SHA1 : RSA_SHA1;
      case SHA224:
        return rsaPss ? RSAPSS_SHA224 : RSA_SHA224;
      case SHA256:
        return rsaPss ? RSAPSS_SHA256 : RSA_SHA256;
      case SHA384:
        return rsaPss ? RSAPSS_SHA384 : RSA_SHA384;
      case SHA512:
        return rsaPss ? RSAPSS_SHA512 : RSA_SHA512;
      case SHA3_224:
        return rsaPss ? RSAPSS_SHA3_224 : RSA_SHA3_224;
      case SHA3_256:
        return rsaPss ? RSAPSS_SHA3_256 : RSA_SHA3_256;
      case SHA3_384:
        return rsaPss ? RSAPSS_SHA3_384 : RSA_SHA3_384;
      case SHA3_512:
        return rsaPss ? RSAPSS_SHA3_512 : RSA_SHA3_512;
      default:
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for RSA");
    }
  } // method getRSAInstance

  private static SignAlgo getWeierstrassECSigAlgo(HashAlgo hashAlgo)
      throws NoSuchAlgorithmException {
    Args.notNull(hashAlgo, "hashAlgo");
    if (hashAlgo == SM3) {
      return SM2_SM3;
    }

    switch (hashAlgo) {
      case SHA1:
        return ECDSA_SHA1;
      case SHA224:
        return ECDSA_SHA224;
      case SHA256:
        return ECDSA_SHA256;
      case SHA384:
        return ECDSA_SHA384;
      case SHA512:
        return ECDSA_SHA512;
      case SHA3_224:
        return ECDSA_SHA3_224;
      case SHA3_256:
        return ECDSA_SHA3_256;
      case SHA3_384:
        return ECDSA_SHA3_384;
      case SHA3_512:
        return ECDSA_SHA3_512;
      case SHAKE128:
        return ECDSA_SHAKE128;
      case SHAKE256:
        return ECDSA_SHAKE256;
      default:
        throw new NoSuchAlgorithmException("unsupported hash " + hashAlgo + " for ECDSA");
    }
  } // method getECDSASigAlgo

  public static SignAlgo getSignAlgo(CompositeSigSuite algoSuite) throws NoSuchAlgorithmException {
    Args.notNull(algoSuite, "algoSuite");
    for (SignAlgo algo : SignAlgo.values()) {
      if (algo.compositeSigAlgoSuite == algoSuite) {
        return algo;
      }
    }

    throw new NoSuchAlgorithmException("unsupported CompositeSigAlgoSuite " + algoSuite);
  }

}
