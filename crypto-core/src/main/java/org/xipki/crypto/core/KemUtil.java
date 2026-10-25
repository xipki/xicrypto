// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.core.composite.CompositeKemSuite;
import org.xipki.crypto.core.composite.CompositeKemUtil;
import org.xipki.crypto.core.composite.CompositeMLKEMPrivateKey;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;

/**
 * KEMUtil.
 *
 * @author Lijun Liao (xipki)
 */
public class KemUtil {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  // macKey          = derive(masterKey, spki)
  // encapKey        = encapsulateKey(spki)
  // encryptedMacKey = enc_aesGcm(encapKey.secret, macKey)
  // result          = (encapKey.encapsulation, encryptedMacKey)
  public static KemEncapKey generateKemEncapKey(
      SubjectPublicKeyInfo spki, SecretKeyWithAlias masterKey, SecureRandom rnd)
      throws XiSecurityException {
    byte[] rawPkData = spki.subjectPublicKey();

    // derive the MAC key
    byte[] macKey = hmacDerive(masterKey.secretKey(), 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    return new KemEncapKey(masterKey.alias(), kemEncryptSecret(spki, macKey, rnd));
  }

  public static KemEncapsulation kemEncryptSecret(
      SubjectPublicKeyInfo spki, byte[] secret, SecureRandom rnd) throws XiSecurityException {
    AlgorithmIdentifier algId = spki.getAlgorithm();
    Asn1Oid algOid = algId.getAlgorithm();

    // Encapsulate a random key
    byte alg;
    SecretWithEncap skEncap;
    if (AlgorithmOIDs.id_ml_kem_512.equals(algOid) ||
        AlgorithmOIDs.id_ml_kem_768.equals(algOid) ||
        AlgorithmOIDs.id_ml_kem_1024.equals(algOid)) {
      alg = KemEncapsulation.ALG_KMAC_MLKEM_HMAC;

      skEncap = cryptoApi.encapsulateKey(
          MlkemVariant.fromOid(algOid), spki.subjectPublicKey(), rnd);
    } else {
      CompositeKemSuite suite = CompositeKemSuite.getAlgoSuite(algId);
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is neither an MLKEM nor a composite MLKEM key.");
      }

      alg = KemEncapsulation.ALG_KMAC_COMPOSITE_MLKEM_HMAC;
      skEncap = CompositeKemUtil.encap(suite, spki.subjectPublicKey(), rnd);
    }

    try {
      Cipher cipher = cryptoApi.newCipher("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(skEncap.secret(), "AES"),
          // skEncap.getSecret() is always fresh, so we used here constant IV.
          new GCMParameterSpec(128, new byte[12]));
      byte[] encryptedSecret = cipher.doFinal(secret);

      return new KemEncapsulation(alg, skEncap.encap(), encryptedSecret);
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
  }

  public static SecretWithEncap encapsulateKey(
      KeySpec keySpec, byte[] publicKeyData, SecureRandom rnd) {
    MlkemVariant pqcVariant = getMlkemVariant(keySpec);
    return cryptoApi.encapsulateKey(pqcVariant, publicKeyData, rnd);
  }

  public static MlkemVariant getMlkemVariant(KeySpec keySpec) {
    switch (keySpec) {
      case MLKEM512:
        return MlkemVariant.ml_kem_512;
      case MLKEM768:
        return MlkemVariant.ml_kem_768;
      case MLKEM1024:
        return MlkemVariant.ml_kem_1024;
      default:
        throw new IllegalArgumentException("invalid keySpec " + keySpec);
    }
  }

  // returns the decapsulated secret. pkValue is needed for the composite KEM.
  public static byte[] mlkemDecryptSecret(
      PrivateKey privateKey, KemEncapsulation kemEncapsulation) throws XiSecurityException {
    PrivateKeyInfo skInfo = null;
    try {
      skInfo = PrivateKeyInfo.fromPrivateKey(privateKey);
    } catch (CodecException e) {
      throw new XiSecurityException("could not parse encoded PrivateKey", e);
    }

    AlgorithmIdentifier algId = skInfo.getPrivateKeyAlgorithm();
    Asn1Oid algOid = algId.getAlgorithm();

    if (AlgorithmOIDs.id_ml_kem_512.equals(algOid) || AlgorithmOIDs.id_ml_kem_768.equals(algOid) ||
        AlgorithmOIDs.id_ml_kem_1024.equals(algOid)) {
      MlkemVariant variant = MlkemVariant.fromOid(algOid);
      byte[] expandedKeyOrSeed = getPqcExpandedKeyOrSeed(skInfo);
      byte[] decapKey = cryptoApi.decapsulateKey(
          variant, expandedKeyOrSeed, kemEncapsulation.encapKey());
      return doKemDecryptSecret(decapKey, kemEncapsulation);
    } else {
      throw new IllegalArgumentException("The given private key is not an MLKEM key.");
    }
  }

  private static byte[] getPqcExpandedKeyOrSeed(PrivateKeyInfo skInfo) throws XiSecurityException {
    byte[] skData = skInfo.privateKey();
    MlkemPrivateKey mlkemSk;
    try {
      mlkemSk = MlkemPrivateKey.fromEncoded(skData);
    } catch (CodecException e) {
      throw new XiSecurityException(e);
    }

    byte[] seed = mlkemSk.seed();
    byte[] expandedKey = mlkemSk.expandedKey();
    return expandedKey != null ? expandedKey : seed;
  }

  public static byte[] decapsulateKey(KeySpec keySpec, byte[] skValue, byte[] encapKey) {
    MlkemVariant pqcVariant = getMlkemVariant(keySpec);
    return cryptoApi.decapsulateKey(pqcVariant, skValue, encapKey);
  }

  public static byte[] compositeMlKemDecryptSecret(
      PrivateKey privateKey, byte[] publicKeyData, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    byte[] sk;
    CompositeKemSuite suite;

    if (privateKey instanceof CompositeMLKEMPrivateKey) {
      suite = ((CompositeMLKEMPrivateKey) privateKey).suite();
      sk = ((CompositeMLKEMPrivateKey) privateKey).keyValue();
    } else {
      PrivateKeyInfo skInfo = null;
      try {
        skInfo = PrivateKeyInfo.fromPrivateKey(privateKey);
      } catch (CodecException e) {
        throw new XiSecurityException("could not parse encoded PrivateKey", e);
      }
      suite = CompositeKemSuite.getAlgoSuite(skInfo.getPrivateKeyAlgorithm());
      if (suite == null) {
        throw new IllegalArgumentException("The given public key (spki) " +
            "is not an MLKEM or composite MLKEM key.");
      }
      sk = skInfo.privateKey();
    }

    byte[] decapKey = CompositeKemUtil.decap(suite, sk, publicKeyData, kemEncapsulation.encapKey());
    return doKemDecryptSecret(decapKey, kemEncapsulation);
  }

  public static byte[] doKemDecryptSecret(byte[] decapKey, KemEncapsulation kemEncapsulation)
      throws XiSecurityException {
    try {
      Cipher cipher = cryptoApi.newCipher("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decapKey, "AES"),
          new GCMParameterSpec(128, new byte[12]));
    return cipher.doFinal(kemEncapsulation.encryptedSecret());
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException(e);
    }
  }

  public static byte[] hmacDerive(SecretKey ikm, int keyByteSize, byte[] info, byte[] data) {
    return hmacDerive(ikm.getEncoded(), keyByteSize, info, data);
  }

  public static byte[] hmacDerive(byte[] ikm, int keyByteSize, byte[] info, byte[] data) {
    return KeyInfoUtil.hkdf(HashAlgo.SHA256, data, ikm, info, keyByteSize);
  }

}
