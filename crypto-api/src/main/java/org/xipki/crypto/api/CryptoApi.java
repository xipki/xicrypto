// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * Crypto backend.
 * <p>
 * Methods which may be unsupported by a backend are documented as such. The callers (module
 * security) provide a backend-neutral fallback for them.
 *
 * @author Lijun Liao (xipki)
 */
public interface CryptoApi {

  /**
   * Returns the short name of this backend, e.g. "bc", "bcfips" or "jdk". It is used for the
   * selection via the system property {@link CryptoApiFactory#PROP_BACKEND}.
   * @return the short name of this backend.
   */
  String name();

  KeyStore newKeyStore(String algorithm) throws KeyStoreException, NoSuchProviderException;

  KeyAgreement newKeyAgreement(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  MessageDigest newMessageDigest(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  Mac newMac(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException;

  Signature newSignature(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  /**
   * Returns the cipher.
   * <p>
   * For RSA-OAEP, use "RSA/ECB/OAEPPadding" with an explicit
   * {@link javax.crypto.spec.OAEPParameterSpec}: the meaning of
   * "OAEPWith&lt;hash&gt;AndMGF1Padding" differs between the providers (the JDK uses MGF1 with
   * SHA-1, BouncyCastle MGF1 with &lt;hash&gt;).
   *
   * @param algorithm the transformation or the OID of the cipher.
   * @return the cipher.
   */
  Cipher newCipher(String algorithm) throws NoSuchPaddingException,
      NoSuchAlgorithmException, NoSuchProviderException;

  KeyFactory newKeyFactory(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  KeyPairGenerator newKeyPairGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  KeyGenerator newKeyGenerator(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  SecretKeyFactory newSecretKeyFactory(String algorithm)
      throws NoSuchAlgorithmException, NoSuchProviderException;

  PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo) throws InvalidKeySpecException;

  PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo) throws InvalidKeySpecException;

  /**
   * Derives a key with PBKDF2 (RFC 8018). The password is converted to bytes with UTF-8.
   *
   * @param hmacAlgorithm the JCA name of the PRF, e.g. "HmacSHA256".
   * @param password the password.
   * @param salt the salt.
   * @param iterationCount the iteration count.
   * @param keyLength the length of the derived key in bytes.
   * @return the derived key.
   * @throws GeneralSecurityException if the PRF is not supported or the derivation fails.
   */
  default byte[] pbkdf2(String hmacAlgorithm, char[] password, byte[] salt,
                        int iterationCount, int keyLength) throws GeneralSecurityException {
    SecretKeyFactory kf = newSecretKeyFactory("PBKDF2With" + hmacAlgorithm);
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength * 8);
    try {
      return kf.generateSecret(spec).getEncoded();
    } finally {
      spec.clearPassword();
    }
  }

  /**
   * Derives a key with PBKDF2 (RFC 8018). The password is converted to bytes with UTF-8.
   *
   * @param prf the PRF. If null, the default PRF hmacWithSHA1 is used.
   * @param password the password.
   * @param salt the salt.
   * @param iterationCount the iteration count.
   * @param keyLength the length of the derived key in bytes.
   * @return the derived key.
   * @throws GeneralSecurityException if the PRF is not supported or the derivation fails.
   */
  default byte[] pbkdf2(AlgorithmIdentifier prf, char[] password, byte[] salt,
                        int iterationCount, int keyLength) throws GeneralSecurityException {
    String hmacName = (prf == null) ? "HmacSHA1"
        : AlgorithmNames.getHmacName(prf.getAlgorithm());
    if (hmacName == null) {
      throw new NoSuchAlgorithmException("unsupported PBKDF2 PRF " + prf.getAlgorithm().getId());
    }
    return pbkdf2(hmacName, password, salt, iterationCount, keyLength);
  }

  /**
   * Sets the context string of a signature (e.g. ML-DSA). It must be called after
   * {@link Signature#initSign} or {@link Signature#initVerify}: some backends (e.g. BC-FIPS) do
   * not accept the context before the initialization.
   * @param sig the signature.
   * @param context the context. Null or empty means no context.
   * @throws InvalidAlgorithmParameterException if the context is not supported by this backend.
   */
  void setContext(Signature sig, byte[] context) throws InvalidAlgorithmParameterException;

  /**
   * Computes the extendable-output function (XOF).
   * @param algorithm SHAKE128 or SHAKE256.
   * @param data the input.
   * @param length the output length in bytes.
   * @return the output.
   * @throws UnsupportedOperationException if this backend does not support XOF.
   */
  byte[] xof(String algorithm, byte[] data, int length);

  /**
   * Derives a key using HKDF-SHA-256 (RFC 5869).
   *
   * @param ikm    input keying material
   * @param salt   optional salt; empty array if absent
   * @param info   application/context-specific information
   * @param outputKeyLen desired output key size in bytes
   * @return derived key
   */
  byte[] hkdfSha256Derive(byte[] ikm, byte[] salt, byte[] info, int outputKeyLen);

  SecureRandom getSecureRandom(SecureRandom random);

  /**
   * Returns the parameters of the named Weierstrass curve.
   * @param oid the curve OID.
   * @return the curve parameters, or null if this backend does not support the curve.
   */
  X9ECParameters getByOID(Asn1Oid oid);

  byte[] generateX25519PrivateKey(SecureRandom rnd);

  byte[] generateX25519PublicKey(byte[] sk);

  byte[] calculateX25519Agreement(byte[] sk, byte[] peerPk);

  byte[] generateX448PrivateKey(SecureRandom rnd);

  byte[] generateX448PublicKey(byte[] sk);

  byte[] calculateX448Agreement(byte[] sk, byte[] peerPk);

  /**
   * Generate MLDSA keypair.
   * @param variant the ML-DSA variant.
   * @param random may be null
   * @return the generated keypair
   */
  KeyPair generateKeyPair(MldsaVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException;

  /**
   * Generate MLKEM keypair.
   * @param variant the ML-KEM variant.
   * @param random may be null
   * @return the generated keypair
   */
  KeyPair generateKeyPair(MlkemVariant variant, SecureRandom random)
      throws NoSuchAlgorithmException;

  SecretWithEncap encapsulateKey(
      MlkemVariant pqcVariant, byte[] publicKeyData, SecureRandom rnd);

  byte[] decapsulateKey(
      MlkemVariant pqcVariant, byte[] privateKeyValue, byte[] encapsulatedKey);

  /**
   * Computes the ML-DSA private key sk (ML-DSA.KeyGen_internal of FIPS 204) from the seed.
   * @param variant the ML-DSA variant.
   * @param seed the 32-byte seed (xi).
   * @return the private key sk (2560, 4032 or 4896 bytes).
   * @throws UnsupportedOperationException if this backend cannot compute it.
   */
  byte[] expandMldsaSeed(MldsaVariant variant, byte[] seed);

  /**
   * Computes the ML-KEM decapsulation key dk (ML-KEM.KeyGen of FIPS 203) from the seed.
   * @param variant the ML-KEM variant.
   * @param seed the 64-byte seed (d || z).
   * @return the decapsulation key dk (1632, 2400 or 3168 bytes).
   * @throws UnsupportedOperationException if this backend cannot compute it.
   */
  byte[] expandMlkemSeed(MlkemVariant variant, byte[] seed);

  /**
   * Returns the JCA standard name of the digest algorithm, e.g. "SHA-256".
   * @param digAlgId the digest algorithm.
   * @return the name, or the dotted OID if the algorithm is unknown.
   */
  default String getDigestName(AlgorithmIdentifier digAlgId) {
    return AlgorithmNames.getDigestName(digAlgId.getAlgorithm());
  }

}
