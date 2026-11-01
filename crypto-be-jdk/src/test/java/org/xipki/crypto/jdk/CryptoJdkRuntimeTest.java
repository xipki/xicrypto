// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Tests crypto-be-jdk with keys of BouncyCastle (XDH, RFC 8410) and ML-KEM with an invalid
 * ciphertext.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkRuntimeTest {

  private static final CryptoJdk CRYPTO = new CryptoJdk();

  /**
   * X25519 and X448 keys of crypto-be-jdk are encoded as in RFC 8410, are readable from RFC 8410
   * encodings (also PKCS#8 v2 with the public key), and work in the key agreement.
   */
  @Test
  public void testXdhRfc8410() throws Exception {
    Provider bc = new BouncyCastleProvider();
    for (String alg : new String[] {"X25519", "X448"}) {
      // keys of crypto-be-jdk: readable by BouncyCastle
      KeyPair kp = CRYPTO.newKeyPairGenerator(alg).generateKeyPair();
      KeyFactory bcKf = KeyFactory.getInstance(alg, bc);
      PrivateKey bcSk = bcKf.generatePrivate(
          new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
      PublicKey bcPk = bcKf.generatePublic(
          new X509EncodedKeySpec(kp.getPublic().getEncoded()));
      // RFC 8410: no parameters in the AlgorithmIdentifier, CurvePrivateKey (OCTET STRING)
      Assert.assertArrayEquals(alg, bcPk.getEncoded(), kp.getPublic().getEncoded());
      PrivateKeyInfo info = PrivateKeyInfo.fromEncoded(kp.getPrivate().getEncoded());
      Assert.assertNull(alg, info.getPrivateKeyAlgorithm().getParameters());
      Assert.assertEquals(alg, 0x04, info.privateKey()[0] & 0xFF);

      // keys of BouncyCastle (PKCS#8 v2 with the public key): readable by crypto-be-jdk
      KeyPair bcKp = KeyPairGenerator.getInstance(alg, bc).generateKeyPair();
      PrivateKey sk = CRYPTO.getPrivateKey(
          PrivateKeyInfo.fromEncoded(bcKp.getPrivate().getEncoded()));
      PublicKey pk = CRYPTO.getPublicKey(
          SubjectPublicKeyInfo.fromEncoded(bcKp.getPublic().getEncoded()));
      Assert.assertArrayEquals(alg, bcKp.getPublic().getEncoded(), pk.getEncoded());

      // key agreement in both directions
      KeyAgreement ka = CRYPTO.newKeyAgreement(alg);
      ka.init(sk);
      ka.doPhase(kp.getPublic(), true);
      byte[] z1 = ka.generateSecret();
      KeyAgreement bcKa = KeyAgreement.getInstance(alg, bc);
      bcKa.init(bcSk);
      bcKa.doPhase(bcKp.getPublic(), true);
      Assert.assertArrayEquals(alg, z1, bcKa.generateSecret());
    }
  }

  @Test
  public void testMlkemInvalidCiphertext() throws Exception {
    for (MlkemVariant variant : MlkemVariant.values()) {
      byte[] pk = SubjectPublicKeyInfo.fromEncoded(
          CRYPTO.generateKeyPair(variant).getPublic().getEncoded()).subjectPublicKey();
      SecretWithEncap encap = CRYPTO.encapsulateKey(variant, pk);
      Assert.assertEquals(32, encap.secret().length);

      byte[] seed = new byte[64];
      CRYPTO.getSecureRandom().nextBytes(seed);
      byte[] shortCt = new byte[encap.encap().length - 1];
      try {
        CRYPTO.decapsulateKey(variant, seed, shortCt);
        Assert.fail(variant + ": invalid ciphertext length accepted");
      } catch (IllegalArgumentException e) {
        // expected: the GeneralSecurityException of the JDK
        Assert.assertTrue(variant + ": " + e, e.getCause() instanceof GeneralSecurityException);
      }
    }
  }

}
