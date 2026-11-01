// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiCrossTest;
import org.xipki.crypto.bcfips.CryptoBcFips;
import org.xipki.crypto.jdk.CryptoJdk;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Cross tests of the BouncyCastle FIPS backend with the JDK backend (crypto-be-jdk), in the
 * approved-only mode of BC-FIPS. The tests of the base class with operations that are not
 * approved are replaced by their approved part.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoJdkCrossTest extends CryptoApiCrossTest {

  private static final CryptoApi backend = new CryptoBcFips();

  private static final CryptoApi reference = new CryptoJdk();

  @Override
  protected CryptoApi backend() {
    return backend;
  }

  @Override
  protected CryptoApi reference() {
    return reference;
  }

  @Override
  protected Set<String> backendProviders() {
    return new HashSet<>(Arrays.asList("BCFIPS", "BCPQC"));
  }

  /** SM3 and SM3withSM2: not offered by the BC-FIPS backend. */
  @Override
  protected boolean supportsSm() {
    return false;
  }

  /** SHAKE128/256withRSAPSS: not offered by the BC-FIPS backend. */
  @Override
  protected boolean supportsRsaPssShake() {
    return false;
  }

  /** SHAKE128/256withECDSA: not offered by the BC-FIPS backend. */
  @Override
  protected boolean supportsEcdsaShake() {
    return false;
  }

  /**
   * crypto-be-jdk: supported with the JVM option
   * --add-exports java.base/sun.security.provider=ALL-UNNAMED.
   */
  @Override
  protected boolean supportsMldsaContext() {
    return Object.class.getModule().isExported("sun.security.provider",
        CryptoJdk.class.getModule());
  }

  /** X25519 and X448 are not approved. */
  @Override
  protected boolean supportsXdh() {
    return false;
  }

  /** PBKDF2 with a password of at least 112 bits (14 characters). */
  @Override
  @Test
  public void testKdfs() throws Exception {
    byte[] ikm = new byte[32];
    byte[] salt = new byte[16];
    rnd().nextBytes(ikm);
    rnd().nextBytes(salt);
    byte[] info = "info".getBytes(StandardCharsets.US_ASCII);
    for (int len : new int[]{16, 32, 100}) {
      Assert.assertArrayEquals("HKDF " + len, backend.hkdfSha256Derive(ikm, salt, info, len),
          reference.hkdfSha256Derive(ikm, salt, info, len));
    }

    char[] password = "passwordPASSWORDpassword".toCharArray();
    for (String hmac : new String[]{"HmacSHA1", "HmacSHA256", "HmacSHA512"}) {
      Assert.assertArrayEquals("PBKDF2 " + hmac, backend.pbkdf2(hmac, password, salt, 1000, 32),
          reference.pbkdf2(hmac, password, salt, 1000, 32));
    }
  }

  /** Without SHA1WITHRSAANDMGF1: BC-FIPS does not sign with SHA-1. */
  @Override
  @Test
  public void testRsaSignatures() throws Exception {
    for (CryptoApi keyGen : new CryptoApi[]{backend, reference}) {
      KeyPairGenerator kpGen = keyGen.newKeyPairGenerator("RSA");
      kpGen.initialize(2048, rnd());
      KeyPair kp = kpGen.generateKeyPair();
      for (String alg : new String[]{"SHA256WITHRSA", "SHA512WITHRSA", "SHA3-256WITHRSA",
          "SHA256WITHRSAANDMGF1", "SHA512WITHRSAANDMGF1", "SHA3-256WITHRSAANDMGF1"}) {
        assertCrossSignVerify(alg, kp, keyGen);
      }
    }
  }

}
