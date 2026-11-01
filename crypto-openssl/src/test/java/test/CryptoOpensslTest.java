// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.test.CryptoApiConformance;
import org.xipki.crypto.openssl.OpensslCryptoApi;
import org.xipki.crypto.openssl.OpenSsl;
import org.xipki.crypto.openssl.OpensslProvider;

/**
 * Conformance tests of the OpenSSL backend. Skipped if libcrypto of OpenSSL 3.5+ is not
 * available.
 *
 * @author Lijun Liao (xipki)
 */
public class CryptoOpensslTest extends CryptoApiConformance {

  private static CryptoApi cryptoApi;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    cryptoApi = new OpensslTestBackend();
  }

  @Override
  protected CryptoApi crypto() {
    return cryptoApi;
  }

  /** ML-DSA of OpenSSL, without the internals of the JDK. */
  @Override
  protected boolean supportsMldsaContext() {
    return true;
  }

  /** The provider fips may lack ML-DSA, see {@link OpensslProvider}. */
  @Override
  protected boolean supportsMldsa() {
    return hasService("Signature", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87");
  }

  @Override
  protected boolean supportsMlkem() {
    return hasService("KeyPairGenerator", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024");
  }

  @Override
  protected boolean supportsEdDsa() {
    return hasService("Signature", "Ed25519", "Ed448");
  }

  // The tests below use algorithms or parameters which are not approved (default configuration
  // of the provider fips: e.g. hmac-key-check, pbkdf2-lower-bound-check, tdes-encrypt-disabled,
  // rsa-pkcs15-pad-disabled, signature-digest-check). OpensslFipsTest covers the FIPS mode.

  @Override
  @Test
  public void testMac() throws Exception {
    assumeNotFips();
    super.testMac();
  }

  @Override
  @Test
  public void testPbkdf2() throws Exception {
    assumeNotFips();
    super.testPbkdf2();
  }

  @Override
  @Test
  public void testDesedeCipher() throws Exception {
    assumeNotFips();
    super.testDesedeCipher();
  }

  @Override
  @Test
  public void testRsa() throws Exception {
    assumeNotFips();
    super.testRsa();
  }

  @Override
  @Test
  public void testSm3() throws Exception {
    assumeNotFips();
    super.testSm3();
  }

  @Override
  @Test
  public void testEcCurves() throws Exception {
    assumeNotFips();
    super.testEcCurves();
  }

  @Override
  @Test
  public void testEcdsaWithShake() throws Exception {
    assumeNotFips();
    super.testEcdsaWithShake();
  }

  @Override
  @Test
  public void testRsaPssWithShake() throws Exception {
    assumeNotFips();
    super.testRsaPssWithShake();
  }

  @Override
  @Test
  public void testX25519() {
    assumeNotFips();
    super.testX25519();
  }

  @Override
  @Test
  public void testX448() {
    assumeNotFips();
    super.testX448();
  }

  @Override
  @Test
  public void testXdhKeyAgreement() throws Exception {
    assumeNotFips();
    super.testXdhKeyAgreement();
  }

  private static void assumeNotFips() {
    Assume.assumeFalse("FIPS mode", OpenSsl.isFipsEnabled());
  }

  private static boolean hasService(String type, String... algorithms) {
    for (String algorithm : algorithms) {
      if (OpensslCryptoApi.provider().getService(type, algorithm) == null) {
        return false;
      }
    }
    return true;
  }

}
