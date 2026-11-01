// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.crypto.openssl.OpensslCryptoApi;
import org.xipki.crypto.openssl.OpenSsl;
import org.xipki.crypto.openssl.OpensslProvider;

import java.security.Provider;

/**
 * Tests of the services registered by {@link OpensslProvider}. Skipped if libcrypto of
 * OpenSSL 3.5+ is not available.
 *
 * @author Lijun Liao (xipki)
 */
public class OpensslProviderTest {

  private static final String[][] NON_FIPS = {
      {"MessageDigest", "SM3"}, {"Mac", "HmacSM3"}, {"Signature", "SM3WITHSM2"},
      {"KeyGenerator", "HmacSM3"}, {"SecretKeyFactory", "PBKDF2WithHmacSM3"},
      {"Signature", "SHAKE128WITHRSAPSS"}, {"Signature", "SHAKE256WITHRSAPSS"}};

  private static final String[][] COMMON = {
      {"MessageDigest", "SHA-256"}, {"MessageDigest", "SHA3-512"},
      {"MessageDigest", "SHAKE256-512"},
      {"Mac", "HmacSHA256"}, {"Mac", "AES-GMAC"},
      {"Signature", "SHA256WITHRSA"}, {"Signature", "SHA256WITHRSAANDMGF1"},
      {"Signature", "RSASSA-PSS"}, {"Signature", "SHA256WITHECDSA"},
      {"Signature", "SHAKE256WITHECDSA"},
      {"Signature", "EdDSA"}, {"Signature", "Ed25519"}, {"Signature", "Ed448"},
      {"Signature", "ML-DSA"}, {"Signature", "ML-DSA-44"}, {"Signature", "ML-DSA-87"},
      {"Cipher", "AES/CBC/PKCS5Padding"}, {"Cipher", "AES/ECB/NoPadding"},
      {"Cipher", "AES/CTR/NoPadding"}, {"Cipher", "AES/GCM/NoPadding"},
      {"Cipher", "AESWrap"}, {"Cipher", "AESWrapPad"},
      {"Cipher", "RSA/ECB/PKCS1Padding"}, {"Cipher", "RSA/ECB/OAEPPadding"},
      {"Cipher", "RSA/ECB/NoPadding"},
      {"KeyFactory", "RSA"}, {"KeyFactory", "RSASSA-PSS"}, {"KeyFactory", "EC"},
      {"KeyPairGenerator", "EC"}, {"KeyPairGenerator", "Ed25519"},
      {"KeyPairGenerator", "X25519"}, {"KeyPairGenerator", "X448"},
      {"KeyPairGenerator", "ML-DSA-65"}, {"KeyPairGenerator", "ML-KEM-768"},
      {"KeyFactory", "ML-KEM"},
      {"KeyAgreement", "ECDH"}, {"KeyAgreement", "XDH"}, {"KeyAgreement", "X25519"},
      {"KeyAgreement", "X448"},
      {"KeyGenerator", "AES"}, {"KeyGenerator", "HmacSHA256"},
      {"SecretKeyFactory", "PBKDF2WithHmacSHA256"},
      {"SecureRandom", OpensslProvider.SECURE_RANDOM}};

  private static Provider provider;

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    provider = OpensslCryptoApi.provider();
  }

  /** Not in the FIPS mode: all services are registered, i.e. the probes are correct. */
  @Test
  public void testAllServices() {
    Assume.assumeFalse("FIPS mode", OpenSsl.isFipsEnabled());
    for (String[][] list : new String[][][]{COMMON, NON_FIPS}) {
      for (String[] s : list) {
        Assert.assertNotNull(s[0] + " " + s[1], provider.getService(s[0], s[1]));
      }
    }
  }

  /** In the FIPS mode: the non-FIPS services are absent. */
  @Test
  public void testFipsServices() {
    Assume.assumeTrue("not in FIPS mode", OpenSsl.isFipsEnabled());
    for (String[] s : NON_FIPS) {
      Assert.assertNull(s[0] + " " + s[1], provider.getService(s[0], s[1]));
    }
  }

}
