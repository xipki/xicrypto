// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.test;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.json.JsonParser;
import org.xipki.crypto.extra.XiPKIProvider;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Verifies the Wycheproof ECDSA test vectors with the ECDSA of the XiPKI provider.
 *
 * @author Lijun Liao (xipki)
 */
public class WycheproofEcdsaTest {

  private static Provider xipki;

  @BeforeClass
  public static void init() {

    xipki = new XiPKIProvider();
  }

  @Test
  public void testBrainpoolP256r1Sha256() throws Exception {
    run("ecdsa_brainpoolP256r1_sha256_test.json");
  }

  @Test
  public void testBrainpoolP384r1Sha384() throws Exception {
    run("ecdsa_brainpoolP384r1_sha384_test.json");
  }

  @Test
  public void testBrainpoolP512r1Sha512() throws Exception {
    run("ecdsa_brainpoolP512r1_sha512_test.json");
  }

  @Test
  public void testSecp256r1Sha256() throws Exception {
    run("ecdsa_secp256r1_sha256_test.json");
  }

  @Test
  public void testSecp256r1Sha3_256() throws Exception {
    run("ecdsa_secp256r1_sha3_256_test.json");
  }

  @Test
  public void testSecp256r1Shake128() throws Exception {
    run("ecdsa_secp256r1_shake128_test.json");
  }

  @Test
  public void testSecp384r1Shake256() throws Exception {
    run("ecdsa_secp384r1_shake256_test.json");
  }

  private static void run(String fileName) throws Exception {
    JsonMap root;
    try (InputStream is = WycheproofEcdsaTest.class.getResourceAsStream(
        "/wycheproof/" + fileName)) {
      Assert.assertNotNull("missing resource " + fileName, is);
      root = JsonParser.parseMap(is, false);
    }

    KeyFactory kf = KeyFactory.getInstance("EC", xipki);
    List<String> failures = new ArrayList<>();
    int count = 0;

    for (JsonMap group : root.getList("testGroups").toMapList()) {
      PublicKey pk = kf.generatePublic(
          new X509EncodedKeySpec(Hex.decode(group.getNnString("publicKeyDer"))));
      String sigAlg = sigAlgName(group.getNnString("sha"));

      for (JsonMap t : group.getList("tests").toMapList()) {
        count++;
        boolean expected = "valid".equals(t.getNnString("result"));
        boolean actual;
        try {
          Signature sig = Signature.getInstance(sigAlg, xipki);
          sig.initVerify(pk);
          sig.update(Hex.decode(t.getNnString("msg")));
          actual = sig.verify(Hex.decode(t.getNnString("sig")));
        } catch (Exception e) {
          actual = false;
        }

        if (actual != expected) {
          failures.add("tcId " + t.getNnObject("tcId") + ": expected " + expected);
        }
      }
    }

    Assert.assertTrue(fileName + ": no tests", count > 100);
    Assert.assertTrue(fileName + ": " + failures.size() + " of " + count + " failed: "
        + failures, failures.isEmpty());
  }

  private static String sigAlgName(String sha) {
    switch (sha) {
      case "SHA-256":
        return "SHA256WITHECDSA";
      case "SHA-384":
        return "SHA384WITHECDSA";
      case "SHA-512":
        return "SHA512WITHECDSA";
      case "SHA3-256":
        return "SHA3-256WITHECDSA";
      case "SHAKE128":
        return "SHAKE128WITHECDSA";
      case "SHAKE256":
        return "SHAKE256WITHECDSA";
      default:
        throw new IllegalArgumentException("unsupported hash " + sha);
    }
  }

}
