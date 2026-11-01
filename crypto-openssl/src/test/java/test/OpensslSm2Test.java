// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.jdk.CryptoJdk;
import org.xipki.crypto.openssl.OpenSsl;
import org.xipki.crypto.openssl.OpensslProvider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * SM3 and SM3withSM2 of OpenSSL, against those of crypto-be-jdk (xicrypto) and the test vectors
 * of the OpenSSL command line.
 *
 * @author Lijun Liao (xipki)
 */
public class OpensslSm2Test {

  private static final byte[] MSG = "SM2 test message".getBytes(StandardCharsets.UTF_8);

  private static CryptoApi openssl;

  private static final CryptoApi jdk = new CryptoJdk();

  @BeforeClass
  public static void init() {
    Assume.assumeTrue("OpenSSL not available: " + OpenSsl.unavailableReason(),
        OpenSsl.isAvailable());
    Assume.assumeFalse("no SM2 in the FIPS mode", OpenSsl.isFipsEnabled());
    openssl = new OpensslTestBackend();
  }

  @Test
  public void testProvider() throws Exception {
    Assert.assertEquals(OpensslProvider.NAME,
        openssl.newMessageDigest("SM3").getProvider().getName());
    Assert.assertEquals(OpensslProvider.NAME,
        openssl.newSignature("SM3WITHSM2").getProvider().getName());
    // by OID
    Assert.assertEquals(OpensslProvider.NAME,
        openssl.newSignature("1.2.156.10197.1.501").getProvider().getName());
    Assert.assertEquals(OpensslProvider.NAME,
        openssl.newMessageDigest("SHA-256").getProvider().getName());
  }

  @Test
  public void testSm3() throws Exception {
    byte[] data = new byte[200_000];
    new Random(1).nextBytes(data);
    MessageDigest md = openssl.newMessageDigest("SM3");
    MessageDigest ref = jdk.newMessageDigest("SM3");
    // larger than one chunk, with offset
    md.update(data, 3, data.length - 3);
    ref.update(data, 3, data.length - 3);
    Assert.assertArrayEquals(ref.digest(), md.digest());

    // byte-wise, and clone in between
    md.update((byte) 1);
    md.update((byte) 2);
    MessageDigest clone = (MessageDigest) md.clone();
    md.update((byte) 3);
    clone.update((byte) 3);
    ref.update(new byte[]{1, 2, 3});
    byte[] expected = ref.digest();
    Assert.assertArrayEquals(expected, md.digest());
    Assert.assertArrayEquals(expected, clone.digest());
  }

  @Test
  public void testCrossSignVerify() throws Exception {
    KeyPair kp = sm2KeyPair();

    // OpenSSL signs, xicrypto verifies, and vice versa
    byte[] sig = sign(openssl, kp.getPrivate(), MSG);
    Assert.assertTrue(verify(jdk, kp.getPublic(), MSG, sig));
    Assert.assertTrue(verify(openssl, kp.getPublic(), MSG, sig));

    sig = sign(jdk, kp.getPrivate(), MSG);
    Assert.assertTrue(verify(openssl, kp.getPublic(), MSG, sig));

    // wrong message, malformed signature
    Assert.assertFalse(verify(openssl, kp.getPublic(), "other".getBytes(), sig));
    Assert.assertFalse(verify(openssl, kp.getPublic(), MSG, new byte[]{0x30, 0x02, 0x01}));

    // the signature object is reusable
    Signature s = openssl.newSignature("SM3WITHSM2");
    s.initSign(kp.getPrivate());
    for (int i = 0; i < 3; i++) {
      s.update(MSG);
      Assert.assertTrue(verify(jdk, kp.getPublic(), MSG, s.sign()));
    }
  }

  @Test
  public void testOpensslTestVector() throws Exception {
    PublicKey pk = openssl.getPublicKey(SubjectPublicKeyInfo.fromEncoded(resource("sm2.spki")));
    Assert.assertTrue(verify(openssl, pk, resource("msg.bin"), resource("sm2-sm3.sig")));

    PrivateKey sk = openssl.getPrivateKey(PrivateKeyInfo.fromEncoded(resource("sm2.p8")));
    byte[] sig = sign(openssl, sk, resource("msg.bin"));
    Assert.assertTrue(verify(jdk, pk, resource("msg.bin"), sig));
  }

  @Test
  public void testWrongKeyType() throws Exception {
    KeyPairGenerator kpGen = openssl.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec("secp256r1"));
    Signature s = openssl.newSignature("SM3WITHSM2");
    Assert.assertThrows(InvalidKeyException.class,
        () -> s.initSign(kpGen.generateKeyPair().getPrivate()));
  }

  /** The cached key and its templates are shared by the threads. */
  @Test
  public void testConcurrent() throws Exception {
    KeyPair kp = sm2KeyPair();
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < 64; i++) {
        byte[] msg = ("message " + i).getBytes(StandardCharsets.UTF_8);
        results.add(pool.submit(() -> {
          byte[] sig = sign(openssl, kp.getPrivate(), msg);
          return verify(openssl, kp.getPublic(), msg, sig) && verify(jdk, kp.getPublic(), msg, sig);
        }));
      }
      for (Future<Boolean> r : results) {
        Assert.assertTrue(r.get());
      }
    } finally {
      pool.shutdownNow();
    }
  }

  private static KeyPair sm2KeyPair() throws Exception {
    KeyPairGenerator kpGen = openssl.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec("sm2p256v1"));
    return kpGen.generateKeyPair();
  }

  private static byte[] sign(CryptoApi crypto, PrivateKey key, byte[] msg) throws Exception {
    Signature s = crypto.newSignature("SM3WITHSM2");
    s.initSign(key);
    s.update(msg);
    return s.sign();
  }

  private static boolean verify(CryptoApi crypto, PublicKey key, byte[] msg, byte[] sig)
      throws Exception {
    Signature s = crypto.newSignature("SM3WITHSM2");
    s.initVerify(key);
    s.update(msg);
    return s.verify(sig);
  }

  private static byte[] resource(String name) throws IOException {
    try (InputStream is = OpensslSm2Test.class.getResourceAsStream("/ec-openssl/" + name)) {
      return is.readAllBytes();
    }
  }

}
