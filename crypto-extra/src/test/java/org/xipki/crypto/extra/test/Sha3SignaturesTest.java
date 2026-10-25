// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.crypto.extra.Primitives;
import org.xipki.crypto.extra.XiPKIProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

/**
 * Tests HmacSHA3-*, SHA3-*withRSA, RSASSA-PSS and the deterministic SHA3-ECDSA of
 * {@link XiPKIProvider} against BouncyCastle. These are used by crypto-be-jdk on JDK 11 to 15; the
 * tests use the provider directly, so they run on every JDK.
 *
 * @author Lijun Liao (xipki)
 */
public class Sha3SignaturesTest {

  private static final SecureRandom RND = new SecureRandom();

  private static final Provider XI = new XiPKIProvider();

  private static final Provider BC = new BouncyCastleProvider();

  /** primitives without HmacSHA3: only the SHA3 digests of the provider SUN. */
  private static final Primitives SUN_ONLY = new Primitives(Security.getProvider("SUN"));

  private static final String[] SHA3 = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};

  private static final int[] BLOCK_SIZES = {144, 136, 104, 72};

  @Test
  public void testHmacSha3() throws Exception {
    for (int i = 0; i < SHA3.length; i++) {
      String alg = "Hmac" + SHA3[i];
      int bs = BLOCK_SIZES[i];
      Mac xi = Mac.getInstance(alg, XI);
      Mac bc = Mac.getInstance(alg, BC);
      Mac fallback = SUN_ONLY.mac(alg);
      // key lengths below, equal to and above the block size
      for (int keyLen : new int[] {1, 32, bs - 1, bs, bs + 1, 2 * bs + 7}) {
        byte[] key = new byte[keyLen];
        RND.nextBytes(key);
        byte[] msg = new byte[RND.nextInt(300)];
        RND.nextBytes(msg);
        SecretKeySpec k = new SecretKeySpec(key, alg);
        bc.init(k);
        byte[] expected = bc.doFinal(msg);
        String desc = alg + ", key length " + keyLen;

        xi.init(k);
        Assert.assertArrayEquals(desc, expected, xi.doFinal(msg));
        // the same key again, after doFinal
        xi.update(msg, 0, msg.length);
        Assert.assertArrayEquals(desc + " (2nd)", expected, xi.doFinal());

        fallback.init(k);
        Assert.assertArrayEquals(desc + " (Primitives fallback)", expected,
            fallback.doFinal(msg));
      }
    }
  }

  @Test
  public void testHmacSha3Clone() throws Exception {
    Mac mac = SUN_ONLY.mac("HmacSHA3-256");
    mac.init(new SecretKeySpec(new byte[] {1, 2, 3}, "HmacSHA3-256"));
    mac.update("prefix".getBytes(StandardCharsets.US_ASCII));
    Mac copy = (Mac) mac.clone();
    byte[] a = mac.doFinal("A".getBytes(StandardCharsets.US_ASCII));
    byte[] b = copy.doFinal("B".getBytes(StandardCharsets.US_ASCII));
    Assert.assertFalse(Arrays.equals(a, b));

    Mac bc = Mac.getInstance("HmacSHA3-256", BC);
    bc.init(new SecretKeySpec(new byte[] {1, 2, 3}, "HmacSHA3-256"));
    Assert.assertArrayEquals(bc.doFinal("prefixB".getBytes(StandardCharsets.US_ASCII)), b);
  }

  @Test
  public void testPrimitivesFallbackOnlyForHmacSha3() {
    try {
      SUN_ONLY.mac("HmacSHA256");
      Assert.fail("HmacSHA256 is not in SUN");
    } catch (NoSuchAlgorithmException e) {
      // expected
    }
  }

  @Test
  public void testSha3WithRsa() throws Exception {
    for (int bits : new int[] {2048, 2047, 3072}) {
      // the RSA key generator of the JDK (BouncyCastle does not generate an odd bit length)
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
      kpGen.initialize(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4), RND);
      KeyPair kp = kpGen.generateKeyPair();
      for (String hash : SHA3) {
        String alg = hash + "WITHRSA";
        String desc = alg + ", " + bits + " bits";
        byte[] msg = new byte[1 + RND.nextInt(200)];
        RND.nextBytes(msg);

        // PKCS#1 v1.5 is deterministic: equal to BouncyCastle
        byte[] sig = sign(XI, alg, kp, msg);
        Assert.assertArrayEquals(desc, sign(BC, alg, kp, msg), sig);
        Assert.assertTrue(desc, verify(XI, alg, kp, msg, sig));

        byte[] modified = sig.clone();
        modified[modified.length / 2] ^= 1;
        Assert.assertFalse(desc + " modified", verify(XI, alg, kp, msg, modified));
        Assert.assertFalse(desc + " short", verify(XI, alg, kp, msg,
            Arrays.copyOf(sig, sig.length - 1)));
        Assert.assertFalse(desc + " other message", verify(XI, alg, kp, new byte[] {1}, sig));
      }
    }
  }

  /**
   * A DigestInfo with absent parameters (instead of NULL) is rejected, as by the JDK.
   */
  @Test
  public void testSha3WithRsaAbsentParameters() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(2048, RND);
    KeyPair kp = kpGen.generateKeyPair();
    byte[] msg = "message".getBytes(StandardCharsets.US_ASCII);
    byte[] hash = MessageDigest.getInstance("SHA3-256", BC).digest(msg);

    // DigestInfo ::= SEQUENCE { SEQUENCE { OID sha3-256 }, OCTET STRING hash }
    byte[] prefix = {0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x08, 0x04, 0x20};
    byte[] digestInfo = new byte[prefix.length + hash.length];
    System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
    System.arraycopy(hash, 0, digestInfo, prefix.length, hash.length);
    Signature raw = Signature.getInstance("NONEwithRSA", BC);
    raw.initSign(kp.getPrivate());
    raw.update(digestInfo);
    byte[] sig = raw.sign();
    Assert.assertFalse(verify(XI, "SHA3-256WITHRSA", kp, msg, sig));
  }

  @Test
  public void testRsaPss() throws Exception {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(3072, RND);
    KeyPair kp = kpGen.generateKeyPair();
    byte[] msg = "message to be signed".getBytes(StandardCharsets.US_ASCII);
    for (String hash : new String[] {"SHA3-256", "SHA3-512", "SHA-256"}) {
      for (int saltLen : new int[] {0, 32, 64}) {
        PSSParameterSpec spec = new PSSParameterSpec(hash, "MGF1",
            new MGF1ParameterSpec(hash), saltLen, 1);
        String desc = hash + ", salt " + saltLen;

        byte[] sig = signPss(XI, spec, kp, msg);
        Assert.assertTrue(desc + ": BouncyCastle verifies", verifyPss(BC, spec, kp, msg, sig));
        Assert.assertTrue(desc, verifyPss(XI, spec, kp, msg, sig));
        sig = signPss(BC, spec, kp, msg);
        Assert.assertTrue(desc + ": verifies BouncyCastle", verifyPss(XI, spec, kp, msg, sig));

        byte[] modified = sig.clone();
        modified[3] ^= 1;
        Assert.assertFalse(desc + " modified", verifyPss(XI, spec, kp, msg, modified));
      }
    }

    // MGF1 with another hash than the message: not supported (decision 3)
    Signature sig = Signature.getInstance("RSASSA-PSS", XI);
    try {
      sig.setParameter(new PSSParameterSpec("SHA3-256", "MGF1", MGF1ParameterSpec.SHA256, 32,
          1));
      Assert.fail("MGF1 with another hash accepted");
    } catch (InvalidAlgorithmParameterException e) {
      // expected
    }
  }

  /**
   * ECDSA with SHA3 and the deterministic nonce of RFC 6979, with the HmacSHA3 of the
   * {@link Primitives} fallback (no provider of the primitives has HmacSHA3): equal to the
   * deterministic ECDSA of BouncyCastle.
   */
  @Test
  public void testDeterministicSha3Ecdsa() throws Exception {
    Provider xiSunOnly = new XiPKIProvider(SUN_ONLY);
    for (String curve : new String[] {"secp256r1", "secp384r1", "secp521r1",
        "brainpoolP256r1"}) {
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", BC);
      kpGen.initialize(new ECGenParameterSpec(curve), RND);
      KeyPair kp = kpGen.generateKeyPair();
      for (String hash : SHA3) {
        byte[] msg = new byte[1 + RND.nextInt(100)];
        RND.nextBytes(msg);
        String desc = curve + " " + hash;
        byte[] sig = signDeterministic(xiSunOnly, hash + "WITHECDSA", kp, msg);
        Assert.assertArrayEquals(desc, signDeterministic(BC, hash + "WITHECDDSA", kp, msg),
            sig);
        Assert.assertTrue(desc, verify(BC, hash + "WITHECDSA", kp, msg, sig));
      }
    }
  }

  private static byte[] sign(Provider p, String alg, KeyPair kp, byte[] msg) throws Exception {
    Signature s = Signature.getInstance(alg, p);
    s.initSign(kp.getPrivate(), RND);
    s.update(msg);
    return s.sign();
  }

  private static byte[] signDeterministic(Provider p, String alg, KeyPair kp, byte[] msg)
      throws Exception {
    Signature s = Signature.getInstance(alg, p);
    s.initSign(kp.getPrivate());
    s.update(msg);
    return s.sign();
  }

  private static boolean verify(Provider p, String alg, KeyPair kp, byte[] msg, byte[] sig)
      throws Exception {
    Signature s = Signature.getInstance(alg, p);
    s.initVerify(kp.getPublic());
    s.update(msg);
    return s.verify(sig);
  }

  private static byte[] signPss(Provider p, PSSParameterSpec spec, KeyPair kp, byte[] msg)
      throws Exception {
    Signature s = Signature.getInstance("RSASSA-PSS", p);
    s.setParameter(spec);
    s.initSign(kp.getPrivate(), RND);
    s.update(msg);
    return s.sign();
  }

  private static boolean verifyPss(Provider p, PSSParameterSpec spec, KeyPair kp, byte[] msg,
      byte[] sig) throws Exception {
    Signature s = Signature.getInstance("RSASSA-PSS", p);
    s.setParameter(spec);
    s.initVerify(kp.getPublic());
    s.update(msg);
    return s.verify(sig);
  }

}
