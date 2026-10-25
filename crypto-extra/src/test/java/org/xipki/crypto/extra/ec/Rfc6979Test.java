// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.crypto.Digest;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECPrivateKeySpec;

/**
 * Tests the deterministic ECDSA (RFC 6979) of {@link XiECDSASignatureSpi}: the vectors of
 * RFC 6979 A.2.5, and the deterministic signatures of BouncyCastle on several curves and hashes
 * (the curve P-521 tests the bit shift of bits2int).
 *
 * @author Lijun Liao (xipki)
 */
public class Rfc6979Test {

  private static final Provider XI = new XiPKIProvider();

  private static final SecureRandom RND = new SecureRandom();

  @Test
  public void testRfc6979VectorsP256() throws Exception {
    // RFC 6979, A.2.5, ECDSA, 256 Bits (Prime Field), with SHA-256
    BigInteger x = new BigInteger(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16);
    assertSignature("secp256r1", x, "sample",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    assertSignature("secp256r1", x, "test",
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");
  }

  @Test
  public void testAgainstBouncyCastle() throws Exception {
    String[][] cases = {
        {"secp256r1", "SHA-1"}, {"secp256r1", "SHA-256"}, {"secp256r1", "SHA-512"},
        {"secp384r1", "SHA-256"}, {"secp384r1", "SHA-512"},
        {"secp521r1", "SHA-1"}, {"secp521r1", "SHA-256"}, {"secp521r1", "SHA-512"},
        {"brainpoolP256r1", "SHA-256"}, {"brainpoolP512r1", "SHA-512"}};
    for (String[] c : cases) {
      X9ECParameters bcParams = c[0].startsWith("brainpool")
          ? TeleTrusTNamedCurves.getByName(c[0])
          : NISTNamedCurves.getByName(nistName(c[0]));
      ECDomainParameters dom = new ECDomainParameters(bcParams);
      for (int i = 0; i < 20; i++) {
        BigInteger x = new BigInteger(dom.getN().bitLength() + 8, RND).mod(dom.getN());
        if (x.signum() == 0) {
          continue;
        }
        byte[] msg = new byte[1 + RND.nextInt(100)];
        RND.nextBytes(msg);

        ECDSASigner bc = new ECDSASigner(new HMacDSAKCalculator(bcDigest(c[1])));
        bc.init(true, new ECPrivateKeyParameters(x, dom));
        BigInteger[] rs = bc.generateSignature(MessageDigest.getInstance(c[1]).digest(msg));

        DssSigValue sig = DssSigValue.fromEncoded(sign(c[0], x, c[1], msg));
        String desc = c[0] + " " + c[1];
        Assert.assertEquals(desc, rs[0], sig.r());
        Assert.assertEquals(desc, rs[1], sig.s());
      }
    }
  }

  @Test
  public void testLeftmostBits() {
    for (int qlen : new int[] {160, 255, 256, 384, 521, 523}) {
      int rlen = (qlen + 7) / 8;
      for (int tlen : new int[] {rlen, rlen + 1, 64, 96}) {
        if (tlen * 8 < qlen) {
          continue;
        }
        for (int i = 0; i < 50; i++) {
          byte[] t = new byte[tlen];
          RND.nextBytes(t);
          byte[] expected = fixed(XiECDSASignatureSpi.Rfc6979KGenerator.bits2int(t, qlen), rlen);
          Assert.assertArrayEquals(qlen + "/" + tlen, expected,
              XiECDSASignatureSpi.Rfc6979KGenerator.leftmostBits(t, qlen, rlen));
        }
      }
    }
  }

  private static void assertSignature(String curve, BigInteger x, String msg, String r, String s)
      throws Exception {
    DssSigValue sig = DssSigValue.fromEncoded(
        sign(curve, x, "SHA-256", msg.getBytes(StandardCharsets.US_ASCII)));
    Assert.assertEquals(msg, new BigInteger(r, 16), sig.r());
    Assert.assertEquals(msg, new BigInteger(s, 16), sig.s());
  }

  private static byte[] sign(String curve, BigInteger x, String hash, byte[] msg)
      throws Exception {
    PrivateKey sk = KeyFactory.getInstance("EC", XI).generatePrivate(
        new ECPrivateKeySpec(x, EcCurve.ofName(curve).parameterSpec()));
    Signature signer = Signature.getInstance(hash.replace("-", "") + "WITHECDSA", XI);
    // no SecureRandom: deterministic, without additional data
    signer.initSign(sk);
    signer.update(msg);
    return signer.sign();
  }

  private static Digest bcDigest(String hash) {
    switch (hash) {
      case "SHA-1":
        return new SHA1Digest();
      case "SHA-256":
        return new SHA256Digest();
      default:
        return new SHA512Digest();
    }
  }

  private static String nistName(String secName) {
    switch (secName) {
      case "secp256r1":
        return "P-256";
      case "secp384r1":
        return "P-384";
      default:
        return "P-521";
    }
  }

  private static byte[] fixed(BigInteger v, int len) {
    byte[] b = v.toByteArray();
    byte[] r = new byte[len];
    int n = Math.min(b.length, len);
    System.arraycopy(b, b.length - n, r, len - n, n);
    return r;
  }

}
