// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.crypto.extra.Primitives;
import org.xipki.crypto.extra.XiSignatureSpi;
import org.xipki.crypto.extra.ec.math.EcCurve;
import org.xipki.crypto.extra.ec.math.ModN;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * ECDSA (SEC 1, FIPS 186-5) for the named curves of {@link EcCurve}, with the signature
 * encoded as DER SEQUENCE { r INTEGER, s INTEGER }.
 * <ul>
 *   <li>The nonce k is derived as in RFC 6979. If the key is initialized with a
 *       {@link SecureRandom}, fresh random bytes are added as k' (RFC 6979, section 3.6,
 *       hedged signatures); otherwise the signature is deterministic.</li>
 *   <li>k·G uses the constant-time ladder of {@link EcCurve}. The modular arithmetic with the
 *       private key is blinded with a random factor: s = (k·b)^-1 · (b·e + b·r·d) mod n.</li>
 *   <li>The verification accepts only DER encoded signatures with r, s in [1, n-1].</li>
 * </ul>
 *
 * @author Lijun Liao (xipki)
 */
public class XiECDSASignatureSpi extends XiSignatureSpi {

  private static final SecureRandom BLINDING_RANDOM = new SecureRandom();

  private final Primitives primitives;

  private final String macAlg;

  /** the HMAC of RFC 6979, created when first needed: verification does not need it. */
  private Mac mac;

  private XiECPrivateKey sk;

  private XiECPublicKey pk;

  /**
   * Constructor.
   * @param primitives the source of the HMAC.
   * @param digest the hash of the message, e.g. SHA-256 or SHAKE128 with 32 bytes output.
   * @param macAlg the JCA name of the HMAC for RFC 6979.
   */
  public XiECDSASignatureSpi(Primitives primitives, MessageDigest digest, String macAlg) {
    super(digest);
    this.primitives = primitives;
    this.macAlg = macAlg;
  }

  private Mac mac() {
    if (mac == null) {
      try {
        mac = primitives.mac(macAlg);
      } catch (GeneralSecurityException e) {
        throw new ProviderException("unsupported HMAC " + macAlg
            + " (needed for the nonce of RFC 6979)", e);
      }
    }
    return mac;
  }

  @Override
  protected void initVerify(PublicKey publicKey) throws InvalidKeyException {
    this.pk = EcKeys.toXiPublicKey(publicKey);
    this.sk = null;
  }

  @Override
  protected void initSign(PrivateKey privateKey) throws InvalidKeyException {
    // fails here, not only in sign(), if the HMAC is not available
    mac();
    this.sk = EcKeys.toXiPrivateKey(privateKey);
    this.pk = null;
  }

  @Override
  protected byte[] sign(byte[] hash) {
    EcCurve curve = sk.curve();
    ModN modN = curve.scalarField();
    BigInteger n = curve.order();
    // the hash is public
    ModN.Element e = modN.fromBigInteger(Rfc6979KGenerator.bits2int(hash, n.bitLength()));
    // JCA boundary: the private key is a BigInteger
    ModN.Element d = modN.fromBigInteger(sk.getS());

    byte[] extra = null;
    if (random != null) {
      extra = new byte[modN.byteLength()];
      random.nextBytes(extra);
    }

    // the secret values are handled as ModN elements and fixed-length bytes only
    Rfc6979KGenerator kGen = new Rfc6979KGenerator(mac(), modN, modN.toBytes(d), hash, extra);
    while (true) {
      byte[] kBytes = kGen.nextK();
      ModN.Element k = modN.fromBytes(kBytes);
      Arrays.fill(kBytes, (byte) 0);

      ECPoint kG = curve.multiplyG(k);
      // r is public
      BigInteger r = kG.getAffineX().mod(n);
      if (r.signum() == 0) {
        continue;
      }

      // s = k^-1 (e + r d) = (k b)^-1 (b e + b r d), blinded with a random b
      ModN.Element b = modN.random(BLINDING_RANDOM);
      ModN.Element kbInv = modN.inv(modN.mul(k, b));
      ModN.Element t = modN.add(modN.mul(b, e),
          modN.mul(modN.mul(b, modN.fromBigInteger(r)), d));
      ModN.Element s = modN.mul(kbInv, t);
      if (modN.isZero(s)) {
        continue;
      }

      return new DssSigValue(r, modN.toBigInteger(s)).getEncoded();
    }
  }

  @Override
  protected boolean verify(byte[] hash, byte[] sigBytes) {
    DssSigValue sigValue = EcKeys.decodeSignature(sigBytes);
    if (sigValue == null) {
      return false;
    }

    EcCurve curve = pk.curve();
    BigInteger n = curve.order();
    BigInteger r = sigValue.r();
    BigInteger s = sigValue.s();
    if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0) {
      return false;
    }

    BigInteger e = Rfc6979KGenerator.bits2int(hash, n.bitLength());
    BigInteger w = s.modInverse(n);
    BigInteger u1 = e.multiply(w).mod(n);
    BigInteger u2 = r.multiply(w).mod(n);

    ECPoint x = curve.sumOfTwoMultiplies(u1, u2, pk.getW());
    if (ECPoint.POINT_INFINITY.equals(x)) {
      return false;
    }
    return x.getAffineX().mod(n).equals(r);
  }

  /**
   * Generator of the ECDSA nonce k as in RFC 6979, section 3.2, with optional additional data
   * k' (section 3.6) for hedged signatures. Successive calls of {@link #nextK()} return the
   * candidates of step h.3 (for the case that k or the signature is rejected).
   * <p>
   * The private key and the nonce are handled as fixed-length byte arrays only (no
   * {@link BigInteger}), and the range check of the candidates is constant-time.
   *
   * @author Lijun Liao (xipki)
   */
  static final class Rfc6979KGenerator {

    private final Mac mac;

    private final String macAlg;

    private final ModN modN;

    private final int qlen;

    private final int rlen;

    private byte[] k;

    private byte[] v;

    private boolean first = true;

    /**
     * Constructor.
     * @param mac the HMAC, e.g. HmacSHA256, of the hash of the signature.
     * @param modN the arithmetic modulo the order n of the base point.
     * @param xOctets the private key as int2octets(x), i.e. {@link ModN#toBytes} of x. It is
     *                cleared by this constructor.
     * @param h1 the hash of the message.
     * @param extra additional data k' (e.g. random bytes), or null.
     */
    Rfc6979KGenerator(Mac mac, ModN modN, byte[] xOctets, byte[] h1, byte[] extra) {
      this.mac = mac;
      this.macAlg = mac.getAlgorithm();
      this.modN = modN;
      BigInteger n = modN.modulus();
      this.qlen = n.bitLength();
      this.rlen = modN.byteLength();
      if (xOctets.length != rlen) {
        throw new IllegalArgumentException("invalid length of the private key");
      }

      int hlen = mac.getMacLength();

      // the hash is public
      byte[] hOctets = int2octets(bits2int(h1, qlen));
      byte[] extraBytes = (extra == null) ? new byte[0] : extra;

      v = new byte[hlen];
      Arrays.fill(v, (byte) 0x01);
      k = new byte[hlen];

      // step d and e
      k = hmac(k, v, new byte[]{0x00}, xOctets, hOctets, extraBytes);
      v = hmac(k, v);
      // step f and g
      k = hmac(k, v, new byte[]{0x01}, xOctets, hOctets, extraBytes);
      v = hmac(k, v);

      Arrays.fill(xOctets, (byte) 0);
    }

    /**
     * Returns the next candidate k in [1, n-1], as big-endian bytes of the length of n.
     * @return the next candidate k.
     */
    byte[] nextK() {
      while (true) {
        if (!first) {
          k = hmac(k, v, new byte[]{0x00});
          v = hmac(k, v);
        }
        first = false;

        byte[] t = new byte[0];
        while (t.length * 8 < qlen) {
          v = hmac(k, v);
          byte[] nt = new byte[t.length + v.length];
          System.arraycopy(t, 0, nt, 0, t.length);
          System.arraycopy(v, 0, nt, t.length, v.length);
          Arrays.fill(t, (byte) 0);
          t = nt;
        }

        byte[] cand = leftmostBits(t, qlen, rlen);
        Arrays.fill(t, (byte) 0);
        if (modN.isInRange(cand)) {
          return cand;
        }
        Arrays.fill(cand, (byte) 0);
      }
    }

    /**
     * bits2int of RFC 6979 on bytes: the leftmost qlen bits of t as big-endian bytes of length
     * rlen. The memory accesses depend only on the lengths.
     */
    static byte[] leftmostBits(byte[] t, int qlen, int rlen) {
      int shift = t.length * 8 - qlen;
      if (shift < 0) {
        throw new IllegalArgumentException("input too short");
      }
      int byteShift = shift >>> 3;
      int bitShift = shift & 7;
      byte[] out = new byte[rlen];
      for (int i = 0; i < rlen; i++) {
        int src = t.length - 1 - i - byteShift;
        int lo = (src >= 0) ? (t[src] & 0xFF) : 0;
        int hi = (src >= 1) ? (t[src - 1] & 0xFF) : 0;
        out[rlen - 1 - i] = (byte) ((lo >>> bitShift) | (hi << (8 - bitShift)));
      }
      return out;
    }

    private byte[] hmac(byte[] key, byte[]... data) {
      try {
        mac.init(new SecretKeySpec(key, macAlg));
      } catch (GeneralSecurityException e) {
        throw new ProviderException("could not initialize " + macAlg, e);
      }
      for (byte[] d : data) {
        mac.update(d);
      }
      return mac.doFinal();
    }

    /**
     * Returns the leftmost qlen bits of the input as integer (RFC 6979, section 2.3.2). This is
     * also the conversion of the hash value in ECDSA (SEC 1, section 4.1.3, step 5).
     */
    static BigInteger bits2int(byte[] in, int qlen) {
      BigInteger v = new BigInteger(1, in);
      int blen = in.length * 8;
      return (blen > qlen) ? v.shiftRight(blen - qlen) : v;
    }

    /**
     * int2octets of RFC 6979, section 2.3.3, of v mod n.
     */
    private byte[] int2octets(BigInteger v) {
      return modN.toBytes(modN.fromBigInteger(v));
    }

  }

}
