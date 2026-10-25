// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.crypto.extra.SM3Digest;
import org.xipki.crypto.extra.XiSignatureSpi;
import org.xipki.crypto.extra.ec.math.EcCurve;
import org.xipki.crypto.extra.ec.math.ModN;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * Signature SM3withSM2 (GB/T 32918.2) with the default user ID "1234567812345678", the
 * signature encoded as DER SEQUENCE { r INTEGER, s INTEGER }.
 *
 * @author Lijun Liao (xipki)
 */
public class SM2WITHSM3SignatureSpi extends XiSignatureSpi {

  private XiECPrivateKey sk;

  private XiECPublicKey pk;

  private byte[] za;

  public SM2WITHSM3SignatureSpi() {
    super(new SM3Digest());
  }

  @Override
  protected void initVerify(PublicKey publicKey) throws InvalidKeyException {
    XiECPublicKey key = EcKeys.toXiPublicKey(publicKey);
    assertSm2(key.curve());
    this.pk = key;
    this.sk = null;
    this.za = Sm2.z(null, key.getW());
  }

  @Override
  protected void initSign(PrivateKey privateKey) throws InvalidKeyException {
    XiECPrivateKey key = EcKeys.toXiPrivateKey(privateKey);
    assertSm2(key.curve());
    this.sk = key;
    this.pk = null;
    this.za = Sm2.z(null, key.publicPoint());
  }

  private static void assertSm2(EcCurve curve) throws InvalidKeyException {
    if (curve != Sm2.curve()) {
      throw new InvalidKeyException("not a key of the curve sm2p256v1");
    }
  }

  /**
   * The hash is e = SM3(Z_A || M): Z_A is the start of every message.
   */
  @Override
  protected void resetDigest() {
    digest.reset();
    digest.update(za);
  }

  @Override
  protected byte[] sign(byte[] e) {
    BigInteger[] rs = Sm2.sign(sk.getS(), e, secureRandom());
    return new DssSigValue(rs[0], rs[1]).getEncoded();
  }

  @Override
  protected boolean verify(byte[] e, byte[] sigBytes) {
    DssSigValue sig = EcKeys.decodeSignature(sigBytes);
    return sig != null && Sm2.verify(pk.getW(), e, sig.r(), sig.s());
  }

  /**
   * SM2 digital signature (GB/T 32918.2) on the curve sm2p256v1, with SM3.
   *
   * @author Lijun Liao (xipki)
   */
  private static final class Sm2 {

    /** default user ID "1234567812345678". */
    private static final byte[] DEFAULT_ID = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};

    private static final SecureRandom BLINDING_RANDOM = new SecureRandom();

    private Sm2() {
    }

    /**
     * Returns the curve sm2p256v1.
     * @return the curve, or null if the SM algorithms are disabled.
     */
    static EcCurve curve() {
      return EcCurve.ofOid(CurveOIDs.sm2p256v1);
    }

    /**
     * Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A).
     * @param userId the user ID, null for the default "1234567812345678".
     * @param w the public point.
     * @return Z_A.
     */
    static byte[] z(byte[] userId, ECPoint w) {
      byte[] id = (userId == null) ? DEFAULT_ID : userId;
      if (id.length > 0x1FFF) {
        throw new IllegalArgumentException("user ID too long");
      }

      EcCurve curve = curve();
      ECParameterSpec spec = curve.parameterSpec();
      int len = curve.fieldByteLength();

      SM3Digest digest = new SM3Digest();
      int bits = id.length * 8;
      digest.update((byte) (bits >> 8));
      digest.update((byte) bits);
      digest.update(id);
      for (BigInteger v : new BigInteger[]{spec.getCurve().getA(), spec.getCurve().getB(),
          spec.getGenerator().getAffineX(), spec.getGenerator().getAffineY(),
          w.getAffineX(), w.getAffineY()}) {
        digest.update(BigIntegers.asUnsignedByteArray(len, v));
      }
      return digest.digest();
    }

    /**
     * Signs the hash e = SM3(Z_A || M). The secret values (d, k) are handled with the
     * constant-time arithmetic of {@link ModN}; only r and s (public) are {@link BigInteger}.
     * @param d the private key.
     * @param e the hash.
     * @param random the source of k.
     * @return {r, s}.
     */
    static BigInteger[] sign(BigInteger d, byte[] e, SecureRandom random) {
      EcCurve curve = curve();
      ModN modN = curve.scalarField();
      BigInteger n = curve.order();
      // the hash is public
      BigInteger eh = new BigInteger(1, e);
      // JCA boundary: the private key is a BigInteger
      ModN.Element dE = modN.fromBigInteger(d);
      ModN.Element onePlusD = modN.add(modN.one(), dE);

      while (true) {
        ModN.Element k = modN.random(random);
        // (x1, y1) = k·G
        ECPoint kG = curve.multiplyG(k);
        // r = (e + x1) mod n, r != 0 and r + k != n; r is public
        BigInteger r = eh.add(kG.getAffineX()).mod(n);
        ModN.Element rE = modN.fromBigInteger(r);
        if (r.signum() == 0 || modN.isZero(modN.add(rE, k))) {
          continue;
        }

        // s = (1 + d)^-1 · (k - r·d) mod n, blinded with a random b:
        // s = (b·(1 + d))^-1 · (b·k - b·r·d) mod n
        ModN.Element b = modN.random(BLINDING_RANDOM);
        ModN.Element inv = modN.inv(modN.mul(b, onePlusD));
        ModN.Element t = modN.sub(modN.mul(b, k), modN.mul(modN.mul(b, rE), dE));
        ModN.Element s = modN.mul(inv, t);
        if (!modN.isZero(s)) {
          return new BigInteger[]{r, modN.toBigInteger(s)};
        }
      }
    }

    /**
     * Verifies the signature (r, s) of the hash e = SM3(Z_A || M).
     */
    static boolean verify(ECPoint w, byte[] e, BigInteger r, BigInteger s) {
      EcCurve curve = curve();
      BigInteger n = curve.order();
      if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0) {
        return false;
      }

      // t = (r + s) mod n, t != 0
      BigInteger t = r.add(s).mod(n);
      if (t.signum() == 0) {
        return false;
      }

      // (x1, y1) = s·G + t·P
      ECPoint p = curve.sumOfTwoMultiplies(s, t, w);
      if (ECPoint.POINT_INFINITY.equals(p)) {
        return false;
      }

      // R = (e + x1) mod n
      return new BigInteger(1, e).add(p.getAffineX()).mod(n).equals(r);
    }

  }

}
