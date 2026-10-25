// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arithmetic modulo the (prime) order n of a curve, for the secret scalars of the signatures
 * (nonce, private key). Addition, subtraction, multiplication, inversion (Fermat) and the
 * conversions from and to fixed-length byte arrays are constant-time, see {@link PrimeField}.
 * <p>
 * The conversions from and to {@link BigInteger} are not constant-time: use them for public
 * values (hash, r, s) and at the API boundary (e.g. {@code ECPrivateKey.getS()}) only.
 *
 * @author Lijun Liao (xipki)
 */
public final class ModN {

  /**
   * Element of Z/nZ, in Montgomery form. Instances are immutable and belong to one {@link ModN}.
   */
  public static final class Element {

    private final ModN modN;

    private final int[] v;

    private Element(ModN modN, int[] v) {
      this.modN = modN;
      this.v = v;
    }

  }

  private final PrimeField f;

  private final int bitLength;

  ModN(BigInteger n) {
    this.f = new PrimeField(n);
    this.bitLength = n.bitLength();
  }

  /**
   * Returns the modulus n.
   * @return the modulus n.
   */
  public BigInteger modulus() {
    return f.p;
  }

  /**
   * Returns the length of n in bytes.
   * @return the length of n in bytes.
   */
  public int byteLength() {
    return f.byteLength;
  }

  /**
   * Returns the element for the value. Not constant-time: for public values, or at the API
   * boundary. Values outside [0, n) are reduced.
   * @param v the value, not negative.
   * @return the element.
   */
  public Element fromBigInteger(BigInteger v) {
    if (v.signum() < 0) {
      throw new IllegalArgumentException("negative value");
    }
    BigInteger r = (v.compareTo(f.p) < 0) ? v : v.mod(f.p);
    return new Element(this, f.fromBigInteger(r));
  }

  /**
   * Returns the element for the big-endian unsigned value, reduced mod n. Constant-time for a
   * given length.
   * @param be the value, at most as long as 4 * ceil(bitLength(n) / 32) bytes.
   * @return the element.
   */
  public Element fromBytes(byte[] be) {
    return new Element(this, f.fromBytes(be));
  }

  /**
   * Returns the value as big-endian bytes of exactly {@link #byteLength()} bytes.
   * Constant-time.
   * @param a the element.
   * @return the encoded value.
   */
  public byte[] toBytes(Element a) {
    return f.toBytes(check(a).v);
  }

  /**
   * Returns the value. Not constant-time: for public values (r, s) only.
   * @param a the element.
   * @return the value.
   */
  public BigInteger toBigInteger(Element a) {
    return f.toBigInteger(check(a).v);
  }

  public Element one() {
    return new Element(this, f.one());
  }

  public Element add(Element a, Element b) {
    return new Element(this, f.add(check(a).v, check(b).v));
  }

  public Element sub(Element a, Element b) {
    return new Element(this, f.sub(check(a).v, check(b).v));
  }

  public Element mul(Element a, Element b) {
    return new Element(this, f.mul(check(a).v, check(b).v));
  }

  /**
   * Returns a^-1 mod n (a^(n-2), constant-time), or 0 for a = 0.
   * @param a the element.
   * @return the inverse.
   */
  public Element inv(Element a) {
    return new Element(this, f.inv(check(a).v));
  }

  public boolean isZero(Element a) {
    return f.isZero(check(a).v);
  }

  /**
   * Returns whether the big-endian unsigned value is in [1, n-1]. Constant-time for a given
   * length; only the result is revealed.
   * @param be the value, at most as long as 4 * ceil(bitLength(n) / 32) bytes.
   * @return whether the value is in [1, n-1].
   */
  public boolean isInRange(byte[] be) {
    return f.isInRangeNonZero(PrimeField.limbsFromBytes(be, f.n));
  }

  /**
   * Returns a uniformly random element of [1, n-1] (rejection sampling on
   * {@link #byteLength()} random bytes with the bits above bitLength(n) cleared).
   * @param random the source of randomness.
   * @return the random element.
   */
  public Element random(SecureRandom random) {
    byte[] b = new byte[f.byteLength];
    int topBits = bitLength - 8 * (f.byteLength - 1);
    int topMask = (1 << topBits) - 1;
    try {
      while (true) {
        random.nextBytes(b);
        b[0] &= (byte) topMask;
        if (isInRange(b)) {
          return fromBytes(b);
        }
      }
    } finally {
      java.util.Arrays.fill(b, (byte) 0);
    }
  }

  /**
   * Returns the plain value as little-endian 32-bit limbs, for the scalar multiplication.
   */
  int[] plainLimbs(Element a) {
    return f.toPlain(check(a).v);
  }

  private Element check(Element a) {
    if (a.modN != this) {
      throw new IllegalArgumentException("element of another modulus");
    }
    return a;
  }

}
