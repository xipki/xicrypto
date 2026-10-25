// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.ECPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.math.BigInteger;
import java.security.KeyRep;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * EC private key on a named curve of {@link EcCurve}.
 * <p>
 * Encoded as PKCS#8 PrivateKeyInfo with id-ecPublicKey and the named curve, the inner
 * ECPrivateKey as in RFC 5915 (with the public key).
 * <p>
 * {@link #destroy()} drops the references to the secret values. {@link BigInteger} is
 * immutable, so copies made by the garbage collector or by callers cannot be zeroized.
 *
 * @author Lijun Liao (xipki)
 */
public final class XiECPrivateKey implements java.security.interfaces.ECPrivateKey {

  private static final long serialVersionUID = 1L;

  private final transient EcCurve curve;

  private BigInteger s;

  private ECPoint w;

  private byte[] encoded;

  private boolean destroyed;

  /**
   * Constructor.
   * @param curve the curve.
   * @param s the private value, in [1, n-1].
   * @param w the public point s·G, or null to compute it.
   */
  XiECPrivateKey(EcCurve curve, BigInteger s, ECPoint w) {
    this.curve = curve;
    this.s = s;
    this.w = (w != null) ? w : curve.multiplyG(s);
  }

  EcCurve curve() {
    return curve;
  }

  /**
   * Returns the public point s·G.
   * @return the public point.
   */
  ECPoint publicPoint() {
    assertNotDestroyed();
    return w;
  }

  @Override
  public BigInteger getS() {
    assertNotDestroyed();
    return s;
  }

  @Override
  public ECParameterSpec getParams() {
    return curve.parameterSpec();
  }

  @Override
  public String getAlgorithm() {
    return "EC";
  }

  @Override
  public String getFormat() {
    return "PKCS#8";
  }

  @Override
  public synchronized byte[] getEncoded() {
    assertNotDestroyed();
    if (encoded == null) {
      ECPrivateKey sk = new ECPrivateKey(curve.order().bitLength(), s,
          curve.encodePoint(w), null);
      encoded = new PrivateKeyInfo(
          new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, curve.oid()),
          sk.toAsn1Primitive()).getEncoded();
    }
    return encoded.clone();
  }

  @Override
  public synchronized void destroy() {
    if (encoded != null) {
      Arrays.fill(encoded, (byte) 0);
      encoded = null;
    }
    s = null;
    w = null;
    destroyed = true;
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  private void assertNotDestroyed() {
    if (destroyed) {
      throw new IllegalStateException("key is destroyed");
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof XiECPrivateKey) || destroyed) {
      return false;
    }
    XiECPrivateKey o = (XiECPrivateKey) obj;
    return !o.destroyed && curve == o.curve && s.equals(o.s);
  }

  @Override
  public int hashCode() {
    return destroyed ? 0 : curve.oid().hashCode();
  }

  @Override
  public String toString() {
    return "XiECPrivateKey (" + curve.oid().getId() + ")";
  }

  private Object writeReplace() {
    return new KeyRep(KeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded());
  }

}
