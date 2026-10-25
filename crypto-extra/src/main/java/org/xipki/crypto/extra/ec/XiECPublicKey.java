// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.security.KeyRep;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * EC public key on a named curve of {@link EcCurve}.
 * <p>
 * Encoded as SubjectPublicKeyInfo with id-ecPublicKey and the named curve (RFC 5480), the point
 * uncompressed.
 *
 * @author Lijun Liao (xipki)
 */
public final class XiECPublicKey implements ECPublicKey {

  private static final long serialVersionUID = 1L;

  private final transient EcCurve curve;

  private final ECPoint w;

  private final byte[] encoded;

  /**
   * Constructor.
   * @param curve the curve.
   * @param w the point, must be a valid public key (see {@link EcCurve#checkPublicPoint}).
   */
  XiECPublicKey(EcCurve curve, ECPoint w) {
    this.curve = curve;
    this.w = w;
    this.encoded = new SubjectPublicKeyInfo(
        new AlgorithmIdentifier(AlgorithmOIDs.id_ecPublicKey, curve.oid()),
        curve.encodePoint(w)).getEncoded();
  }

  EcCurve curve() {
    return curve;
  }

  @Override
  public ECPoint getW() {
    return w;
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
    return "X.509";
  }

  @Override
  public byte[] getEncoded() {
    return encoded.clone();
  }

  @Override
  public boolean equals(Object obj) {
    return obj == this
        || (obj instanceof XiECPublicKey && Arrays.equals(encoded, ((XiECPublicKey) obj).encoded));
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded);
  }

  @Override
  public String toString() {
    return "XiECPublicKey (" + curve.oid().getId() + ")";
  }

  private Object writeReplace() {
    return new KeyRep(KeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded());
  }

}
