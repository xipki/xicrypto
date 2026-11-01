// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Weierstrass curves of OpenSSL used by xipki.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslCurves {

  /**
   * A curve.
   *
   * @param oid the OID.
   * @param name the name of the curve in OpenSSL (the "group" parameter).
   * @param keyType the key type in OpenSSL: "SM2" for the curve SM2, "EC" otherwise.
   * @param aliases the further names, e.g. "P-256".
   */
  record Curve(Asn1Oid oid, String name, String keyType, String... aliases) {

    /** Returns the ECParameterSpec of the curve, computed once. */
    ECParameterSpec spec() {
      return SPECS.computeIfAbsent(this, OsslCurves::newSpec);
    }

    /** Returns the EC_GROUP of the curve, never freed. */
    MemorySegment group() {
      return GROUPS.computeIfAbsent(this, c -> {
        MemorySegment group = OpenSsl.ecGroup(c.name);
        if (OpenSsl.isNull(group)) {
          throw new IllegalStateException("OpenSSL does not support the curve " + c.name);
        }
        return group;
      });
    }

    /** Returns the length of the field elements in bytes. */
    int fieldByteLength() {
      return (((ECFieldFp) spec().getCurve().getField()).getFieldSize() + 7) / 8;
    }

  }

  /**
   * The ECParameterSpec of a named curve.
   */
  static final class NamedSpec extends ECParameterSpec {

    private final Curve curve;

    NamedSpec(Curve curve, EllipticCurve ec, ECPoint g, BigInteger n, int h) {
      super(ec, g, n, h);
      this.curve = curve;
    }

    Curve curve() {
      return curve;
    }

    @Override
    public String toString() {
      return curve.name + " (" + curve.oid.getId() + ")";
    }

  }

  private static final List<Curve> CURVES = List.of(
      new Curve(CurveOIDs.secp192r1, "prime192v1", "EC", "secp192r1", "P-192"),
      new Curve(CurveOIDs.secp224r1, "secp224r1", "EC", "P-224"),
      new Curve(CurveOIDs.secp256r1, "prime256v1", "EC", "secp256r1", "P-256"),
      new Curve(CurveOIDs.secp384r1, "secp384r1", "EC", "P-384"),
      new Curve(CurveOIDs.secp521r1, "secp521r1", "EC", "P-521"),
      new Curve(CurveOIDs.brainpoolP192r1, "brainpoolP192r1", "EC"),
      new Curve(CurveOIDs.brainpoolP224r1, "brainpoolP224r1", "EC"),
      new Curve(CurveOIDs.brainpoolP256r1, "brainpoolP256r1", "EC"),
      new Curve(CurveOIDs.brainpoolP384r1, "brainpoolP384r1", "EC"),
      new Curve(CurveOIDs.brainpoolP512r1, "brainpoolP512r1", "EC"),
      new Curve(CurveOIDs.sm2p256v1, "SM2", "SM2", "sm2p256v1"));

  /** Upper-case name, alias or OID to the curve. */
  private static final Map<String, Curve> BY_NAME = new HashMap<>();

  private static final Map<Curve, ECParameterSpec> SPECS =
      new ConcurrentHashMap<>();

  private static final Map<Curve, MemorySegment> GROUPS =
      new ConcurrentHashMap<>();

  static {
    for (Curve c : CURVES) {
      BY_NAME.put(c.oid.getId(), c);
      BY_NAME.put(c.name.toUpperCase(Locale.ROOT), c);
      for (String alias : c.aliases) {
        BY_NAME.put(alias.toUpperCase(Locale.ROOT), c);
      }
    }
  }

  private OsslCurves() {
  }

  /**
   * Returns the curve of the name, alias or OID.
   * @return the curve, or null if not supported.
   */
  static Curve byName(String name) {
    return (name == null) ? null : BY_NAME.get(name.trim().toUpperCase(Locale.ROOT));
  }

  /**
   * Returns the curve of the OpenSSL "group" name of a key.
   * @return the curve, or null if not supported.
   */
  static Curve byGroupName(String group) {
    return byName(group);
  }

  /**
   * Returns the curve of the parameters: ECGenParameterSpec (name or OID), or ECParameterSpec
   * (compared by value).
   * @throws InvalidAlgorithmParameterException if the curve is not supported.
   */
  static Curve of(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    Curve curve = null;
    if (params instanceof ECGenParameterSpec gen) {
      curve = byName(gen.getName());
    } else if (params instanceof NamedSpec named) {
      curve = named.curve();
    } else if (params instanceof ECParameterSpec spec) {
      curve = bySpec(spec);
    }

    if (curve == null) {
      throw new InvalidAlgorithmParameterException("unsupported EC parameters " + params);
    }
    return curve;
  }

  private static Curve bySpec(ECParameterSpec spec) {
    for (Curve c : CURVES) {
      ECParameterSpec s = c.spec();
      if (s.getCurve().equals(spec.getCurve()) && s.getGenerator().equals(spec.getGenerator())
          && s.getOrder().equals(spec.getOrder()) && s.getCofactor() == spec.getCofactor()) {
        return c;
      }
    }
    return null;
  }

  /**
   * Returns the curve of the key size: 256, 384 or 521 for the NIST curves.
   * @return the curve, or null if no curve of this size.
   */
  static Curve ofKeySize(int keySize) {
    return switch (keySize) {
      case 192 -> byName("P-192");
      case 224 -> byName("P-224");
      case 256 -> byName("P-256");
      case 384 -> byName("P-384");
      case 521 -> byName("P-521");
      default -> null;
    };
  }

  private static ECParameterSpec newSpec(Curve c) {
    MemorySegment group = c.group();
    // {p, a, b, order, cofactor}
    BigInteger[] params = OpenSsl.ecGroupParams(group);
    byte[] g = OpenSsl.ecPointEncode(group, OpenSsl.ecGenerator(group), false);
    int len = (g.length - 1) / 2;
    ECPoint generator = new ECPoint(new BigInteger(1, g, 1, len),
        new BigInteger(1, g, 1 + len, len));
    return new NamedSpec(c, new EllipticCurve(new ECFieldFp(params[0]), params[1], params[2]),
        generator, params[3], params[4].intValueExact());
  }

  /**
   * Returns the uncompressed encoding 04 || x || y of the point.
   */
  static byte[] encodePoint(Curve curve, ECPoint w) {
    int len = curve.fieldByteLength();
    byte[] encoded = new byte[1 + 2 * len];
    encoded[0] = 4;
    toFixedLength(w.getAffineX(), encoded, 1, len);
    toFixedLength(w.getAffineY(), encoded, 1 + len, len);
    return encoded;
  }

  /**
   * Returns the point of the uncompressed encoding 04 || x || y.
   */
  static ECPoint decodePoint(byte[] encoded) {
    if (encoded.length < 3 || encoded[0] != 4 || encoded.length % 2 != 1) {
      throw new IllegalArgumentException("not an uncompressed EC point");
    }
    int len = (encoded.length - 1) / 2;
    return new ECPoint(new BigInteger(1, encoded, 1, len),
        new BigInteger(1, encoded, 1 + len, len));
  }

  private static void toFixedLength(BigInteger v, byte[] out, int off, int len) {
    byte[] be = v.toByteArray();
    int skip = (be.length > len) ? be.length - len : 0;
    System.arraycopy(be, skip, out, off + len - (be.length - skip), be.length - skip);
  }

}
