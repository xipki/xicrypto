// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec.math;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.util.BigIntegers;
import org.xipki.codec.asn1.oid.CurveOIDs;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Named Weierstrass curve of the backend-neutral implementation, with the JCA view
 * ({@link ECParameterSpec}, {@link ECPoint}) used by the JCA services of the XiPKI provider.
 * <p>
 * The scalar multiplication of the base point ({@link #multiplyG(BigInteger)}) is constant-time
 * with respect to the scalar. {@link #sumOfTwoMultiplies(BigInteger, BigInteger, ECPoint)} is
 * meant for public values (signature verification).
 *
 * @author Lijun Liao (xipki)
 */
public final class EcCurve {

  /**
   * System property to disable the SM algorithms (SM2, SM3), e.g. to test that the other
   * algorithms work without them.
   */
  public static final String PROP_DISABLE_SM = "xipki.crypto.disableSm";

  /** curve name (upper case, without '-' and '_') or dotted OID to the curve OID. */
  private static final Map<String, Asn1Oid> ALIASES = new HashMap<>();

  /** {p, a, b, Gx, Gy, n} of the named curves, all with cofactor 1, in the order of lookup. */
  private static final Map<Asn1Oid, String[]> PARAMS = new LinkedHashMap<>();

  private static final Map<Asn1Oid, EcCurve> CURVES = new ConcurrentHashMap<>();

  static {
    define(CurveOIDs.secp256r1, new String[]{"P256", "SECP256R1", "PRIME256V1"},
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    define(CurveOIDs.secp384r1, new String[]{"P384", "SECP384R1"},
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
            + "ffffffff0000000000000000ffffffff",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
            + "ffffffff0000000000000000fffffffc",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a"
            + "c656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
            + "5502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
            + "0a60b1ce1d7e819d7a431d7c90ea0e5f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
            + "581a0db248b0a77aecec196accc52973");

    define(CurveOIDs.secp521r1, new String[]{"P521", "SECP521R1"},
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "fff",
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffc",
        "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109"
            + "e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f"
            + "00",
        "c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d"
            + "baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd"
            + "66",
        "11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6"
            + "62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16"
            + "650",
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386"
            + "409");

    define(CurveOIDs.brainpoolP256r1, new String[]{"BRAINPOOLP256R1"},
        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
        "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");

    define(CurveOIDs.brainpoolP384r1, new String[]{"BRAINPOOLP384R1"},
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123"
            + "acd3a729901d1a71874700133107ec53",
        "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f"
            + "8aa5814a503ad4eb04a8c7dd22ce2826",
        "4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57"
            + "cb4390295dbc9943ab78696fa504c11",
        "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8"
            + "e826e03436d646aaef87b2e247d4af1e",
        "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928"
            + "0e4646217791811142820341263c5315",
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7"
            + "cf3ab6af6b7fc3103b883202e9046565");

    define(CurveOIDs.brainpoolP512r1, new String[]{"BRAINPOOLP512R1"},
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871"
            + "7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc"
            + "2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7"
            + "2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
        "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e"
            + "ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111"
            + "b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870"
            + "553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069");

    define(CurveOIDs.sm2p256v1, new String[]{"SM2P256V1", "SM2"},
        "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
        "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
        "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
        "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
        "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
        "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123");

    define(CurveOIDs.frp256v1, new String[]{"FRP256V1"},
        "f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03",
        "f1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00",
        "ee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f",
        "b6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff",
        "6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb",
        "f1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1");
  }

  private final Asn1Oid oid;

  private final WeierstrassCurve curve;

  private final ECParameterSpec parameterSpec;

  private final BigInteger order;

  private volatile VarTimeMultiplier varTimeMultiplier;

  private EcCurve(Asn1Oid oid, String[] p) {
    this.oid = oid;
    this.curve = new WeierstrassCurve(
        new BigInteger(p[0], 16), new BigInteger(p[1], 16), new BigInteger(p[2], 16),
        new BigInteger(p[3], 16), new BigInteger(p[4], 16), new BigInteger(p[5], 16));
    this.order = curve.getOrder();

    PrimeField f = curve.field;
    EllipticCurve ec = new EllipticCurve(new ECFieldFp(f.p),
        f.toBigInteger(curve.a), f.toBigInteger(curve.b));
    WeierstrassPoint g = curve.getG();
    ECPoint jg = new ECPoint(g.getXCoordBigInt(), g.getYCoordBigInt());
    this.parameterSpec = new ECParameterSpec(ec, jg, order, 1);
  }

  private static void define(Asn1Oid oid, String[] names, String... params) {
    PARAMS.put(oid, params);
    ALIASES.put(oid.getId(), oid);
    for (String name : names) {
      ALIASES.put(name, oid);
    }
  }

  /**
   * Returns whether the SM algorithms are disabled by the system property
   * {@link #PROP_DISABLE_SM}.
   * @return whether the SM algorithms are disabled.
   */
  public static boolean isSmDisabled() {
    return Boolean.getBoolean(PROP_DISABLE_SM);
  }

  /**
   * Returns the curve for the name, as used in {@link java.security.spec.ECGenParameterSpec}.
   * @param name the OID (dotted) or a name of the curve, case-insensitive, '-' and '_' are
   *             ignored, e.g. "brainpoolP256r1", "SM2", "sm2p256v1", "FRP256v1", "secp256r1",
   *             "P-256".
   * @return the curve, or null if unknown.
   */
  public static EcCurve ofName(String name) {
    if (name == null) {
      return null;
    }
    String key = name.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
    return ofOid(ALIASES.get(key));
  }

  /**
   * Returns the curve.
   * @param oid the curve OID.
   * @return the curve, or null if unknown, or if it is SM2 and the SM algorithms are disabled.
   */
  public static EcCurve ofOid(Asn1Oid oid) {
    if (oid == null || (CurveOIDs.sm2p256v1.equals(oid) && isSmDisabled())) {
      return null;
    }

    EcCurve c = CURVES.get(oid);
    if (c != null) {
      return c;
    }

    String[] params = PARAMS.get(oid);
    return (params == null) ? null : CURVES.computeIfAbsent(oid, k -> new EcCurve(k, params));
  }

  /**
   * Returns the curve with the given parameters.
   * @param spec the parameters.
   * @return the curve, or null if no known curve has these parameters.
   */
  public static EcCurve ofParameterSpec(ECParameterSpec spec) {
    if (spec == null || !(spec.getCurve().getField() instanceof ECFieldFp)) {
      return null;
    }

    for (Asn1Oid oid : PARAMS.keySet()) {
      EcCurve c = ofOid(oid);
      if (c != null && c.matches(spec)) {
        return c;
      }
    }
    return null;
  }

  private boolean matches(ECParameterSpec spec) {
    ECParameterSpec m = parameterSpec;
    return m.getOrder().equals(spec.getOrder())
        && m.getCofactor() == spec.getCofactor()
        && m.getGenerator().equals(spec.getGenerator())
        && ((ECFieldFp) m.getCurve().getField()).getP().equals(
            ((ECFieldFp) spec.getCurve().getField()).getP())
        && m.getCurve().getA().equals(spec.getCurve().getA())
        && m.getCurve().getB().equals(spec.getCurve().getB());
  }

  public Asn1Oid oid() {
    return oid;
  }

  /**
   * Returns the curve arithmetic, e.g. for the adapters to the curve interfaces of the crypto
   * backends.
   * @return the curve arithmetic.
   */
  public WeierstrassCurve weierstrassCurve() {
    return curve;
  }

  public ECParameterSpec parameterSpec() {
    return parameterSpec;
  }

  public BigInteger order() {
    return order;
  }

  /**
   * Returns the length of the encoded field elements in bytes.
   * @return the length of the encoded field elements in bytes.
   */
  public int fieldByteLength() {
    return curve.field.byteLength;
  }

  /**
   * Returns k·G. Constant-time with respect to k.
   * @param k the scalar.
   * @return the point k·G in affine coordinates, or {@link ECPoint#POINT_INFINITY}.
   */
  public ECPoint multiplyG(BigInteger k) {
    return toJca(curve.getG().multiply(k));
  }

  /**
   * Returns the arithmetic modulo the order n, for secret scalars (constant-time).
   * @return the arithmetic modulo n.
   */
  public ModN scalarField() {
    return curve.scalars();
  }

  /**
   * Returns k·G. Constant-time with respect to k, including the conversion of k.
   * @param k the scalar, an element of {@link #scalarField()}.
   * @return the point k·G in affine coordinates, or {@link ECPoint#POINT_INFINITY}.
   */
  public ECPoint multiplyG(ModN.Element k) {
    return toJca(curve.getG().multiply(k));
  }

  /**
   * Returns u1·G + u2·Q. Variable-time, for public values only (signature verification), see
   * {@link VarTimeMultiplier}.
   * @param u1 the scalar of the base point.
   * @param u2 the scalar of Q.
   * @param q the point Q, must be on this curve.
   * @return u1·G + u2·Q in affine coordinates, or {@link ECPoint#POINT_INFINITY}.
   * @throws IllegalArgumentException if Q is not a valid point of this curve.
   */
  public ECPoint sumOfTwoMultiplies(BigInteger u1, BigInteger u2, ECPoint q) {
    PrimeField f = curve.field;
    int[][] qc = checkedCoordinates(q);
    int[][] r = varTimeMultiplier().sumOfTwoMultiplies(
        u1.mod(order), u2.mod(order), qc[0], qc[1]);
    return (r == null) ? ECPoint.POINT_INFINITY
        : new ECPoint(f.toBigInteger(r[0]), f.toBigInteger(r[1]));
  }

  private VarTimeMultiplier varTimeMultiplier() {
    VarTimeMultiplier m = varTimeMultiplier;
    if (m == null) {
      synchronized (this) {
        m = varTimeMultiplier;
        if (m == null) {
          m = new VarTimeMultiplier(curve);
          varTimeMultiplier = m;
        }
      }
    }
    return m;
  }

  /**
   * Returns the affine coordinates of the point in the field representation, after checking
   * that they are in [0, p) and that the point is on the curve.
   */
  private int[][] checkedCoordinates(ECPoint w) {
    if (w == null || ECPoint.POINT_INFINITY.equals(w)) {
      throw new IllegalArgumentException("point at infinity is not a valid public key");
    }

    PrimeField f = curve.field;
    BigInteger x = w.getAffineX();
    BigInteger y = w.getAffineY();
    if (x.signum() < 0 || x.compareTo(f.p) >= 0 || y.signum() < 0 || y.compareTo(f.p) >= 0) {
      throw new IllegalArgumentException("coordinate out of range");
    }

    int[] fx = f.fromBigInteger(x);
    int[] fy = f.fromBigInteger(y);
    if (!curve.isOnCurve(fx, fy)) {
      throw new IllegalArgumentException("point is not on the curve");
    }
    return new int[][]{fx, fy};
  }

  /**
   * Decodes a point (SEC 1, section 2.3.4) and validates it as a public key: it must be on the
   * curve and must not be the point at infinity.
   * @param encoded the encoded point.
   * @return the point.
   * @throws IllegalArgumentException if the encoding is invalid or the point is not valid.
   */
  public ECPoint decodePublicPoint(byte[] encoded) {
    WeierstrassPoint p = curve.decodePoint(encoded);
    if (p.isInfinity()) {
      throw new IllegalArgumentException("point at infinity is not a valid public key");
    }
    return toJca(p);
  }

  /**
   * Validates the point as a public key: coordinates in [0, p), on the curve, not the point at
   * infinity.
   * @param w the point.
   * @throws IllegalArgumentException if the point is not valid.
   */
  public void checkPublicPoint(ECPoint w) {
    checkedCoordinates(w);
  }

  /**
   * Encodes the point uncompressed (SEC 1, section 2.3.3).
   * @param w the point, not the point at infinity.
   * @return the encoded point.
   */
  public byte[] encodePoint(ECPoint w) {
    if (ECPoint.POINT_INFINITY.equals(w)) {
      throw new IllegalArgumentException("point at infinity");
    }

    int len = fieldByteLength();
    byte[] r = new byte[1 + 2 * len];
    r[0] = 0x04;
    BigIntegers.asUnsignedByteArray(w.getAffineX(), r, 1, len);
    BigIntegers.asUnsignedByteArray(w.getAffineY(), r, 1 + len, len);
    return r;
  }

  private static ECPoint toJca(WeierstrassPoint p) {
    if (p.isInfinity()) {
      return ECPoint.POINT_INFINITY;
    }
    WeierstrassPoint a = p.normalize();
    return new ECPoint(a.getXCoordBigInt(), a.getYCoordBigInt());
  }

  @Override
  public String toString() {
    return "EcCurve " + oid.getId();
  }

}
