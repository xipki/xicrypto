// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.io.Serial;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;

/**
 * A key of OpenSSL (EVP_PKEY), with the JCA interfaces of its type. The encoding (X.509
 * SubjectPublicKeyInfo or PKCS#8 PrivateKeyInfo) is that of OpenSSL; the values of the key
 * are read from OpenSSL when requested.
 *
 * @author Lijun Liao (xipki)
 */
abstract class OsslKey implements Key {

  private final transient NativeKey nativeKey;

  private final String algorithm;

  private final byte[] encoded;

  private OsslKey(NativeKey nativeKey, String algorithm) {
    this.nativeKey = nativeKey;
    this.algorithm = algorithm;
    this.encoded = nativeKey.apply(pkey -> OpenSsl.encodeKey(pkey, nativeKey.isPrivate()));
    if (encoded == null) {
      throw new IllegalStateException("could not encode the key: " + OpenSsl.errors());
    }
  }

  /**
   * Returns the Java key of the EVP_PKEY, which is owned by the returned key.
   * @param pkey the EVP_PKEY.
   * @param privateKey whether it is a private key.
   * @return the key.
   * @throws InvalidKeyException if the type of the key is not supported.
   */
  static OsslKey wrap(MemorySegment pkey, boolean privateKey) throws InvalidKeyException {
    String type = OpenSsl.pkeyTypeName(pkey);
    NativeKey nk = new NativeKey(pkey, privateKey);
    if (type == null) {
      throw new InvalidKeyException("unknown key type");
    }

    switch (type) {
      case "RSA":
      case "RSA-PSS":
        return privateKey ? new RsaPrivate(nk) : new RsaPublic(nk);
      case "EC":
      case "SM2":
        return privateKey ? new EcPrivate(nk) : new EcPublic(nk);
      case "ED25519":
      case "ED448":
        return privateKey ? new EdPrivate(nk, type) : new EdPublic(nk, type);
      case "X25519":
      case "X448":
        return privateKey ? new XecPrivate(nk, type) : new XecPublic(nk, type);
      default:
        if (type.startsWith("ML-DSA-") || type.startsWith("ML-KEM-")) {
          return privateKey ? new PqcPrivate(nk, type) : new PqcPublic(nk, type);
        }
        throw new InvalidKeyException("unsupported key type " + type);
    }
  }

  /**
   * Returns the Java key of the EVP_PKEY, or throws an IllegalStateException. For the keys
   * just generated or imported, whose type is known to be supported.
   */
  static OsslKey wrapKnown(MemorySegment pkey, boolean privateKey) {
    try {
      return wrap(pkey, privateKey);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException(e.getMessage(), e);
    }
  }

  NativeKey nativeKey() {
    return nativeKey;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getFormat() {
    return nativeKey.isPrivate() ? "PKCS#8" : "X.509";
  }

  @Override
  public byte[] getEncoded() {
    return encoded.clone();
  }

  /**
   * Serialized as {@link KeyRep}: the EVP_PKEY cannot be serialized.
   */
  @Serial
  Object writeReplace() {
    return new KeyRep(nativeKey.isPrivate() ? KeyRep.Type.PRIVATE : KeyRep.Type.PUBLIC,
        algorithm, getFormat(), encoded);
  }

  @Override
  public boolean equals(Object obj) {
    return obj instanceof OsslKey other && nativeKey.isPrivate() == other.nativeKey.isPrivate()
        && Arrays.equals(encoded, other.encoded);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded);
  }

  BigInteger bigIntParam(String name) {
    BigInteger v = nativeKey.apply(pkey -> OpenSsl.pkeyBigIntParam(pkey, name));
    if (v == null) {
      throw new IllegalStateException("could not read the parameter " + name + " of the key");
    }
    return v;
  }

  byte[] rawKey() {
    byte[] raw = nativeKey.apply(pkey -> OpenSsl.pkeyRawKey(pkey, nativeKey.isPrivate()));
    if (raw == null) {
      throw new IllegalStateException("could not read the raw key");
    }
    return raw;
  }

  /** Returns the integer of the little-endian bytes. */
  static BigInteger fromLittleEndian(byte[] le) {
    byte[] be = new byte[le.length];
    for (int i = 0; i < le.length; i++) {
      be[i] = le[le.length - 1 - i];
    }
    return new BigInteger(1, be);
  }

  // ---------- RSA ----------

  private static final class RsaPublic extends OsslKey implements RSAPublicKey {

    private final BigInteger modulus;

    private final BigInteger publicExponent;

    RsaPublic(NativeKey nk) {
      super(nk, "RSA");
      this.modulus = bigIntParam("n");
      this.publicExponent = bigIntParam("e");
    }

    @Override
    public BigInteger getModulus() {
      return modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
      return publicExponent;
    }

  }

  private static final class RsaPrivate extends OsslKey implements RSAPrivateCrtKey {

    private final BigInteger modulus;

    RsaPrivate(NativeKey nk) {
      super(nk, "RSA");
      this.modulus = bigIntParam("n");
    }

    @Override
    public BigInteger getModulus() {
      return modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
      return bigIntParam("e");
    }

    @Override
    public BigInteger getPrivateExponent() {
      return bigIntParam("d");
    }

    @Override
    public BigInteger getPrimeP() {
      return bigIntParam("rsa-factor1");
    }

    @Override
    public BigInteger getPrimeQ() {
      return bigIntParam("rsa-factor2");
    }

    @Override
    public BigInteger getPrimeExponentP() {
      return bigIntParam("rsa-exponent1");
    }

    @Override
    public BigInteger getPrimeExponentQ() {
      return bigIntParam("rsa-exponent2");
    }

    @Override
    public BigInteger getCrtCoefficient() {
      return bigIntParam("rsa-coefficient1");
    }

  }

  // ---------- EC ----------

  private static OsslCurves.Curve curve(NativeKey nk) {
    String group = nk.apply(pkey -> OpenSsl.pkeyUtf8StringParam(pkey, "group"));
    OsslCurves.Curve curve = OsslCurves.byGroupName(group);
    if (curve == null) {
      throw new IllegalStateException("unsupported curve " + group);
    }
    return curve;
  }

  private static final class EcPublic extends OsslKey implements ECPublicKey {

    private final OsslCurves.Curve curve;

    private final ECPoint w;

    EcPublic(NativeKey nk) {
      super(nk, "EC");
      this.curve = curve(nk);
      byte[] encoded = nk.apply(pkey ->
          OpenSsl.pkeyOctetStringParam(pkey, "encoded-pub-key", 1 + 2 * 66));
      this.w = OsslCurves.decodePoint(encoded);
    }

    @Override
    public ECPoint getW() {
      return w;
    }

    @Override
    public ECParameterSpec getParams() {
      return curve.spec();
    }

  }

  private static final class EcPrivate extends OsslKey implements ECPrivateKey {

    private final OsslCurves.Curve curve;

    EcPrivate(NativeKey nk) {
      super(nk, "EC");
      this.curve = curve(nk);
    }

    @Override
    public BigInteger getS() {
      return bigIntParam("priv");
    }

    @Override
    public ECParameterSpec getParams() {
      return curve.spec();
    }

  }

  // ---------- EdDSA, XDH ----------

  private static NamedParameterSpec namedSpec(String type) {
    return switch (type) {
      case "ED25519" -> NamedParameterSpec.ED25519;
      case "ED448" -> NamedParameterSpec.ED448;
      case "X25519" -> NamedParameterSpec.X25519;
      case "X448" -> NamedParameterSpec.X448;
      default -> new NamedParameterSpec(type);
    };
  }

  private static final class EdPublic extends OsslKey implements EdECPublicKey {

    private final NamedParameterSpec params;

    private final EdECPoint point;

    EdPublic(NativeKey nk, String type) {
      super(nk, "EdDSA");
      this.params = namedSpec(type);
      // RFC 8032: y little-endian, the most significant bit of the last byte is the x parity
      byte[] raw = rawKey();
      boolean xOdd = (raw[raw.length - 1] & 0x80) != 0;
      raw[raw.length - 1] &= 0x7F;
      this.point = new EdECPoint(xOdd, fromLittleEndian(raw));
    }

    @Override
    public EdECPoint getPoint() {
      return point;
    }

    @Override
    public NamedParameterSpec getParams() {
      return params;
    }

  }

  private static final class EdPrivate extends OsslKey implements EdECPrivateKey {

    private final NamedParameterSpec params;

    EdPrivate(NativeKey nk, String type) {
      super(nk, "EdDSA");
      this.params = namedSpec(type);
    }

    @Override
    public Optional<byte[]> getBytes() {
      return Optional.of(rawKey());
    }

    @Override
    public NamedParameterSpec getParams() {
      return params;
    }

  }

  private static final class XecPublic extends OsslKey implements XECPublicKey {

    private final NamedParameterSpec params;

    private final BigInteger u;

    XecPublic(NativeKey nk, String type) {
      super(nk, "XDH");
      this.params = namedSpec(type);
      byte[] raw = rawKey();
      if ("X25519".equals(type)) {
        // RFC 7748: the most significant bit is masked
        raw[raw.length - 1] &= 0x7F;
      }
      this.u = fromLittleEndian(raw);
    }

    @Override
    public BigInteger getU() {
      return u;
    }

    @Override
    public AlgorithmParameterSpec getParams() {
      return params;
    }

  }

  private static final class XecPrivate extends OsslKey implements XECPrivateKey {

    private final NamedParameterSpec params;

    XecPrivate(NativeKey nk, String type) {
      super(nk, "XDH");
      this.params = namedSpec(type);
    }

    @Override
    public Optional<byte[]> getScalar() {
      return Optional.of(rawKey());
    }

    @Override
    public AlgorithmParameterSpec getParams() {
      return params;
    }

  }

  // ---------- ML-DSA, ML-KEM ----------

  private static final class PqcPublic extends OsslKey implements PublicKey {

    private final NamedParameterSpec params;

    PqcPublic(NativeKey nk, String type) {
      super(nk, type.substring(0, 6));
      this.params = new NamedParameterSpec(type);
    }

    @Override
    public NamedParameterSpec getParams() {
      return params;
    }

  }

  private static final class PqcPrivate extends OsslKey implements PrivateKey {

    private final NamedParameterSpec params;

    PqcPrivate(NativeKey nk, String type) {
      super(nk, type.substring(0, 6));
      this.params = new NamedParameterSpec(type);
    }

    @Override
    public NamedParameterSpec getParams() {
      return params;
    }

  }

}
