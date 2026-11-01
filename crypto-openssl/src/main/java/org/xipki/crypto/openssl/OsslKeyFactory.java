// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Locale;

/**
 * KeyFactory on OpenSSL. The keys are {@link OsslKey}s.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslKeyFactory extends KeyFactorySpi {

  /**
   * Whether OpenSSL needs the public key to encode an EC private key (3.x does, 4.1 does not),
   * probed once.
   */
  private static final class EcPubRequired {

    static final boolean VALUE = probe();

    private static boolean probe() {
      MemorySegment pkey = OpenSsl.keyFromData("EC", true, new OsslParams()
          .utf8("group", "prime256v1").bigInt("priv", BigInteger.ONE, true));
      if (OpenSsl.isNull(pkey)) {
        OpenSsl.clearErrors();
        return true;
      }
      try {
        byte[] encoded = OpenSsl.encodeKey(pkey, true);
        if (encoded == null) {
          OpenSsl.clearErrors();
        }
        return encoded == null;
      } finally {
        OpenSsl.pkeyFree(pkey);
      }
    }

  }

  /** The allowed key types in OpenSSL, e.g. {"RSA", "RSA-PSS"}. */
  private final String[] keyTypes;

  /**
   * Constructor.
   * @param keyTypes the allowed key types in OpenSSL.
   */
  OsslKeyFactory(String... keyTypes) {
    this.keyTypes = keyTypes;
  }

  private boolean allows(String keyType) {
    for (String t : keyTypes) {
      if (t.equals(keyType)) {
        return true;
      }
    }
    return false;
  }

  private boolean allowsAny(String... types) {
    for (String t : types) {
      if (allows(t)) {
        return true;
      }
    }
    return false;
  }

  /** Wraps the EVP_PKEY if it is of an allowed type, otherwise frees it. */
  private OsslKey wrap(MemorySegment pkey, boolean privateKey, String what)
      throws InvalidKeySpecException {
    if (OpenSsl.isNull(pkey)) {
      throw new InvalidKeySpecException("invalid " + what + ": " + OpenSsl.errors());
    }

    String type = OpenSsl.pkeyTypeName(pkey);
    if (!allows(type)) {
      OpenSsl.pkeyFree(pkey);
      throw new InvalidKeySpecException("not a " + String.join(" / ", keyTypes) + " key: "
          + type);
    }

    try {
      return OsslKey.wrap(pkey, privateKey);
    } catch (InvalidKeyException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }
  }

  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    MemorySegment pkey;
    if (keySpec instanceof X509EncodedKeySpec spec) {
      pkey = OpenSsl.d2iPublicKey(spec.getEncoded());
    } else if (keySpec instanceof RSAPublicKeySpec spec && allows("RSA")) {
      pkey = OpenSsl.keyFromData("RSA", false, new OsslParams()
          .bigInt("n", spec.getModulus(), false)
          .bigInt("e", spec.getPublicExponent(), false));
    } else if (keySpec instanceof ECPublicKeySpec spec && allows("EC")) {
      OsslCurves.Curve curve = curve(spec.getParams());
      pkey = OpenSsl.keyFromData(curve.keyType(), false, new OsslParams()
          .utf8("group", curve.name())
          .octets("pub", OsslCurves.encodePoint(curve, spec.getW())));
    } else if (keySpec instanceof XECPublicKeySpec spec && allowsAny("X25519", "X448")) {
      String type = xdhType(spec.getParams());
      pkey = OpenSsl.newRawPublicKey(type,
          toLittleEndian(spec.getU(), "X25519".equals(type) ? 32 : 56));
    } else if (keySpec instanceof EdECPublicKeySpec spec && allowsAny("ED25519", "ED448")) {
      String type = edType(spec.getParams());
      pkey = OpenSsl.newRawPublicKey(type, encodeEdPoint(type, spec.getPoint()));
    } else {
      throw new InvalidKeySpecException("unsupported key spec " + keySpec);
    }

    return (PublicKey) wrap(pkey, false, "public key");
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    MemorySegment pkey;
    if (keySpec instanceof PKCS8EncodedKeySpec spec) {
      byte[] encoded = spec.getEncoded();
      try {
        pkey = OpenSsl.d2iPrivateKey(encoded);
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
    } else if (keySpec instanceof RSAPrivateCrtKeySpec spec && allows("RSA")) {
      pkey = OpenSsl.keyFromData("RSA", true, new OsslParams()
          .bigInt("n", spec.getModulus(), false)
          .bigInt("e", spec.getPublicExponent(), false)
          .bigInt("d", spec.getPrivateExponent(), true)
          .bigInt("rsa-factor1", spec.getPrimeP(), true)
          .bigInt("rsa-factor2", spec.getPrimeQ(), true)
          .bigInt("rsa-exponent1", spec.getPrimeExponentP(), true)
          .bigInt("rsa-exponent2", spec.getPrimeExponentQ(), true)
          .bigInt("rsa-coefficient1", spec.getCrtCoefficient(), true));
    } else if (keySpec instanceof ECPrivateKeySpec spec && allows("EC")) {
      OsslCurves.Curve curve = curve(spec.getParams());
      OsslParams params = new OsslParams().utf8("group", curve.name());
      if (EcPubRequired.VALUE) {
        MemorySegment w =
            OpenSsl.ecPointMul(curve.group(), spec.getS(), MemorySegment.NULL, null);
        try {
          params.octets("pub", OpenSsl.ecPointEncode(curve.group(), w, false));
        } finally {
          OpenSsl.ecPointFree(w);
        }
      }
      pkey = OpenSsl.keyFromData(curve.keyType(), true,
          params.bigInt("priv", spec.getS(), true));
    } else if (keySpec instanceof XECPrivateKeySpec spec && allowsAny("X25519", "X448")) {
      pkey = OpenSsl.newRawPrivateKey(xdhType(spec.getParams()), spec.getScalar());
    } else if (keySpec instanceof EdECPrivateKeySpec spec && allowsAny("ED25519", "ED448")) {
      pkey = OpenSsl.newRawPrivateKey(edType(spec.getParams()), spec.getBytes());
    } else {
      throw new InvalidKeySpecException("unsupported key spec " + keySpec);
    }

    return (PrivateKey) wrap(pkey, true, "private key");
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    try {
      key = engineTranslateKey(key);
    } catch (InvalidKeyException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }

    Object spec = null;
    if (keySpec.isAssignableFrom(X509EncodedKeySpec.class) && key instanceof PublicKey) {
      spec = new X509EncodedKeySpec(key.getEncoded());
    } else if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class) && key instanceof PrivateKey) {
      spec = new PKCS8EncodedKeySpec(key.getEncoded());
    } else if (keySpec.isAssignableFrom(RSAPublicKeySpec.class) && key instanceof RSAPublicKey k) {
      spec = new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent());
    } else if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class)
        && key instanceof RSAPrivateCrtKey k) {
      spec = new RSAPrivateCrtKeySpec(k.getModulus(), k.getPublicExponent(),
          k.getPrivateExponent(), k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(),
          k.getPrimeExponentQ(), k.getCrtCoefficient());
    } else if (keySpec.isAssignableFrom(ECPublicKeySpec.class) && key instanceof ECPublicKey k) {
      spec = new ECPublicKeySpec(k.getW(), k.getParams());
    } else if (keySpec.isAssignableFrom(ECPrivateKeySpec.class) && key instanceof ECPrivateKey k) {
      spec = new ECPrivateKeySpec(k.getS(), k.getParams());
    } else if (keySpec.isAssignableFrom(XECPublicKeySpec.class) && key instanceof XECPublicKey k) {
      spec = new XECPublicKeySpec(k.getParams(), k.getU());
    } else if (keySpec.isAssignableFrom(EdECPublicKeySpec.class)
        && key instanceof EdECPublicKey k) {
      spec = new EdECPublicKeySpec(k.getParams(), k.getPoint());
    }

    if (spec == null) {
      throw new InvalidKeySpecException("unsupported key spec " + keySpec.getName() + " for "
          + key.getClass().getName());
    }
    return keySpec.cast(spec);
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    if (key instanceof OsslKey ok) {
      if (!allows(ok.nativeKey().apply(OpenSsl::pkeyTypeName))) {
        throw new InvalidKeyException("not a " + String.join(" / ", keyTypes) + " key");
      }
      return key;
    }

    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new InvalidKeyException("key " + key.getClass().getName() + " has no encoding");
    }
    try {
      return (key instanceof PrivateKey)
          ? engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded))
          : engineGeneratePublic(new X509EncodedKeySpec(encoded));
    } catch (InvalidKeySpecException e) {
      throw new InvalidKeyException(e.getMessage(), e);
    }
  }

  private static OsslCurves.Curve curve(ECParameterSpec params)
      throws InvalidKeySpecException {
    try {
      return OsslCurves.of(params);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeySpecException(e.getMessage(), e);
    }
  }

  private static String xdhType(AlgorithmParameterSpec params)
      throws InvalidKeySpecException {
    String name = (params instanceof NamedParameterSpec n)
        ? n.getName().toUpperCase(Locale.ROOT) : "";
    if (name.equals("X25519") || name.equals("X448")) {
      return name;
    }
    throw new InvalidKeySpecException("unsupported XDH parameters " + params);
  }

  private static String edType(NamedParameterSpec params) throws InvalidKeySpecException {
    String name = params.getName().toUpperCase(Locale.ROOT);
    if (name.equals("ED25519") || name.equals("ED448")) {
      return name;
    }
    throw new InvalidKeySpecException("unsupported EdDSA parameters " + params.getName());
  }

  /** Returns the little-endian encoding of the value with the length. */
  static byte[] toLittleEndian(BigInteger v, int len) {
    byte[] be = v.toByteArray();
    byte[] le = new byte[len];
    for (int i = 0; i < Math.min(len, be.length); i++) {
      le[i] = be[be.length - 1 - i];
    }
    return le;
  }

  /** RFC 8032: y little-endian, the most significant bit of the last byte is the x parity. */
  private static byte[] encodeEdPoint(String type, EdECPoint point) {
    byte[] raw = toLittleEndian(point.getY(), "ED25519".equals(type) ? 32 : 57);
    if (point.isXOdd()) {
      raw[raw.length - 1] |= (byte) 0x80;
    }
    return raw;
  }

}
