// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import org.xipki.codec.asn1.crypto.RSAPublicKey;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * 3.2.1.  Encoding of subjectPublicKey
 * <p>
 *    For RSA public keys (rsaEncryption), the SEQUENCE and INTEGER type
 *    and length fields are omitted and the two INTEGER value fields
 *    (modulus, exponent) are encoded as an array of two unwrapped CBOR
 *    unsigned bignum (~biguint), i.e. [ modulus : ~biguint, exponent :
 *    ~biguint ].  If the exponent is 65537, the array and the exponent is
 *    omitted and subjectPublicKey consist of only the modulus encoded as
 *    an unwrapped CBOR unsigned bignum (~biguint).
 *
 * @author Lijun Liao (xipki)
 */
public class C509RSASubjectPublicKey extends C509SubjectPublicKey {

  private final BigInteger publicExponent;

  private final BigInteger modulus;

  private PublicKey jceKey;

  public C509RSASubjectPublicKey(BigInteger modulus, BigInteger publicExponent) {
    super(ConstPublicKeyAlgorithm.rsaEncryption);
    this.publicExponent = Args.notNull(publicExponent, "publicExponent");
    this.modulus = Args.notNull(modulus, "modulus");
    if (modulus.compareTo(publicExponent) <= 0) {
      throw new IllegalArgumentException("RSA modulus is not bigger than public exponent");
    }

    if (publicExponent.signum() != 1) {
      throw new IllegalArgumentException("RSA public exponent is not positive");
    }

    if (modulus.signum() != 1) {
      throw new IllegalArgumentException("RSA modulus is not positive");
    }
  }

  public BigInteger publicExponent() {
    return publicExponent;
  }

  public BigInteger modulus() {
    return modulus;
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeInt(algorithm);
    encodeKeyOnly(encoder);
  }

  private void encodeKeyOnly(CborEncoder encoder) throws CodecException {
    boolean isF4 = publicExponent.equals(RSAKeyGenParameterSpec.F4);
    if (!isF4) {
      encoder.writeArrayStart(2);
    }
    encoder.writeUnwrappedBiguint(modulus);

    if (!isF4) {
      encoder.writeUnwrappedBiguint(publicExponent);
    }
  }

  public static C509RSASubjectPublicKey decode(CborDecoder decoder) throws CodecException {
    CborType mt = decoder.peekType();
    BigInteger modulus;
    BigInteger publicExponent;
    if (mt.isByteString()) {
      modulus = new BigInteger(1, decoder.readByteString());
      publicExponent = RSAKeyGenParameterSpec.F4;
    } else if (mt.isArray()) {
      decoder.readNullOrArrayLength(2);
      modulus = new BigInteger(1, decoder.readByteString());
      publicExponent = new BigInteger(1, decoder.readByteString());
    } else {
      throw new CodecException("invalid RSASubjectPublicKey");
    }

    return new C509RSASubjectPublicKey(modulus, publicExponent);
  }

  @Override
  public SubjectPublicKeyInfo toX509SubjectPublicKey() {
    RSAPublicKey rsaPk = new RSAPublicKey(modulus, publicExponent);
    return new SubjectPublicKeyInfo(x509AlgId(), rsaPk.getEncoded());
  }

  @Override
  public synchronized PublicKey publicKey() throws InvalidKeySpecException {
    if (jceKey == null) {
      try {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        jceKey = kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidKeySpecException("could not find KeyFactory for " +
            algorithm + ": " + ex.getMessage());
      }
    }
    return jceKey;
  }

  @Override
  protected void valueToString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "RSA public key\n");
    ToStringUtil.appendIndent(buf, indentLevel + 1, "modulus\n");
    byte[] bytes = modulus.toByteArray();
    ToStringUtil.appendHex(buf, indentLevel + 2,
        bytes[0] == 0x00 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);

    ToStringUtil.appendIndent(buf, indentLevel + 1, "public exponent\n");
    bytes = publicExponent.toByteArray();
    ToStringUtil.appendHex(buf, indentLevel + 2,
        bytes[0] == 0x00 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof C509RSASubjectPublicKey)) {
      return false;
    }

    C509RSASubjectPublicKey b = (C509RSASubjectPublicKey) obj;

    return Objects.equals(modulus, b.modulus)
        && Objects.equals(publicExponent, b.publicExponent);
  }

}
