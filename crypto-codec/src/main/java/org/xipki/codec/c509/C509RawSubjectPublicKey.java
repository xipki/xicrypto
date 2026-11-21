// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborMap;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * The public key of an algorithm that is not registered in {@link ConstPublicKeyAlgorithm},
 * whose value is not a byte string (for a byte string see {@link C509BytesSubjectPublicKey}).
 * The value is kept in its original encoding, see {@link CborEncodedItem}.
 * <p>
 * Such a key has no X.509 representation and cannot be converted to a JCA key.
 *
 * @author Lijun Liao (xipki)
 */
public class C509RawSubjectPublicKey extends C509SubjectPublicKey {

  private final CborEncodedItem value;

  /**
   * @param algorithm an algorithm not registered in {@link ConstPublicKeyAlgorithm}.
   * @param value     the value, neither a byte string nor null.
   * @throws IllegalArgumentException if the algorithm is registered, or the value is a byte
   *         string or null.
   */
  public C509RawSubjectPublicKey(int algorithm, CborEncodedItem value) {
    super(algorithm);
    if (ConstPublicKeyAlgorithm.isRegistered(algorithm)) {
      throw new IllegalArgumentException("algorithm "
          + ConstPublicKeyAlgorithm.describe(algorithm) + " is registered");
    }
    if (value == null || value.type().isNull() || value.type().isByteString()) {
      throw new IllegalArgumentException("value must not be null or a byte string, use "
          + C509BytesSubjectPublicKey.class.getSimpleName() + " for a byte string");
    }
    this.value = value;
  }

  /**
   * Creates the key from generic CBOR data, encoded deterministically, see
   * {@link CborMap#deepSorted(Object)}.
   *
   * @param algorithm an algorithm not registered in {@link ConstPublicKeyAlgorithm}.
   * @param value     the value: generic CBOR data, see {@link CborDecoder#readNext()}, but no
   *                  byte string.
   * @throws IllegalArgumentException if the algorithm is registered, the value is a byte string
   *         or null, or cannot be encoded.
   */
  public C509RawSubjectPublicKey(int algorithm, Object value) {
    this(algorithm, toEncodedItem(value));
  }

  private static CborEncodedItem toEncodedItem(Object value) {
    if (value == null || value instanceof byte[]) {
      throw new IllegalArgumentException("value must not be null or a byte string, use "
          + C509BytesSubjectPublicKey.class.getSimpleName() + " for a byte string");
    }

    return CborEncodedItem.ofData(value);
  }

  /** The value in its original encoding. */
  public CborEncodedItem value() {
    return value;
  }

  public static C509RawSubjectPublicKey read(CborDecoder decoder, int algorithm)
      throws CodecException {
    if (decoder.peekType().isByteString()) {
      throw new CodecException("value of the public key is a byte string");
    }

    try {
      return new C509RawSubjectPublicKey(algorithm, decoder.readEncodedItem());
    } catch (IllegalArgumentException e) {
      throw new CodecException(e.getMessage(), e);
    }
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeInt(algorithm);
    encoder.writeObject(value);
  }

  @Override
  protected void valueToString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "Raw public key: ")
        .append(value.toDiagnostic()).append("\n");
  }

  /**
   * @throws UnsupportedOperationException always, the algorithm has no X.509 representation.
   */
  @Override
  public SubjectPublicKeyInfo toX509SubjectPublicKey() {
    throw new UnsupportedOperationException(
        "public key algorithm " + algorithm + " has no X.509 representation");
  }

  /**
   * @throws InvalidKeySpecException always, the algorithm is not registered.
   */
  @Override
  public synchronized PublicKey publicKey() throws InvalidKeySpecException {
    throw new InvalidKeySpecException("unknown key algorithm " + algorithm);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509RawSubjectPublicKey)) {
      return false;
    }

    C509RawSubjectPublicKey b = (C509RawSubjectPublicKey) obj;
    return algorithm == b.algorithm && value.equals(b.value);
  }

  @Override
  public int hashCode() {
    return 31 * algorithm + value.hashCode();
  }

}
