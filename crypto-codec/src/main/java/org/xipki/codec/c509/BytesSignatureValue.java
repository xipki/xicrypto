// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * Byte-string signature value used by ordinary C509 signature algorithms
 * (draft-ietf-cose-cbor-encoded-cert-21, Sections 3.1.12 and 3.2.2). ECDSA
 * signatures are encoded as in Section 2.1 of RFC 9053.
 *
 * @author Lijun Liao (xipki)
 */
public class BytesSignatureValue extends SignatureValue {

  private final byte[] value;

  public BytesSignatureValue(byte[] value) {
    this.value = Args.notNull(value, "value");
  }

  public byte[] value() {
    return Arrays.copyOf(value, value.length);
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeByteString(value);
  }

  public static BytesSignatureValue read(CborDecoder decoder) throws CodecException {
    return new BytesSignatureValue(decoder.readByteString());
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return ToStringUtil.toString(value, buf, indentLevel);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof BytesSignatureValue)) {
      return false;
    }

    return Arrays.equals(value, ((BytesSignatureValue) obj).value);
  }
  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }


}
