// Copyright (c) 2024-2026 xipki. All rights reserved.
// License LICENSE-XXXX

package org.xipki.codec.c509;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * 3.1.  Message fields
 * <p>
 *    ...
 * <p>
 *  * subjectPublicKeyInfo.  The 'AlgorithmIdentifier' field including
 *    parameters is encoded as the CBOR int 'subjectPublicKeyAlgorithm'
 *    (see Section 9.11) or as an array with an unwrapped CBOR OID tag
 *    [RFC9090] optionally followed by the parameters encoded as a CBOR
 *    byte string.  In general, the 'subjectPublicKey' BIT STRING value
 *    field is encoded as a CBOR byte string.  This specification
 *    assumes the BIT STRING has zero unused bits and the unused bits
 *    byte is omitted.  For rsaEncryption and id-ecPublicKey, the
 *    encoding of subjectPublicKey is further optimized as described in
 *    Section 3.2.
 *
 * @author Lijun Liao (xipki)
 */
public class C509BytesSubjectPublicKey extends C509SubjectPublicKey {

  private final byte[] publicKeyData;

  public C509BytesSubjectPublicKey(int algorithm, byte[] publicKeyData) {
    super(algorithm);
    this.publicKeyData = Args.notNull(publicKeyData, "publicKeyData");
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeInt(algorithm);
    encoder.writeByteString(publicKeyData);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return null;
  }

  public static C509BytesSubjectPublicKey decode(CborDecoder decoder, int algorithm)
      throws CodecException {
    CborType mt = decoder.peekType();
    if (mt.isByteString()) {
      return new C509BytesSubjectPublicKey(algorithm, decoder.readByteString());
    } else {
      throw new CodecException("invalid BytesSubjectPublicKey");
    }
  }

  public byte[] publicKeyData() {
    return publicKeyData;
  }

  @Override
  public void valueToString(StringBuilder buf, int indentLevel) {
    ToStringUtil.appendIndent(buf, indentLevel, "Raw public key\n");
    ToStringUtil.appendHex(buf, indentLevel + 1, publicKeyData);
  }

  @Override
  public SubjectPublicKeyInfo toX509SubjectPublicKey() {
    return new SubjectPublicKeyInfo(x509AlgId(), publicKeyData);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }

    if (!(obj instanceof C509BytesSubjectPublicKey)) {
      return false;
    }

    C509BytesSubjectPublicKey b = (C509BytesSubjectPublicKey) obj;

    return algorithm == b.algorithm && Arrays.equals(publicKeyData, b.publicKeyData);
  }

}
