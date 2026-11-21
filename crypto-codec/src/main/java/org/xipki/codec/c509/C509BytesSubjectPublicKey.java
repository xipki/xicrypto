// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.util.ToStringUtil;

import java.util.Objects;
import java.util.Arrays;

/**
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

  public static C509BytesSubjectPublicKey read(CborDecoder decoder, int algorithm)
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
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof C509BytesSubjectPublicKey)) {
      return false;
    }

    C509BytesSubjectPublicKey b = (C509BytesSubjectPublicKey) obj;

    return algorithm == b.algorithm && Arrays.equals(publicKeyData, b.publicKeyData);
  }
  @Override
  public int hashCode() {
    return Objects.hash(algorithm, Arrays.hashCode(publicKeyData));
  }


}
