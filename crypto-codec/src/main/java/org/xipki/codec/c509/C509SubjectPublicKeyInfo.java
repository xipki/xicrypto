// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;

import java.security.spec.InvalidKeySpecException;

/**
 * A C509 public key independent of a certificate, the counterpart of the X.509
 * SubjectPublicKeyInfo (draft-liao-cose-c509-additions-00, Section 3):
 *
 * <pre>
 * C509SubjectPublicKeyInfo = [
 *   subjectPublicKeyAlgorithm : AlgorithmIdentifier,
 *   subjectPublicKey          : Defined
 * ]
 * </pre>
 *
 * The two fields have the same encoding as in TBSCertificate, see {@link C509SubjectPublicKey}.
 *
 * @author Lijun Liao (xipki)
 */
public class C509SubjectPublicKeyInfo extends CborEncodable {

  private final C509SubjectPublicKey publicKeyInfo;

  public C509SubjectPublicKeyInfo(C509SubjectPublicKey publicKeyInfo) {
    this.publicKeyInfo = Args.notNull(publicKeyInfo, "publicKeyInfo");
  }

  public C509SubjectPublicKey publicKeyInfo() {
    return publicKeyInfo;
  }

  /**
   * Converts an X.509 SubjectPublicKeyInfo.
   *
   * @throws InvalidKeySpecException if the key algorithm is not supported.
   */
  public static C509SubjectPublicKeyInfo fromSubjectPublicKeyInfo(SubjectPublicKeyInfo x509)
      throws InvalidKeySpecException {
    return new C509SubjectPublicKeyInfo(C509SubjectPublicKey.fromSubjectPublicKeyInfo(x509));
  }

  public SubjectPublicKeyInfo toX509SubjectPublicKey() {
    return publicKeyInfo.toX509SubjectPublicKey();
  }

  @Override
  public void encode(CborEncoder encoder) throws CodecException {
    encoder.writeArrayStart(2);
    publicKeyInfo.encode(encoder);
  }

  public static C509SubjectPublicKeyInfo parse(byte[] encoded) throws CodecException {
    try (CborDecoder decoder = new ByteArrayCborDecoder(encoded)) {
      return read(decoder);
    }
  }

  public static C509SubjectPublicKeyInfo read(CborDecoder decoder) throws CodecException {
    decoder.readArrayLength(2);
    return new C509SubjectPublicKeyInfo(C509SubjectPublicKey.read(decoder));
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    publicKeyInfo.toString(buf, indentLevel);
    return buf;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    return obj instanceof C509SubjectPublicKeyInfo
        && publicKeyInfo.equals(((C509SubjectPublicKeyInfo) obj).publicKeyInfo);
  }

  @Override
  public int hashCode() {
    return publicKeyInfo.hashCode();
  }

}
