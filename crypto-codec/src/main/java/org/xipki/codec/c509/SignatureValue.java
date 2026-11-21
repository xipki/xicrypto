// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.c509;

import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodable;

/**
 * Base type for signature value encodings used by C509 certificates, CRLs, CSRs, and OCSP messages.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class SignatureValue extends CborEncodable {

  public static SignatureValue read(int signatureAlgorithm, CborDecoder decoder)
      throws CodecException {
    if (ConstSignatureAlgorithm.isStaticDhSignature(signatureAlgorithm)) {
      return C509DhSigStaticSignatureValue.read(decoder);
    } else {
      return BytesSignatureValue.read(decoder);
    }
  }

  public static SignatureValue convertSignatureValue(int signatureAlgorithm, byte[] signatureValue)
      throws CodecException {
    if (ConstSignatureAlgorithm.isStaticDhSignature(signatureAlgorithm)) {
      return C509DhSigStaticSignatureValue.read(new ByteArrayCborDecoder(signatureValue));
    } else {
      return new BytesSignatureValue(signatureValue);
    }
  }

}
