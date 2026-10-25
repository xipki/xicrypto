// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.exception.CodecException;

import java.io.IOException;

/**
 * Cbor Encodable interface.
 *
 * @author Lijun Liao (xipki)
 */
public interface CborEncodable {

  void encode(CborEncoder encoder) throws CodecException;

  default byte[] getEncoded() throws CodecException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      encode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new CodecException("IO error: " + e.getMessage());
    }
  }

}
