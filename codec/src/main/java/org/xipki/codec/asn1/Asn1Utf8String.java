// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.nio.charset.StandardCharsets;

/**
 * UTF8 String
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Utf8String extends AbstractAsn1String {

  private final byte[] octets;

  public static Asn1Utf8String fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Utf8String) Asn1Util.readAsn1Object(Asn1Tags.UTF8_STRING, encoded);
  }

  public Asn1Utf8String(String value) {
    super(PrimitiveType.UTF8_STRING, value);
    this.octets = value.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }
}
