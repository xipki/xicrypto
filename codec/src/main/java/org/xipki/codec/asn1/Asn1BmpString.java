// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

/**
 * ASN.1 BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * </p>
 * @author Lijun Liao (xipki)
 */
public class Asn1BmpString extends AbstractAsn1String {

  public static Asn1BmpString fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1BmpString) Asn1Util.readAsn1Object(Asn1Tags.BMP_STRING, encoded);
  }

  public Asn1BmpString(String value) {
    super(PrimitiveType.BMP_STRING, value);
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return 2 * value.length();
  }

  byte[] contentToByteArray() {
    char[] cs = value.toCharArray();
    byte[] r = new byte[2 * cs.length];

    int i = 0;
    for (char c : cs) {
      r[i++] = (byte) (c >> 8);
      r[i++] = (byte) c;
    }
    return r;
  }

}
