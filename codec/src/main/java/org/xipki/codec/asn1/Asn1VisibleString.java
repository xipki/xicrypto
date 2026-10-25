// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

/**
 * ASN.1 VisibleString (X.680, also named ISO646String), universal tag 26.
 * It allows the printable characters of ISO 646 (7-bit ASCII) and the space, i.e. 0x20–0x7E,
 * no control characters.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1VisibleString extends AbstractAsn1String {

  public static Asn1VisibleString fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1VisibleString) Asn1Util.readAsn1Object(Asn1Tags.VISIBLE_STRING, encoded);
  }

  public Asn1VisibleString(String value) {
    this(value, true);
  }

  /**
   * Constructor.
   * @param value the string value.
   * @param strict whether to check the VisibleString character set. The decoder uses false
   *               and accepts all ASCII characters, like for the PrintableString.
   */
  Asn1VisibleString(String value, boolean strict) {
    super(PrimitiveType.VISIBLE_STRING, value);
    if (!strict) {
      return;
    }

    for (char v : value.toCharArray()) {
      if (v < 0x20 || v > 0x7E) {
        throw new IllegalArgumentException("invalid VisibleString '" + value + "'");
      }
    }
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return value.length();
  }

}
