// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

/**
 * ASN.1 IA5String is essentially 7-bit ASCII.
 * It allows exactly these characters:
 * <ul>
 * <li>Letters: A–Z, a–z</li>
 * <li>Digits: 0–9</li>
 * <li>Punctuation / symbols: all ASCII characters from 0x20–0x7E</li>
 * <li>Control characters: NUL through US (0x00–0x1F) and DEL (0x7F)
 *   are technically part of the IA5 repertoire, although they are generally
 *   inappropriate for textual fields.</li>
 * </ul>
 * So the IA5 character repertoire is all 128 ASCII characters (0x00–0x7F).
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1IA5String extends AbstractAsn1String {

  public static Asn1IA5String fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1IA5String) Asn1Util.readAsn1Object(Asn1Tags.IA5_STRING, encoded);
  }

  public Asn1IA5String(String value) {
    super(PrimitiveType.IA5_STRING, value);

    for (char v : value.toCharArray()) {
      if (v <= 127) {
        continue;
      }

      throw new IllegalArgumentException("invalid IA5String '" + value + "'");
    }
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return value.length();
  }

}
