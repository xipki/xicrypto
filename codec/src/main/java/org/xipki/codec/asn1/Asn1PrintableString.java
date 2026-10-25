// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

/**
 * PRINTABLE STRING
 * <p>
 * Allowed chars:
 * <pre>
 *        A, B, ..., Z
 *         a, b, ..., z
 *         0, 1, ..., 9
 *     (space) ' ( ) + , - . / : = ?
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1PrintableString extends AbstractAsn1String {

  public static Asn1PrintableString fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1PrintableString) Asn1Util.readAsn1Object(Asn1Tags.PRINTABLE_STRING, encoded);
  }

  public Asn1PrintableString(String value) {
    this(value, true);
  }

  /**
   * Constructor.
   * @param value the string value.
   * @param strict whether to check the PrintableString character set. The decoder
   *               uses false, since characters like '*', '@' and '_' are
   *               often found in the PrintableString of real-world certificates.
   */
  Asn1PrintableString(String value, boolean strict) {
    super(PrimitiveType.PRINTABLE_STRING, value);
    if (!strict) {
      return;
    }

    for (char v : value.toCharArray()) {
      if ((v >= 'A' && v <= 'Z') ||
          (v >= 'a' && v <= 'z') ||
          (v >= '0' && v <= '9') ||
          (v == ' ' || v == '\'' || v == '(' || v == ')' ||
              v == '+' || v == ',' || v == '-' || v == '.' ||
              v == '/' || v == ':' || v == '=' || v == '?')) {
        continue;
      }

      throw new IllegalArgumentException("invalid PrintableString '" + value + "': '" + v + "'");
    }
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return value.length();
  }

}
