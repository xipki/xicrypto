// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

/**
 * The ASN.1 Tags.
 *
 * @author Lijun Liao (xipki)
 */
public interface Asn1Tags {
  // 0x00: Reserved for use by the encoding rules
  int BOOLEAN             = 0x01;
  int INTEGER             = 0x02;
  int BIT_STRING          = 0x03;
  int OCTET_STRING        = 0x04;
  int NULL                = 0x05;
  int OBJECT_IDENTIFIER   = 0x06;
  int OBJECT_DESCRIPTOR   = 0x07;
  int EXTERNAL            = 0x08;
  int REAL                = 0x09;
  int ENUMERATED          = 0x0a; // decimal 10
  int EMBEDDED_PDV        = 0x0b; // decimal 11
  int UTF8_STRING         = 0x0c; // decimal 12
  int RELATIVE_OID        = 0x0d; // decimal 13
  int TIME                = 0x0e;
  // 0x0f: Reserved for future editions of this Recommendation | International Standard
  int SEQUENCE            = 0x10; // decimal 16
  int SET                 = 0x11; // decimal 17
  int NUMERIC_STRING      = 0x12; // decimal 18
  int PRINTABLE_STRING    = 0x13; // decimal 19
  int T61_STRING          = 0x14; // decimal 20
  int VIDEOTEX_STRING     = 0x15; // decimal 21
  int IA5_STRING          = 0x16; // decimal 22
  int UTC_TIME            = 0x17; // decimal 23
  int GENERALIZED_TIME    = 0x18; // decimal 24
  int GRAPHIC_STRING      = 0x19; // decimal 25
  int VISIBLE_STRING      = 0x1a; // decimal 26
  int GENERAL_STRING      = 0x1b; // decimal 27
  int UNIVERSAL_STRING    = 0x1c; // decimal 28
  int UNRESTRICTED_STRING = 0x1d; // decimal 29
  int BMP_STRING          = 0x1e; // decimal 30
  int DATE                = 0x1f;
  int TIME_OF_DAY         = 0x20;
  int DATE_TIME           = 0x21;
  int DURATION            = 0x22;
  int OBJECT_IDENTIFIER_IRI = 0x23;
  int RELATIVE_OID_IRI    = 0x24;
  // 0x25..: Reserved for addenda to this Recommendation | International Standard

  int CONSTRUCTED         = 0x20; // decimal 32

  int UNIVERSAL           = 0x00; // decimal 32
  int APPLICATION         = 0x40; // decimal 64
  int CONTEXT_SPECIFIC    = 0x80; // decimal 128
  int PRIVATE             = 0xC0; // decimal 192

  int FLAGS               = 0xE0;
}
