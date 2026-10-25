// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

/**
 * Enum for the primitive type.
 *
 * @author Lijun Liao (xipki)
 */
public enum PrimitiveType {

  BOOLEAN,
  INTEGER,
  NULL,
  ENUMERATED,
  OID,
  RELATIVE_OID,
  SEQUENCE,
  SET,
  BIT_STRING,
  OCTET_STRING,
  UTF8_STRING,
  PRINTABLE_STRING,
  IA5_STRING,
  BMP_STRING,
  VISIBLE_STRING,
  UTC_TIME,
  GENERALIZED_TIME,
  TAGGED_OBJECT,
  ANY

}
