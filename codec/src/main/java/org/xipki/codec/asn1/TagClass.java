// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

/**
 * Enum for the tag class.
 *
 * @author Lijun Liao (xipki)
 */
public enum TagClass {

  universal(0x00),
  application(0x40),
  contextSpecific(0x80),
  _private(0xc0);

  private final int mask;

  TagClass(int mask) {
    this.mask = mask;
  }

  public int mask() {
    return mask;
  }

}
