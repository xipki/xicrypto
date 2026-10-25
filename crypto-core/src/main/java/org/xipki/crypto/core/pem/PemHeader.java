// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.pem;

import java.util.Objects;

/**
 * Class representing a PEM header (name, value) pair.
 *
 * @author Lijun Liao (xipki)
 */
public class PemHeader {

  private final String name;
  private final String value;

  /**
   * Base constructor.
   *
   * @param name name of the header property.
   * @param value value of the header property.
   */
  public PemHeader(String name, String value) {
    this.name = name;
    this.value = value;
  }

  public String getName() {
    return name;
  }

  public String getValue() {
    return value;
  }

  @Override
  public int hashCode() {
    return getHashCode(this.name) + 31 * getHashCode(this.value);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (!(o instanceof PemHeader)) {
      return false;
    }

    PemHeader other = (PemHeader)o;
    return Objects.equals(this.name, other.name) && Objects.equals(this.value, other.value);
  }

  private int getHashCode(String s) {
    if (s == null) {
      return 1;
    }

    return s.hashCode();
  }

}
