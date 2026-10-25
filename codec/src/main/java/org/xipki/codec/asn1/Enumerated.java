// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class Enumerated extends Asn1Encodable {

  protected final Asn1Enumerated enumerated;

  public Enumerated(int value) {
    this.enumerated = new Asn1Enumerated(value);
  }

  protected Enumerated(Asn1Enumerated enumerated) {
    this.enumerated = Args.notNull(enumerated, "enumerate");
  }

  public Asn1Enumerated getEnumerated() {
    return enumerated;
  }

  public int getValue() {
    return enumerated.getValue();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return enumerated;
  }

  @Override
  protected abstract String getTitle();

  public abstract String getEnumeratedName();

  @Override
  public String toString() {
    return getTitle() + ": " + getEnumeratedName();
  }

}
