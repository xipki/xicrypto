// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(0..MAX) OF T
 * </pre>
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractSet0<T extends Asn1Encodable> extends AbstractSet<T> {

  @SafeVarargs
  protected AbstractSet0(T... entries) {
    super(0, Integer.MAX_VALUE, entries);
  }

  protected AbstractSet0(List<T> entries) {
    super(0, Integer.MAX_VALUE, entries);
  }

  protected AbstractSet0(Asn1Set set) throws CodecException {
    super(0, Integer.MAX_VALUE, set);
  }

}
