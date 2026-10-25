// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SET SIZE(min..MAX) OF T
 * </pre>
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractSet<T extends Asn1Encodable> extends AbstractCollection<T> {

  @SafeVarargs
  protected AbstractSet(int min, int max, T... entries) {
    super(true, min, max, entries);
  }

  protected AbstractSet(int min, int max, List<T> entries) {
    super(true, min, max, entries);
  }

  protected AbstractSet(int min, int max, Asn1Set set) throws CodecException {
    super(true, min, max, set);
  }

}
