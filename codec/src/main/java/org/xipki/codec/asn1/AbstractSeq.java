// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..max) OF T
 * </pre>
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractSeq<T extends Asn1Encodable> extends AbstractCollection<T> {

  @SafeVarargs
  protected AbstractSeq(int min, int max, T... entries) {
    super(false, min, max, entries);
  }

  protected AbstractSeq(int min, int max, List<T> entries) {
    super(false, min, max, entries);
  }

  protected AbstractSeq(int min, int max, Asn1Sequence seq) throws CodecException {
    super(false, min, max, seq);
  }

}
