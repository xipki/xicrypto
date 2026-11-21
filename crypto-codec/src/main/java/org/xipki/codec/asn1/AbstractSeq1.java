// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(1..MAX) OF T
 * </pre>
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractSeq1<T extends Asn1Encodable> extends AbstractSeq<T> {

  @SafeVarargs
  protected AbstractSeq1(T... entries) {
    super(1, Integer.MAX_VALUE, entries);
  }

  protected AbstractSeq1(List<T> entries) {
    super(1, Integer.MAX_VALUE, entries);
  }

  protected AbstractSeq1(Asn1Sequence seq) throws CodecException {
    super(0, Integer.MAX_VALUE, seq);
  }

}
