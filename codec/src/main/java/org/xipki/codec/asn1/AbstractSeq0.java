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
public abstract class AbstractSeq0<T extends Asn1Encodable> extends AbstractSeq<T> {

  @SafeVarargs
  protected AbstractSeq0(T... entries) {
    super(0, Integer.MAX_VALUE, entries);
  }

  protected AbstractSeq0(List<T> entries) {
    super(0, Integer.MAX_VALUE, entries);
  }

  protected AbstractSeq0(Asn1Sequence seq) throws CodecException {
    super(0, Integer.MAX_VALUE, seq);
  }

}
