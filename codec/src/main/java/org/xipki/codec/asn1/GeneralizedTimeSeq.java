// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF GENERALIZED TIME
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class GeneralizedTimeSeq extends AbstractSeq<Asn1GeneralizedTime> {

  public GeneralizedTimeSeq(int min, Asn1GeneralizedTime... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public GeneralizedTimeSeq(int min, List<Asn1GeneralizedTime> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public GeneralizedTimeSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1GeneralizedTime newType(AbstractAsn1Collection coll, int index)
      throws CodecException {
    return coll.getGeneralizedTimeAt(index);
  }

  public static GeneralizedTimeSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new GeneralizedTimeSeq(min, toGeneralizedTimes(seq));
  }

  static Asn1GeneralizedTime[] toGeneralizedTimes(AbstractAsn1Collection seq)
      throws CodecException {
    int size = seq.size();
    Asn1GeneralizedTime[] r = new Asn1GeneralizedTime[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getGeneralizedTimeAt(i);
    }
    return r;
  }

}
