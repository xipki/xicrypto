// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF IA5 STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IA5StringSeq extends AbstractSeq<Asn1IA5String> {

  public IA5StringSeq(int min, Asn1IA5String... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public IA5StringSeq(int min, List<Asn1IA5String> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public IA5StringSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1IA5String newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getIA5StringAt(index);
  }

  public static IA5StringSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new IA5StringSeq(min, toIA5Strings(seq));
  }

  static Asn1IA5String[] toIA5Strings(String... entries) {
    if (entries == null) {
      return null;
    }

    Args.noNullElements(entries, "entries");
    Asn1IA5String[] r = new Asn1IA5String[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1IA5String(entries[i]);
    }

    return r;
  }

  static Asn1IA5String[] toIA5Strings(AbstractAsn1Collection seq) throws CodecException {
    int size = seq.size();
    Asn1IA5String[] r = new Asn1IA5String[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getIA5StringAt(i);
    }
    return r;
  }

}
