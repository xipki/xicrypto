// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF UTF8 STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Utf8StringSeq extends AbstractSeq<Asn1Utf8String> {

  public Utf8StringSeq(int min, Asn1Utf8String... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public Utf8StringSeq(int min, List<Asn1Utf8String> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public Utf8StringSeq(int min, String... entries) {
    super(min, Integer.MAX_VALUE, toUtf8Strings(entries));
  }

  public Utf8StringSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1Utf8String newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getUtf8StringAt(index);
  }

  public static Utf8StringSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new Utf8StringSeq(min, toUtf8Strings(seq));
  }

  static Asn1Utf8String[] toUtf8Strings(String... entries) {
    if (entries == null) {
      return null;
    }

    Args.noNullElements(entries, "entries");
    Asn1Utf8String[] r = new Asn1Utf8String[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1Utf8String(entries[i]);
    }

    return r;
  }

  static Asn1Utf8String[] toUtf8Strings(AbstractAsn1Collection seq) throws CodecException {
    int size = seq.size();
    Asn1Utf8String[] r = new Asn1Utf8String[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getUtf8StringAt(i);
    }
    return r;
  }

}
