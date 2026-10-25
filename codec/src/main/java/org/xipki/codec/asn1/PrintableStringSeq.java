// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF PRINTABLE STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PrintableStringSeq extends AbstractSeq<Asn1PrintableString> {

  public PrintableStringSeq(int min, Asn1PrintableString... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public PrintableStringSeq(int min, List<Asn1PrintableString> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public PrintableStringSeq(int min, String... entries) {
    super(min, Integer.MAX_VALUE, toPrintableStrings(entries));
  }

  public PrintableStringSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1PrintableString newType(AbstractAsn1Collection coll, int index)
      throws CodecException {
    return coll.getPrintableStringAt(index);
  }

  public static PrintableStringSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new PrintableStringSeq(min, toPrintableStrings(seq));
  }

  static Asn1PrintableString[] toPrintableStrings(String... entries) {
    if (entries == null) {
      return null;
    }

    Args.noNullElements(entries, "entries");
    Asn1PrintableString[] r = new Asn1PrintableString[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1PrintableString(entries[i]);
    }

    return r;
  }

  static Asn1PrintableString[] toPrintableStrings(AbstractAsn1Collection seq)
      throws CodecException {
    int size = seq.size();
    Asn1PrintableString[] r = new Asn1PrintableString[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getPrintableStringAt(i);
    }
    return r;
  }

}
