// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SET SIZE(min..MAX) OF PRINTABLE STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class PrintableStringSet extends AbstractSet<Asn1PrintableString> {

  public PrintableStringSet(int min, Asn1PrintableString... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public PrintableStringSet(int min, List<Asn1PrintableString> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public PrintableStringSet(int min, String... entries) {
    super(min, Integer.MAX_VALUE, PrintableStringSeq.toPrintableStrings(entries));
  }

  public PrintableStringSet(int min, Asn1Set set) throws CodecException {
    super(min, Integer.MAX_VALUE, set);
  }

  @Override
  protected Asn1PrintableString newType(AbstractAsn1Collection coll, int index)
      throws CodecException {
    return coll.getPrintableStringAt(index);
  }

  public static PrintableStringSet fromAsn1(int min, Asn1Set set) throws CodecException {
    Args.setSizeMin(set, "set", min);
    return new PrintableStringSet(min, PrintableStringSeq.toPrintableStrings(set));
  }

}
