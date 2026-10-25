// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF OCTET STRING
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OctetStringSeq extends AbstractSeq<Asn1OctetString> {

  public OctetStringSeq(int min, Asn1OctetString... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OctetStringSeq(int min, byte[]... entries) {
    super(min, Integer.MAX_VALUE, toOctetStrings(entries));
  }

  public OctetStringSeq(int min, List<Asn1OctetString> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OctetStringSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1OctetString newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getOctetStringAt(index);
  }

  public static OctetStringSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "se1", min);
    return new OctetStringSeq(min, toOctetStrings(seq));
  }

  static Asn1OctetString[] toOctetStrings(byte[]... entries) {
    if (entries == null) {
      return null;
    }

    Args.noNullElements(entries, "entries");
    Asn1OctetString[] r = new Asn1OctetString[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1OctetString(entries[i]);
    }

    return r;
  }

  static Asn1OctetString[] toOctetStrings(AbstractAsn1Collection seq) throws CodecException {
    int size = seq.size();
    Asn1OctetString[] r = new Asn1OctetString[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getOctetStringAt(i);
    }
    return r;
  }

}
