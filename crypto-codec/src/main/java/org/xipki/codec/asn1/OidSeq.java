// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.List;

/**
 * <pre>
 * xxx ::= SET SIZE(min..MAX) OF OBJECT IDENTIFIER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class OidSeq extends AbstractSeq<Asn1Oid> {

  public OidSeq(int min, Asn1Oid... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OidSeq(int min, List<Asn1Oid> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OidSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  @Override
  protected Asn1Oid newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getOidAt(index);
  }

  public static OidSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new OidSeq(min, seq);
  }

}
