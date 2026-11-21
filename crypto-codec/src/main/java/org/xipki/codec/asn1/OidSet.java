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
public class OidSet extends AbstractSet<Asn1Oid> {

  public OidSet(int min, Asn1Oid... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OidSet(int min, List<Asn1Oid> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public OidSet(int min, Asn1Set set) throws CodecException {
    super(min, Integer.MAX_VALUE, set);
  }

  @Override
  protected Asn1Oid newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getOidAt(index);
  }

  public static OidSet fromAsn1(int min, Asn1Set set) throws CodecException {
    Args.setSizeMin(set, "set", min);
    return new OidSet(min, set);
  }

}
