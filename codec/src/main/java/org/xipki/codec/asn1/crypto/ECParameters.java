// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * <pre>
 *    ECParameters ::= CHOICE {
 *      namedCurve         OBJECT IDENTIFIER
 *      -- implicitCurve   NULL
 *      -- specifiedCurve  SpecifiedECDomain
 *    }
 *      -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
 *      -- Details for SpecifiedECDomain can be found in [X9.62].
 *      -- Any future additions to this CHOICE should be coordinated
 *      -- with ANSI X9.
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class ECParameters extends Asn1Encodable {

  private final Asn1Oid namedCurve;

  private ECParameters(Asn1Oid namedCurve) {
    this.namedCurve = namedCurve;
  }

  public static ECParameters fromAsn1(Asn1Primitive asn1) throws CodecException {
    if (asn1 instanceof Asn1Oid) {
      return new ECParameters((Asn1Oid) asn1);
    } else {
      throw new CodecException("invalid ASN.1 type");
    }
  }

  public static ECParameters ofNamedCurve(Asn1Oid namedCurve) {
    return new ECParameters(Args.notNull(namedCurve, "namedCurve"));
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  public Asn1Oid getNamedCurve() {
    return namedCurve;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return namedCurve;
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return namedCurve.toString(buf, indentLevel);
  }

}
