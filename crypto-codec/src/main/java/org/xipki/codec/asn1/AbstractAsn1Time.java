// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.time.Instant;

/**
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractAsn1Time extends Asn1Primitive{

  public abstract Instant getTime();

  public abstract String getText();

  public static AbstractAsn1Time fromEncoded(byte[] encoded) throws CodecException {
    Args.notEmptyBytes(encoded, "encoded");
    int tag = encoded[0] & 0xff;
    if (tag == Asn1Tags.UTC_TIME) {
      return Asn1UtcTime.fromEncoded(encoded);
    } else if (tag == Asn1Tags.GENERALIZED_TIME) {
      return Asn1GeneralizedTime.fromEncoded(encoded);
    } else {
      throw new CodecException("malformed ASN.1 time");
    }
  }

}
