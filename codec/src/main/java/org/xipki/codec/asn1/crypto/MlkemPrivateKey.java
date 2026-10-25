// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.exception.CodecException;

/**
 * ML-KEM Private key
 *
 * @author Lijun Liao (xipki)
 */
public class MlkemPrivateKey extends PqcPrivateKey {

  public MlkemPrivateKey(byte[] seed, byte[] expandedKey) {
    super(seed, expandedKey);
  }

  public MlkemPrivateKey(Asn1OctetString seed, Asn1OctetString expandedKey) {
    super(seed, expandedKey);
  }

  private MlkemPrivateKey(Asn1Primitive asn1) throws CodecException {
    super(asn1);
  }

  public static MlkemPrivateKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Util.readAsn1Object(encoded));
  }

  public static MlkemPrivateKey fromAsn1(Asn1Primitive asn1) throws CodecException {
    return new MlkemPrivateKey(asn1);
  }

  @Override
  protected boolean isSeedLengthValid(int seedLength) {
    return seedLength == 64;
  }

  @Override
  protected boolean isExpandedKeyLengthValid(int expandedKeyLength) {
    return expandedKeyLength == 1632 || expandedKeyLength == 2400 || expandedKeyLength == 3168;
  }

}
