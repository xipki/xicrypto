// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.exception.CodecException;

/**
 * ML-DSA Private key
 *
 * @author Lijun Liao (xipki)
 */
public class MldsaPrivateKey extends PqcPrivateKey {

  public MldsaPrivateKey(byte[] seed, byte[] expandedKey) {
    super(seed, expandedKey);
  }

  public MldsaPrivateKey(Asn1OctetString seed, Asn1OctetString expandedKey) {
    super(seed, expandedKey);
  }

  private MldsaPrivateKey(Asn1Primitive asn1) throws CodecException {
    super(asn1);
  }

  public static MldsaPrivateKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Util.readAsn1Object(encoded));
  }

  public static MldsaPrivateKey fromAsn1(Asn1Primitive asn1) throws CodecException {
    return new MldsaPrivateKey(asn1);
  }

  @Override
  protected boolean isSeedLengthValid(int seedLength) {
    return seedLength == 32;
  }

  @Override
  protected boolean isExpandedKeyLengthValid(int expandedKeyLength) {
    return expandedKeyLength == 2560 || expandedKeyLength == 4032 || expandedKeyLength == 4896;
  }

}
