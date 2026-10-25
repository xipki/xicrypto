// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.util.Arrays;
import java.util.List;

/**
 * SET or SET OF
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Set extends AbstractAsn1Collection {

  public static Asn1Set fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Set) Asn1Util.readAsn1Object(Asn1Tags.SET, encoded);
  }

  public Asn1Set(List<? extends Asn1Encodable> values) {
    super(values);
  }

  public Asn1Set(Asn1Encodable... values) {
    super(values);
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.SET;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.SET;
  }

  /**
   * The order of the elements in a SET is not significant: two SETs are equal if they contain
   * the same elements, i.e. if their DER encodings, in which the elements are sorted, are equal.
   */
  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Set)) {
      return false;
    }

    Asn1Set b = (Asn1Set) obj;
    if (size() != b.size()) {
      return false;
    }

    return Arrays.equals(getEncoded(Asn1Encoding.DER), b.getEncoded(Asn1Encoding.DER));
  }

  @Override
  public int hashCode() {
    // independent of the order of the elements
    int hash = getTagNo();
    for (int i = 0; i < size(); i++) {
      hash += getObjectAt(i).hashCode();
    }
    return hash;
  }

}
