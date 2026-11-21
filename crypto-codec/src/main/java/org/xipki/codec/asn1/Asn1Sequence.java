// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * SEQUENCE or SEQUENCE OF
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Sequence extends AbstractAsn1Collection {

  public static Asn1Sequence buildIgnoreNull(Asn1Encodable... elements) {
    List<Asn1Encodable> v = new ArrayList<>(elements.length);
    for (Asn1Encodable element : elements) {
      if (element != null) {
        v.add(element);
      }
    }
    return new Asn1Sequence(v);
  }

  public static Asn1Sequence fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Sequence) Asn1Util.readAsn1Object(Asn1Tags.SEQUENCE, encoded);
  }

  public static Asn1Sequence fromStream(InputStream is) throws CodecException {
    return (Asn1Sequence) Asn1Util.readAsn1Object(Asn1Tags.SEQUENCE, is);
  }

  public Asn1Sequence(List<? extends Asn1Encodable> values) {
    super(values);
  }

  public Asn1Sequence(Asn1Encodable... values) {
    super(values);
  }

  public Asn1Sequence(Asn1Primitive... values) {
    super(values);
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.SEQUENCE;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.SEQUENCE;
  }

}
