// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Container for the content in a tagged object.
 *
 * @author Lijun Liao (xipki)
 */
class TagContent {

  final byte[] definiteLengthValue;

  /**
   * Whether the definite-length value is a constructed encoding, i.e. a series of TLVs.
   */
  private final boolean constructed;

  /**
   * DER encoding of the definite-length value, computed lazily.
   */
  private volatile byte[] derDefiniteLengthValue;

  final List<Asn1Primitive> indefiniteLengthValue;

  final Asn1TaggedObject.GenContent baseObject;

  private TagContent(boolean constructed, byte[] definiteLengthValue,
                     List<Asn1Primitive> indefiniteLengthValue,
                     Asn1TaggedObject.GenContent baseObject) {
    if (indefiniteLengthValue != null && indefiniteLengthValue.isEmpty()) {
      throw new IllegalArgumentException("indefiniteLengthValue shall not be empty");
    }
    this.constructed = constructed;
    this.definiteLengthValue = definiteLengthValue;
    this.indefiniteLengthValue = indefiniteLengthValue;
    this.baseObject = baseObject;
  }

  public static TagContent ofBaseObject(boolean explicit, Asn1Primitive baseObject) {
    return new TagContent(false, null, null,
        new Asn1TaggedObject.GenContent(explicit, baseObject));
  }

  public static TagContent ofDefiniteLenthValue(boolean constructed, byte[] definiteLenthValue) {
    return new TagContent(constructed, definiteLenthValue, null, null);
  }

  public static TagContent ofDefiniteLenthValue(List<Asn1Primitive> indefiniteLengthValue) {
    return new TagContent(true, null, indefiniteLengthValue, null);
  }

  /**
   * Returns the definite-length value in the given encoding. For DER, the elements of a
   * constructed value are decoded and DER-encoded. The value of a primitive encoding is
   * returned as it is, since its type is not known without the ASN.1 schema.
   */
  private byte[] definiteLengthValue(Asn1Encoding encoding) {
    if (encoding != Asn1Encoding.DER || !constructed) {
      return definiteLengthValue;
    }

    byte[] der = derDefiniteLengthValue;
    if (der == null) {
      // The result is always cached, also if (part of) the value could not be converted to DER
      // because of the nesting depth limit. Otherwise, the conversion of the nested values would
      // be repeated for each nesting level, which takes exponential time. Moreover, the cache
      // keeps the encoded length and the encoding consistent.
      der = toDer(definiteLengthValue);
      derDefiniteLengthValue = der;
    }
    return der;
  }

  /**
   * Converts the series of TLVs to DER.
   * @return the DER encoding, or the given value if it is not a valid series of TLVs or the
   *         objects are nested too deep.
   */
  private static byte[] toDer(byte[] value) {
    // The elements are decoded by a new decoder, and DER-encoded, which may decode the values of
    // the nested tagged objects by further decoders. The nesting depth of the elements is
    // counted in the further decoders, so that Asn1Decoder.MAX_DEPTH applies across them.
    int[] outerDepth = Asn1Decoder.outerDepth();
    final int savedOuterDepth = outerDepth[0];

    Asn1Decoder.ByteArrayDecoder decoder = new Asn1Decoder.ByteArrayDecoder(value);
    try {
      List<Asn1Primitive> elements = new ArrayList<>();
      while (decoder.streamOffset() < value.length) {
        elements.add(decoder.nextObject());
      }

      outerDepth[0] = savedOuterDepth + decoder.maxDepthReached();
      ByteArrayOutputStream out = new ByteArrayOutputStream(value.length);
      for (Asn1Primitive element : elements) {
        out.writeBytes(element.getEncoded(Asn1Encoding.DER));
      }
      return out.toByteArray();
    } catch (CodecException e) {
      // nested too deep, or the content is not a valid series of TLVs and cannot be converted
      // to DER.
      return value;
    } finally {
      outerDepth[0] = savedOuterDepth;
      decoder.close();
    }
  }

  public int getEncodedLength(Asn1Encoding encoding) {
    if (definiteLengthValue != null) {
      return definiteLengthValue(encoding).length;
    } else if (baseObject != null) {
      return baseObject.getEncodedLength(encoding);
    } else {
      int len = 0;
      for (Asn1Primitive m : indefiniteLengthValue) {
        int len0 = m.getEncodedLength(encoding);
        len += Asn1Util.numBytesOfTag(m.getTagNo()) + Asn1Util.numBytesOfLength(len0) + len0;
      }
      return len;
    }
  }

  @Override
  public int hashCode() {
    return definiteLengthValue != null ? Arrays.hashCode(definiteLengthValue(Asn1Encoding.DER)) :
        indefiniteLengthValue != null ? indefiniteLengthValue.hashCode() : baseObject.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof TagContent)) {
      return false;
    }

    TagContent b = (TagContent) obj;
    // do a deep equals check
    if (baseObject != null && b.baseObject != null) {
      return baseObject.equals(b.baseObject);
    }

    if (definiteLengthValue != null && b.definiteLengthValue != null) {
      return Arrays.equals(definiteLengthValue(Asn1Encoding.DER),
          b.definiteLengthValue(Asn1Encoding.DER));
    }

    if (indefiniteLengthValue != null && b.indefiniteLengthValue != null) {
      return indefiniteLengthValue.equals(b.indefiniteLengthValue);
    }

    // fallback to the encoded format
    int encodedLen = getEncodedLength(Asn1Encoding.DER);
    if (encodedLen != b.getEncodedLength(Asn1Encoding.DER)) {
      return false;
    }

    try {
      Asn1Encoder.ByteArrayEncoder encoder = new Asn1Encoder.ByteArrayEncoder(
          Asn1Encoding.DER, new byte[encodedLen]);

      this.encodeTo(encoder);
      byte[] encoded = encoder.getWrittenBytes(false);

      encoder = new Asn1Encoder.ByteArrayEncoder(Asn1Encoding.DER, new byte[encodedLen]);

      b.encodeTo(encoder);
      byte[] bEncoded = encoder.getWrittenBytes(false);

      return Arrays.equals(encoded, bEncoded);
    } catch (CodecException e) {
      return false;
    }
  }

  public StringBuilder toString(int tagNo, StringBuilder buf, int indentLevel) {
    if (definiteLengthValue != null) {
      String prefix = "[" + tagNo + "]\n";
      ToStringUtil.appendIndent(buf, indentLevel, prefix);
      ToStringUtil.appendHex(buf, indentLevel + 1, definiteLengthValue);
    } else if (indefiniteLengthValue != null) {
      String prefix = "[" + tagNo + "]\n";
      ToStringUtil.appendIndent(buf, indentLevel, prefix);

      int size = indefiniteLengthValue.size();
      if (size == 0) {
        ToStringUtil.appendIndent(buf, indentLevel + 1, "<EMPTY>");
      } else if (size == 1) {
        indefiniteLengthValue.get(0).toString(buf, indentLevel + 1);
      } else {
        new AbstractCollection<>(false, 0, Integer.MAX_VALUE, indefiniteLengthValue) {
          @Override
          protected Asn1Primitive newType(AbstractAsn1Collection seq, int index) {
            return seq.getObjectAt(index);
          }
        }.toString(buf, indentLevel + 1);
      }
    } else {
      baseObject.toString(tagNo, buf, indentLevel);
    }
    return buf;
  }

  public Asn1TaggedObject getExplicitTaggedBase() throws CodecException {
    if (definiteLengthValue != null) {
      return Asn1Util.readAsn1Tagged(definiteLengthValue);
    } else if (indefiniteLengthValue != null) {
      if (indefiniteLengthValue.size() == 1
          && indefiniteLengthValue.get(0) instanceof Asn1TaggedObject) {
        return (Asn1TaggedObject) indefiniteLengthValue.get(0);
      } else {
        throw new CodecException("base object is not EXPLICIT tagged object");
      }
    } else {
      if (!baseObject.explicit) {
        throw new CodecException("base object is not EXPLICIT");
      }

      if (!(baseObject.content instanceof Asn1TaggedObject)) {
        throw new CodecException("base object is not tagged");
      }
      return (Asn1TaggedObject) baseObject.content;
    }
  }

  Asn1Primitive getExplicitBase(int expectedTagNo) throws CodecException {
    if (definiteLengthValue != null) {
      return Asn1Util.readAsn1Object(expectedTagNo, definiteLengthValue);
    }

    Asn1Primitive p;
    if (indefiniteLengthValue != null) {
      if (indefiniteLengthValue.size() == 1) {
        p = indefiniteLengthValue.get(0);
      } else {
        throw new CodecException("base object is not a single object");
      }
    } else {
      if (!baseObject.explicit) {
        throw new CodecException("base object is not EXPLICIT");
      }

      p = baseObject.content;
    }

    if (p.getTagNo() != expectedTagNo) {
      throw new CodecException("base object has tagNo " + baseObject.content.getTagNo() + ", but " +
          "expected " + expectedTagNo);
    }

    return p;
  }

  public Asn1Primitive getExplicitBase() throws CodecException {
    if (definiteLengthValue != null) {
      return Asn1Util.readAsn1Object(definiteLengthValue);
    } else if (indefiniteLengthValue != null) {
      if (indefiniteLengthValue.size() == 1) {
        return indefiniteLengthValue.get(0);
      } else {
        throw new CodecException("base object is not a single object");
      }
    } else {
      if (!baseObject.explicit) {
        throw new CodecException("base object is not EXPLICIT");
      }
      return baseObject.content;
    }
  }

  public Asn1Primitive getImplicitBase(boolean constructed, int baseObjectTagNo)
      throws CodecException {
    if (definiteLengthValue != null) {
      return Asn1Util.readAsn1ObjectWithValue(constructed, baseObjectTagNo, definiteLengthValue);
    } else if (indefiniteLengthValue != null) {
      int size = indefiniteLengthValue.size();
      if (baseObjectTagNo == Asn1Tags.SEQUENCE) {
        return new Asn1Sequence(indefiniteLengthValue);
      } else if (baseObjectTagNo == Asn1Tags.SET) {
        return new Asn1Set(indefiniteLengthValue);
      }
      if (Asn1Decoder.isConstructedStringType(baseObjectTagNo)) {
        // constructed string: the content contains the pieces
        return Asn1Decoder.joinPieces(baseObjectTagNo, indefiniteLengthValue);
      }

      if (size == 1) {
        Asn1Primitive r = indefiniteLengthValue.get(0);
        if (r.getTagNo() != baseObjectTagNo) {
          throw new CodecException("base object " + r.getTagNo() + " and expected tag "
              + baseObjectTagNo + " do not match");
        }
        return r;
      } else {
        throw new CodecException("The implicit base object does not match expected tag "
            + baseObjectTagNo);
      }
    } else {
      if (baseObject.explicit) {
        throw new CodecException("base object is not IMPLICIT");
      }

      if (baseObject.content.getTagNo() != baseObjectTagNo) {
        throw new CodecException("base object " + baseObject.content.getTagNo() + " and " +
            "baseObjectTagNo " + baseObjectTagNo + " do not match");
      }
      return baseObject.content;
    }
  }

  void encodeTo(Asn1Encoder encoder) throws CodecException {
    if (definiteLengthValue != null) {
      encoder.write(definiteLengthValue(encoder.getEncoding()));
    } else if (indefiniteLengthValue != null) {
      for (Asn1Primitive piece : indefiniteLengthValue) {
        encoder.encode(piece);
      }
    } else {
      Asn1Primitive base = baseObject.content;
      if (baseObject.explicit) {
        encoder.encode(base);
      } else {
        encoder.encodeValue(base.type(), base);
      }
    }
  }

}
