// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.io.InputStream;
import java.math.BigInteger;
import java.time.Instant;

/**
 * The ASN.1 utility class.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Util {

  public static Asn1IA5String[] toIA5Strings(String... strings) {
    if (strings == null) {
      return null;
    }

    Args.noNullElements(strings, "strings");
    Asn1IA5String[] r = new Asn1IA5String[strings.length];
    for (int i = 0; i < strings.length; i++) {
      r[i] = new Asn1IA5String(strings[i]);
    }
    return r;
  }

  public static Asn1PrintableString[] toPrintableStrings(String... strings) {
    if (strings == null) {
      return null;
    }

    Args.noNullElements(strings, "strings");
    Asn1PrintableString[] r = new Asn1PrintableString[strings.length];
    for (int i = 0; i < strings.length; i++) {
      r[i] = new Asn1PrintableString(strings[i]);
    }
    return r;
  }

  public static Asn1Utf8String[] toUtf8Strings(String... strings) {
    if (strings == null) {
      return null;
    }

    Args.noNullElements(strings, "strings");
    Asn1Utf8String[] r = new Asn1Utf8String[strings.length];
    for (int i = 0; i < strings.length; i++) {
      r[i] = new Asn1Utf8String(strings[i]);
    }
    return r;
  }

  public static Asn1IA5String toIA5String(String str) {
    return str == null ? null : new Asn1IA5String(str);
  }

  public static Asn1PrintableString toPrintableString(String str) {
    return str == null ? null : new Asn1PrintableString(str);
  }

  public static Asn1BmpString toBMPString(String str) {
    return str == null ? null : new Asn1BmpString(str);
  }

  public static Asn1Utf8String toUtf8String(String str) {
    return str == null ? null : new Asn1Utf8String(str);
  }

  public static String fromAsn1(AbstractAsn1String str) {
    return str == null ? null : str.getString();
  }

  public static Asn1BitString toBitString(byte[] bytes) {
    return bytes == null ? null : new Asn1BitString(bytes);
  }

  public static byte[] fromAsn1(Asn1BitString asn1) {
    return asn1 == null ? null : asn1.getAlignedOctets();
  }

  public static Asn1OctetString toOctetString(byte[] bytes) {
    return bytes == null ? null : new Asn1OctetString(bytes);
  }

  public static byte[] fromAsn1(Asn1OctetString asn1) {
    return asn1 == null ? null : asn1.getOctets();
  }

  public static Asn1Boolean toBoolean(Boolean b) {
    return b == null ? null : Asn1Boolean.getInstance(b);
  }

  public static Boolean fromAsn1(Asn1Boolean asn1) {
    return asn1 == null ? null : asn1.isTrue();
  }

  public static Asn1Integer toInteger(BigInteger value) {
    return value == null ? null : new Asn1Integer(value);
  }

  public static BigInteger fromAsn1(Asn1Integer asn1) {
    return asn1 == null ? null : asn1.getValue();
  }

  public static Asn1Integer toInteger(Integer value) {
    return value == null ? null : new Asn1Integer(value);
  }

  public static Integer fromAsn1Int(Asn1Integer asn1) {
    return asn1 == null ? null : asn1.intValueExact();
  }

  public static Asn1Integer toInteger(Long value) {
    return value == null ? null : new Asn1Integer(value);
  }

  public static Long fromAsn1Long(Asn1Integer asn1) {
    return asn1 == null ? null : asn1.longValueExact();
  }

  public static Asn1GeneralizedTime toGeneralizedDate(Instant date) {
    return date == null ? null : new Asn1GeneralizedTime(date);
  }

  public static Asn1UtcTime toUtcTime(Instant date) {
    return date == null ? null : new Asn1UtcTime(date);
  }

  public static Instant fromAsn1(AbstractAsn1Time asn1) {
    return asn1 == null ? null : asn1.getTime();
  }

  public static Instant fromAsn1(Time asn1) {
    return asn1 == null ? null : asn1.time();
  }

  public static Asn1Primitive readAsn1Object(byte[] encoded) throws CodecException {
    try (Asn1Decoder.ByteArrayDecoder decoder = new Asn1Decoder.ByteArrayDecoder(encoded)) {
      Asn1Primitive r = decoder.nextObject();
      if (decoder.hasMoreBytes()) {
        throw new CodecException("encoded has " + decoder.remainingBytesSize()
            + " remaining bytes");
      }
      return r;
    }
  }

  public static Asn1Primitive readAsn1Object(int expectedTag, byte[] encoded)
      throws CodecException {
    try (Asn1Decoder.ByteArrayDecoder decoder = new Asn1Decoder.ByteArrayDecoder(encoded)) {
      Asn1Primitive r = Asn1Decoder.rejectInvalidTextString(
          decoder.nextObject(expectedTag), expectedTag);
      if (decoder.hasMoreBytes()) {
        String msg = "encoded has " + decoder.remainingBytesSize() +
                   " remaining bytes, position=" + decoder.position();
        throw new CodecException(msg);
      }
      return r;
    }
  }

  public static Asn1TaggedObject readAsn1Tagged(byte[] encoded)
      throws CodecException {
    try (Asn1Decoder.ByteArrayDecoder decoder = new Asn1Decoder.ByteArrayDecoder(encoded)) {
      Asn1TaggedObject r = decoder.nextTaggedObject();
      if (decoder.hasMoreBytes()) {
        throw new CodecException("encoded has remaining bytes");
      }
      return r;
    }
  }

  public static Asn1Primitive readAsn1Object(InputStream is) throws CodecException {
    Asn1Decoder.StreamDecoder decoder = new Asn1Decoder.StreamDecoder(is);
    return decoder.nextObject();
  }

  public static Asn1Primitive readAsn1Object(int expectedTag, InputStream is)
      throws CodecException {
    Asn1Decoder.StreamDecoder decoder = new Asn1Decoder.StreamDecoder(is);
    return Asn1Decoder.rejectInvalidTextString(decoder.nextObject(expectedTag), expectedTag);
  }

  public static Asn1TaggedObject readAsn1Tagged(InputStream is) throws CodecException {
    Asn1Decoder.StreamDecoder decoder = new Asn1Decoder.StreamDecoder(is);
    return decoder.nextTaggedObject();
  }

  public static void checkSequenceEnd(int index, int size) throws CodecException {
    if (index != size) {
      throw CodecException.SEQ_WITH_UNEXPECTED_ELEMENTS;
    }
  }

  public static Asn1Primitive readAsn1ObjectWithValue(boolean construct, int tagNo, byte[] value)
      throws CodecException {
    return Asn1Decoder.nextObjectWithValue(construct, tagNo, value);
  }

  static byte[] toTwosComplement(int value) {
    int size;
    if (value >= -0x80 && value <= 0x7F) {
      size = 1;
    } else if (value >= -0x8000 && value <= 0x7FFF) {
      size = 2;
    } else if (value >= -0x800000 && value <= 0x7FFFFF) {
      size = 3;
    } else {
      size = 4;
    }

    byte[] result = new byte[size];
    for (int i = size - 1; i >= 0; i--) {
      result[i] = (byte) value;
      value >>= 8;
    }

    return result;
  }

  static int numBytesOfLength(int len) {
    Args.notNegative(len, "len");
    return (len <= 0x7F) ? 1
        : (len <= 0xFF) ? 2
        : (len <= 0xFFFF) ? 3
        : (len <= 0xFFFFFF) ? 4 : 5;
  }

  static int numBytesOfTag(int tagNo) {
    if (tagNo < 31) {
      return 1;
    } else {
      int num;
      if (tagNo < 128) {
        num = 1;
      } else if (tagNo < 128 * 128) {
        num = 2;
      } else if (tagNo < 128 * 128 * 128) {
        num = 3;
      } else if (tagNo < 128 * 128 * 128 * 128) {
        num = 4;
      } else {
        num = 5;
      }

      return 1 + num;
    }
  }

  public static byte[] tagNo2bytes(TagClass tagClass, boolean constructed, int tagNo) {
    int mask = tagClass.mask();
    if (constructed) {
      mask |= 0x20;
    }

    if (tagNo < 31) {
      return new byte[] {(byte) (tagNo | mask)};
    } else {
      int firstByte = mask | 0x1F;
      byte[] bytes = largeTagNo2bytes(tagNo);
      byte[] r = new byte[1 + bytes.length];
      r[0] = (byte) firstByte;
      System.arraycopy(bytes, 0, r, 1, bytes.length);
      return r;
    }
  }

  private static byte[] largeTagNo2bytes(int tagNo) {
    Args.min(tagNo, "tagNo", 31);
    int size = numBytesOfTag(tagNo) - 1;

    byte[] result = new byte[size];
    for (int i = size - 1; i >= 0; i--) {
      int b = tagNo & 0x7F;
      if (i != size - 1) {
        // bit 8 is set in all but the last byte (X.690 8.1.2.4.2)
        b |= 0x80;
      }
      result[i] = (byte) b;
      tagNo >>>= 7;
    }

    return result;
  }

}
