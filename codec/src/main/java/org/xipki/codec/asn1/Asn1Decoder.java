// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.ByteArraySource;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.StreamSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * ASN.1 Decoder.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Asn1Decoder implements AutoCloseable {

  // end of contents: tag = 0, length = 0: 0x00 00
  private static final TagInfo TAG_INFO_EOC = new TagInfo(TagClass.universal, false, 0);
  private static final int INDEFINITE_LENGTH = -1;
  private static final int TAG_TAGGED_OBJ = -1;

  /**
   * Maximal nesting depth of the constructed objects. It protects the decoder against the
   * {@link StackOverflowError} caused by deeply nested (e.g. 30 80 30 80 ...) malicious input.
   */
  public static final int MAX_DEPTH = 99;

  /**
   * Nesting depth of the objects being DER-encoded by {@link TagContent} on this thread, whose
   * definite-length values are decoded by new decoders. It is counted in the nesting depth of
   * the new decoders, so that {@link #MAX_DEPTH} applies across them.
   */
  private static final ThreadLocal<int[]> OUTER_DEPTH = ThreadLocal.withInitial(() -> new int[1]);

  private final int outerDepth = OUTER_DEPTH.get()[0];

  private int depth;

  private int maxDepthReached;

  private static class TagInfo {
    private final TagClass tagClass;
    private final boolean constructed;
    private final int tag;

    private TagInfo(TagClass tagClass, boolean constructed, int tagNo) {
      this.tagClass = tagClass;
      this.constructed = constructed;
      this.tag = tagNo;
    }
  }

  protected abstract int peek1Byte() throws CodecException;

  protected abstract byte[] peekBytes(int num) throws CodecException;

  public abstract int streamOffset();

  /**
   * read one byte
   * @return the read byte.
   * @throws CodecException in case of I/O problems reading the
   *         ASN1-encoded value from the underlying input stream.
   */
  protected abstract int read1Byte() throws CodecException;

  protected abstract byte[] readExactly(int len) throws CodecException;

  /**
   * Returns the holder of the outer nesting depth on this thread, see {@link #OUTER_DEPTH}.
   */
  static int[] outerDepth() {
    return OUTER_DEPTH.get();
  }

  /**
   * Returns the maximal nesting depth of the objects decoded so far.
   */
  int maxDepthReached() {
    return maxDepthReached;
  }

  public Asn1Primitive nextObject() throws CodecException {
    return doNextObject(null, false);
  }

  public Asn1Primitive nextObject(int expectedTag) throws CodecException {
    return doNextObject(expectedTag, false);
  }

  public Asn1TaggedObject nextTaggedObject() throws CodecException {
    return (Asn1TaggedObject) doNextObject(TAG_TAGGED_OBJ, false);
  }

  static Asn1Primitive nextObjectWithValue(boolean constructed, int tag, byte[] value)
      throws CodecException {
    if (tag == Asn1Tags.SEQUENCE || tag == Asn1Tags.SET) {
      final int endOff = value.length;
      int streamOff;

      List<Asn1Primitive> elements = new LinkedList<>();
      try (ByteArrayDecoder iDecoder = new ByteArrayDecoder(value)) {
        while (iDecoder.streamOffset() < endOff) {
          Asn1Primitive element = iDecoder.nextObject();
          elements.add(element);
        }
        streamOff = iDecoder.streamOffset();
      }

      if (endOff != streamOff) {
        throw new CodecException("invalid offset: " + streamOff + ", shall be "+ endOff);
      }

      return (tag == Asn1Tags.SEQUENCE) ? new Asn1Sequence(elements) : new Asn1Set(elements);
    } else if (constructed && isConstructedStringType(tag)) {
      // constructed string: the value contains the pieces
      List<Asn1Primitive> pieces = new LinkedList<>();
      try (ByteArrayDecoder iDecoder = new ByteArrayDecoder(value)) {
        while (iDecoder.streamOffset() < value.length) {
          pieces.add(iDecoder.nextObject());
        }
      }
      return joinPieces(tag, pieces);
    } else {
      if (tag == Asn1Tags.BIT_STRING) {
        if (value.length == 0) {
          throw new CodecException("BIT STRING without the unused-bits octet");
        }
        byte[] rawValue = Arrays.copyOfRange(value, 1, value.length);
        return newSimplePrimitive(constructed, tag,
            checkUnusedBits(0xff & value[0], rawValue.length), rawValue);
      } else {
        return newSimplePrimitive(constructed, tag, null, value);
      }
    }
  }

  /**
   * X.690, Section 8.6.2.2 and 8.6.2.3: unusedBits is between 0 and 7, and is 0 if
   * there is no subsequent octet.
   */
  private static int checkUnusedBits(int unusedBits, int numOctets) throws CodecException {
    if (unusedBits > 7 || (numOctets == 0 && unusedBits != 0)) {
      throw new CodecException("invalid unusedBits " + unusedBits + " of BIT STRING with "
          + numOctets + " octets");
    }
    return unusedBits;
  }

  private Asn1Primitive nextObjectAllowNull(Integer expectedTag) throws CodecException {
    return doNextObject(expectedTag, true);
  }

  private Asn1Primitive doNextObject(Integer expectedTag, boolean allowNull) throws CodecException {
    if (outerDepth + depth >= MAX_DEPTH) {
      throw new CodecException("nesting depth exceeds " + MAX_DEPTH);
    }

    depth++;
    maxDepthReached = Math.max(maxDepthReached, depth);
    try {
      return doNextObject0(expectedTag, allowNull);
    } catch (IllegalArgumentException | ArithmeticException | IndexOutOfBoundsException
             | ClassCastException | java.time.DateTimeException e) {
      // The constructors of the ASN.1 objects validate the content and throw unchecked
      // exceptions. For the decoder they indicate a malformed encoding.
      throw new CodecException("malformed encoding: " + e.getMessage(), e);
    } finally {
      depth--;
    }
  }

  private Asn1Primitive doNextObject0(Integer expectedTag, boolean allowNull)
      throws CodecException {
    TagInfo tagInfo = readTagInfo();

    if (tagInfo == TAG_INFO_EOC) {
      if (allowNull) {
        return null;
      } else {
        throw new CodecException("reading BREAK, not allowed");
      }
    }

    int tag = tagInfo.tag;
    if (expectedTag != null) {
      if (expectedTag == TAG_TAGGED_OBJ) {
        if (tagInfo.tagClass == TagClass.universal) {
          throw new CodecException("next object is not tagged as expected");
        }
      } else if (tag != expectedTag) {
        throw new CodecException("next object is "+ tag + ", but expected " + expectedTag);
      }
    }

    if (tagInfo.tagClass != TagClass.universal) {
      // tagged object
      return readTaggedValue(tagInfo);
    } else if (tag == Asn1Tags.SEQUENCE || tag == Asn1Tags.SET) {
      // SEQUENCE // SEQUENCE OF // SET // SET OF
      return readCollectionPrimitive(tagInfo);
    } else {
      return readSimpleType(tagInfo);
    }
  }

  // Starting point is the length
  private Asn1TaggedObject readTaggedValue(TagInfo tagInfo) throws CodecException {
    // tagged
    int length = readLength();

    if (length != INDEFINITE_LENGTH) {
      // ----- definite length
      byte[] value = readExactly(length);
      return new Asn1TaggedObject(tagInfo.tagClass, tagInfo.constructed, tagInfo.tag,
          TagContent.ofDefiniteLenthValue(tagInfo.constructed, value));
    }

    // ----- indefinite length
    List<Asn1Primitive> elements = new LinkedList<>();
    while (true) {
      Asn1Primitive p = nextObjectAllowNull(null);
      if (p == null) {
        break;
      }
      elements.add(p);
    }

    return new Asn1TaggedObject(tagInfo.tagClass, tagInfo.constructed, tagInfo.tag,
        TagContent.ofDefiniteLenthValue(elements));
  }

  /*
   * read simple types:
   *  - BIT STRING
   *  - OCTET STRING,
   *  - BMP String
   *  - Printable String
   *  - UTF8 String
   *  - IA5 String.
   *  - NULL
   *  - INTEGER
   *  - UTC TIME
   *  - GENERALIZED TIME
   *
   * Starting point is the length
   */
  private Asn1Primitive readSimpleType(TagInfo tagInfo) throws CodecException {
    int tag = tagInfo.tag;
    int len = readLength();

    if (!tagInfo.constructed) {
      // constructed = false
      if (len == INDEFINITE_LENGTH) {
        throw new CodecException("indefinite length with constructed = false is not allowed");
      }

      if (tag == Asn1Tags.BIT_STRING) {
        if (len < 1) {
          throw new CodecException("invalid length " + len);
        }

        int unusedBits = read1Byte();
        byte[] value = len == 1 ? new byte[0] : readExactly(len - 1);
        return new Asn1BitString(value, checkUnusedBits(unusedBits, value.length));
      } else {
        byte[] value = readExactly(len);
        return newSimplePrimitive(false, tag, null, value);
      }
    }

    // constructed simple type
    List<Asn1Primitive> pieces = new LinkedList<>();

    if (len == INDEFINITE_LENGTH) {
      while (true) {
        Asn1Primitive piece = nextObjectAllowNull(tag);
        if (piece == null) {
          break;
        }
        pieces.add(piece);
      }
    } else {
      int endOff = streamOffset() + len;
      while (streamOffset() < endOff) {
        Asn1Primitive piece = nextObject();
        pieces.add(piece);
      }

      if (endOff != streamOffset()) {
        throw new CodecException("invalid offset: " + streamOffset() + ", shall be "+ endOff);
      }
    }

    return joinPieces(tag, pieces);
  }

  /**
   * Joins the pieces of a constructed BIT STRING, OCTET STRING or text string (X.690 8.6.3,
   * 8.7.3 and 8.23.6).
   * @param tag the tag of the string type.
   * @param pieces the pieces, each must be of the given type.
   * @return the joined string.
   * @throws CodecException if the pieces are not valid.
   */
  static Asn1Primitive joinPieces(int tag, List<Asn1Primitive> pieces) throws CodecException {
    for (Asn1Primitive p : pieces) {
      if (p.getTagNo() != tag || p instanceof Asn1TaggedObject) {
        throw new CodecException("piece is " + p.getTagNo() + ", but expected " + tag);
      }
    }

    if (tag == Asn1Tags.BIT_STRING) {
      int numPieces = pieces.size();
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      int unusedBits = 0;
      for (int i = 0; i < numPieces; i++) {
        Asn1BitString p = (Asn1BitString) pieces.get(i);
        if (i != numPieces - 1 && p.getUnusedBits() != 0) {
          throw new CodecException("constructed bit-string with non-zero unusedBits in " +
              "the non-last piece is not supported");
        }
        unusedBits = p.getUnusedBits();
        byte[] octets = p.getOctets();
        buf.write(octets, 0, octets.length);
      }

      return new Asn1BitString(buf.toByteArray(), unusedBits);
    } else if (tag == Asn1Tags.OCTET_STRING) {
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      for (Asn1Primitive p : pieces) {
        byte[] octets = ((Asn1OctetString) p).getOctets();
        buf.write(octets, 0, octets.length);
      }
      return new Asn1OctetString(buf.toByteArray());
    } else if (isTextString(tag)) {
      // The text strings: concatenate the content octets and decode them together, since a
      // multi-byte character may be split across two pieces.
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      for (Asn1Primitive p : pieces) {
        byte[] octets = textStringContent(p);
        buf.write(octets, 0, octets.length);
      }

      return newSimplePrimitive(false, tag, null, buf.toByteArray());
    } else {
      throw new CodecException("constructed encoding for type " + tag + " is not supported");
    }
  }

  static boolean isConstructedStringType(int tag) {
    return tag == Asn1Tags.BIT_STRING || tag == Asn1Tags.OCTET_STRING || isTextString(tag);
  }

  // starting point is the length
  private AbstractAsn1Collection readCollectionPrimitive(TagInfo tagInfo) throws CodecException {
    int len = readLength();

    List<Asn1Primitive> elements = new LinkedList<>();
    if (len == INDEFINITE_LENGTH) {
      while (true) {
        Asn1Primitive element = nextObjectAllowNull(null);
        if (element == null) {
          break;
        }
        elements.add(element);
      }
    } else {
      int endOff = streamOffset() + len;
      while (streamOffset() < endOff) {
        Asn1Primitive element = nextObject();
        elements.add(element);
      }

      if (endOff != streamOffset()) {
        throw new CodecException("invalid offset: " + streamOffset() + ", shall be "+ endOff);
      }
    }

    return (tagInfo.tag == Asn1Tags.SEQUENCE) ? new Asn1Sequence(elements) : new Asn1Set(elements);
  }

  private static Asn1Primitive newSimplePrimitive(
      boolean constructed, int tagNo, Integer unusedBits, byte[] value) throws CodecException {
    // OCTET STRING, IA5String, PrintableString, VisibleString, UTF8String, BMPString
    if (tagNo == Asn1Tags.OCTET_STRING ||
        tagNo == Asn1Tags.IA5_STRING ||
        tagNo == Asn1Tags.PRINTABLE_STRING ||
        tagNo == Asn1Tags.VISIBLE_STRING ||
        tagNo == Asn1Tags.UTF8_STRING ||
        tagNo == Asn1Tags.BMP_STRING) {
      switch (tagNo) {
        case Asn1Tags.OCTET_STRING: {
          return new Asn1OctetString(value);
        }
        // If the content is not valid for the string type, it cannot be represented
        // by the string object without loss. In this case an Asn1Any is returned which keeps
        // the original encoding, e.g. for the signature verification.
        case Asn1Tags.UTF8_STRING: {
          String str = decodeUtf8Strict(value);
          return str == null ? new Asn1Any(constructed, tagNo, value) : new Asn1Utf8String(str);
        }
        case Asn1Tags.PRINTABLE_STRING: {
          return !isAscii(value) ? new Asn1Any(constructed, tagNo, value)
              : new Asn1PrintableString(new String(value, StandardCharsets.US_ASCII), false);
        }
        case Asn1Tags.IA5_STRING:
          return !isAscii(value) ? new Asn1Any(constructed, tagNo, value)
              : new Asn1IA5String(new String(value, StandardCharsets.US_ASCII));
        case Asn1Tags.VISIBLE_STRING:
          return !isAscii(value) ? new Asn1Any(constructed, tagNo, value)
              : new Asn1VisibleString(new String(value, StandardCharsets.US_ASCII), false);
        // BMPString
        default: {
          int byteLen = value.length;
          if (0 != (byteLen & 1)) {
            return new Asn1Any(constructed, tagNo, value);
          }

          int charLen = byteLen / 2;
          char[] cs = new char[charLen];
          for (int i = 0; i != charLen; i++) {
            cs[i] = (char)((value[2 * i] << 8) | (value[2 * i + 1] & 0xff));
          }

          return new Asn1BmpString(new String(cs));
        }
      }
    }

    // BIT STRING: although ASN.1 allows the encoding of BIT STRING in multiple peaces in BER,
    // we do not support it since it is rarely be used.
    // BIT STRING
    if (tagNo == Asn1Tags.BIT_STRING) {
      if (unusedBits == null) {
        throw new IllegalArgumentException("unusedBits shall not be null");
      }
      return new Asn1BitString(value, unusedBits);
    }

    // remaining simple types or unknown type
    int len = value.length;
    switch (tagNo) {
      case Asn1Tags.BOOLEAN: {
        if (len != 1) {
          throw new CodecException("invalid length " + len);
        }
        return new Asn1Boolean(0xFF & value[0]);
      }
      case Asn1Tags.INTEGER: {
        if (len < 1) {
          throw new CodecException("invalid length " + len);
        }
        return new Asn1Integer(new BigInteger(value));
      }
      case Asn1Tags.NULL: {
        if (len != 0) {
          throw new CodecException("invalid length " + len);
        }
        return Asn1Null.INSTANCE;
      }
      case Asn1Tags.OBJECT_IDENTIFIER: {
        return new Asn1Oid(value);
      }
      case Asn1Tags.RELATIVE_OID: {
        return new Asn1RelativeOid(value);
      }
      case Asn1Tags.ENUMERATED: {
        if (len < 1) {
          throw new CodecException("invalid length " + len);
        }
        return new Asn1Enumerated(new BigInteger(value).intValueExact());
      }
      case Asn1Tags.UTC_TIME: {
        return new Asn1UtcTime(new String(value, StandardCharsets.US_ASCII));
      }
      case Asn1Tags.GENERALIZED_TIME: {
        return new Asn1GeneralizedTime(new String(value, StandardCharsets.US_ASCII));
      }
      default: {
        return new Asn1Any(constructed, tagNo, value);
      }
    }
  }

  /**
   * The decoder returns an {@link Asn1Any} for a text string whose content is not valid for its
   * type. This method rejects such object if a text string of the given tag is expected, so
   * that the callers casting the result get a {@link CodecException} instead of a
   * {@link ClassCastException}.
   */
  static Asn1Primitive rejectInvalidTextString(Asn1Primitive p, int expectedTag)
      throws CodecException {
    if (p instanceof Asn1Any && p.getTagNo() == expectedTag && isTextString(expectedTag)) {
      throw new CodecException("invalid content of the text string with tag " + expectedTag);
    }
    return p;
  }

  private static boolean isTextString(int tagNo) {
    return tagNo == Asn1Tags.IA5_STRING ||
        tagNo == Asn1Tags.PRINTABLE_STRING ||
        tagNo == Asn1Tags.VISIBLE_STRING ||
        tagNo == Asn1Tags.UTF8_STRING ||
        tagNo == Asn1Tags.BMP_STRING;
  }

  private static byte[] textStringContent(Asn1Primitive p) throws CodecException {
    if (p instanceof Asn1Any) {
      return ((Asn1Any) p).getValue();
    } else if (p instanceof Asn1Utf8String) {
      return ((Asn1Utf8String) p).getOctets();
    } else if (p instanceof Asn1BmpString) {
      return ((Asn1BmpString) p).contentToByteArray();
    } else if (p instanceof Asn1PrintableString || p instanceof Asn1IA5String
        || p instanceof Asn1VisibleString) {
      return ((AbstractAsn1String) p).getString().getBytes(StandardCharsets.US_ASCII);
    } else {
      throw new CodecException("unexpected piece " + p.getClass().getName());
    }
  }

  private static boolean isAscii(byte[] value) {
    for (byte b : value) {
      if (b < 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Decodes the UTF-8 encoded bytes.
   * @param value the UTF-8 encoded bytes.
   * @return the decoded string, or null if value is not a valid UTF-8 encoding.
   */
  private static String decodeUtf8Strict(byte[] value) {
    try {
      // the decoder returned by newDecoder() reports (instead of replaces)
      // malformed input and unmappable characters.
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(value)).toString();
    } catch (CharacterCodingException e) {
      return null;
    }
  }

  private TagInfo readTagInfo() throws CodecException {
    int b = read1Byte();
    if (b == 0x00) {
      int b1 = read1Byte();
      if (b1 == 0x00) {
        return TAG_INFO_EOC;
      } else {
        throw new CodecException("unknown tag " + b);
      }
    }

    int mask = b & 0xc0;
    TagClass tagClass = null;
    for (TagClass tc : TagClass.values()) {
      if (mask == tc.mask()) {
        tagClass = tc;
        break;
      }
    }

    if (tagClass == null) {
      throw new CodecException("unknown tag class of tag " + b);
    }
    boolean constructed = (b & 0x20) != 0;
    int tagNo = b & 0x1F;
    if (tagNo != 31) {
      return new TagInfo(tagClass, constructed, tagNo);
    } else {
      tagNo = 0;
      int b1;
      while (true) {
        b1 = read1Byte();
        if (tagNo > (Integer.MAX_VALUE >> 7)) {
          throw new CodecException("tag number too large");
        }
        tagNo <<= 7;
        tagNo += b1 & 0x7F;
        if (b1 < 128) {
          break;
        }
      }

      return new TagInfo(tagClass, constructed, tagNo);
    }
  }

  private int readLength() throws CodecException {
    int b = read1Byte();
    if (b == 0x80) {
      return INDEFINITE_LENGTH;
    }

    if (b < 128) {
      return b;
    }

    int numBytes = b & 0x7F;
    if (numBytes > 4) {
      throw new CodecException("length too long");
    }

    int len = 0;
    for (int i = 0; i < numBytes; i++) {
      int b1 = read1Byte();
      len <<= 8;
      len += b1;
    }

    if (len < 0) {
      throw new CodecException("length too long");
    }

    return len;
  }

  @Override
  public void close() {
  }

  /**
   * Byte Array ASN.1 Decoder.
   *
   * @author Lijun Liao (xipki)
   */
  public static class ByteArrayDecoder extends Asn1Decoder {

    private final ByteArraySource src;

    /**
     * Creates a new {@link ByteArrayDecoder} instance.
     *
     * @param is the input stream to read the encoded data from, cannot be <code>null</code>.
     */
    public ByteArrayDecoder(InputStream is) throws IOException {
      this(Args.notNull(is, "is").readAllBytes());
    }

    /**
     * Creates a new {@link ByteArrayDecoder} instance.
     * @param bytes the encoded message.
     */
    public ByteArrayDecoder(byte[] bytes) {
      this.src = new ByteArraySource(bytes);
    }

    /**
     * Creates a new {@link ByteArrayDecoder} instance.
     * @param bytes the encoded message.
     * @param offset offset of bytes for the message.
     * @param len length of the bytes for the message.
     */
    public ByteArrayDecoder(byte[] bytes, int offset, int len) throws IOException {
      this.src = new ByteArraySource(bytes, offset, len);
    }

    @Override
    public int streamOffset() {
      return src.position();
    }

    @Override
    public int peek1Byte() throws CodecException {
      return src.peek1Byte();
    }

    @Override
    protected byte[] peekBytes(int num) throws CodecException {
      return src.peekBytes(num);
    }

    public byte[] remainingBytes() {
      return src.remainingBytes();
    }

    public int remainingBytesSize() {
      return src.remainingBytesSize();
    }

    public int position() {
      return src.position();
    }

    public void writeConsumedBytes(OutputStream os) throws IOException {
      src.writeConsumedBytes(os);
    }

    @Override
    public int read1Byte() throws CodecException {
      return src.read1Byte();
    }

    boolean hasMoreBytes() {
      return src.hasMoreBytes();
    }

    @Override
    protected byte[] readExactly(int len) throws CodecException {
      return src.readExactly(len);
    }

  }

  /**
   * Stream ASN.1 Decoder.
   *
   * @author Lijun Liao (xipki)
   */
  public static class StreamDecoder extends Asn1Decoder {

    private final StreamSource src;

    /**
     * Creates a new {@link StreamDecoder} instance.
     *
     * @param is the input stream to read the encoded data from, cannot be <code>null</code>.
     */
    public StreamDecoder(InputStream is) {
      this.src = new StreamSource(is);
    }

    @Override
    public int streamOffset() {
      return src.position();
    }

    @Override
    public int read1Byte() throws CodecException {
      return src.read1Byte();
    }

    @Override
    protected byte[] readExactly(int len) throws CodecException {
      return src.readExactly(len);
    }

    @Override
    public int peek1Byte() throws CodecException {
      return src.peek1Byte();
    }

    @Override
    public byte[] peekBytes(int num) throws CodecException {
      return src.peekBytes(num);
    }

  }
}
