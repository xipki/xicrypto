// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.Asn1IA5String;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.IntegerSeq;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Tests the DER encoding and decoding, compared with BouncyCastle where possible.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1EncodingTest {

  private interface Decoder {
    Object decode() throws Exception;
  }

  // ---------------- lengths and tags ----------------

  @Test
  public void testLengthEncoding() throws Exception {
    int[] lengths = {0, 1, 127, 128, 255, 256, 65535, 65536};
    for (int len : lengths) {
      byte[] value = new byte[len];
      Arrays.fill(value, (byte) 0x5a);
      assertSameAsBc("OCTET STRING length " + len,
          new DEROctetString(value), new Asn1OctetString(value), Asn1OctetString.class);
    }
  }

  @Test
  public void testTagClasses() throws Exception {
    // X.690 8.1.2.2: universal 0x00, application 0x40, context-specific 0x80, private 0xC0
    TagClass[] tagClasses = {TagClass.application, TagClass.contextSpecific, TagClass._private};
    int[] bcTagClasses = {BERTags.APPLICATION, BERTags.CONTEXT_SPECIFIC, BERTags.PRIVATE};
    for (int i = 0; i < tagClasses.length; i++) {
      for (int tagNo : new int[]{5, 31}) {
        for (boolean explicit : new boolean[]{true, false}) {
          String title = tagClasses[i] + (explicit ? " EXPLICIT" : " IMPLICIT")
                            + " [" + tagNo + "]";
          byte[] bcEncoded = new DERTaggedObject(explicit, bcTagClasses[i], tagNo,
              new ASN1Integer(5)).getEncoded();
          Asn1TaggedObject obj = new Asn1TaggedObject(tagClasses[i], explicit, tagNo,
              new Asn1Integer(5));
          Assert.assertEquals(title, Hex.encode(bcEncoded), Hex.encode(obj.getEncoded()));

          Asn1TaggedObject decoded = (Asn1TaggedObject) Asn1Util.readAsn1Object(bcEncoded);
          Assert.assertEquals(title + ": tagClass", tagClasses[i], decoded.getTagClass());
          Assert.assertEquals(title + ": tagNo", tagNo, decoded.getTagNo());
          Assert.assertArrayEquals(title + ": re-encoded", bcEncoded, decoded.getEncoded());
        }
      }
    }
  }

  @Test
  public void testTagNumbers() throws Exception {
    int[] tagNos = {0, 1, 30, 31, 127, 128, 16383, 16384};
    for (int tagNo : tagNos) {
      for (boolean explicit : new boolean[]{true, false}) {
        byte[] bcEncoded = new DERTaggedObject(explicit, tagNo, new ASN1Integer(5)).getEncoded();
        Asn1TaggedObject obj = new Asn1TaggedObject(explicit, tagNo, new Asn1Integer(5));
        String title = (explicit ? "EXPLICIT" : "IMPLICIT") + " [" + tagNo + "]";
        Assert.assertEquals(title, Hex.encode(bcEncoded), Hex.encode(obj.getEncoded()));

        Asn1TaggedObject decoded = (Asn1TaggedObject) Asn1Util.readAsn1Object(bcEncoded);
        Assert.assertEquals(title + ": tagNo", tagNo, decoded.getTagNo());
        Asn1Integer base = explicit ? (Asn1Integer) decoded.getExplicitBase()
            : decoded.getImplicitIntegerBase();
        Assert.assertEquals(title + ": base", BigInteger.valueOf(5), base.getValue());
        Assert.assertArrayEquals(title + ": re-encoded", bcEncoded, decoded.getEncoded());
      }
    }
  }

  @Test
  public void testTagNumbersInCollection() throws Exception {
    // The length of the collection must use the tag sizes of the elements, not of the collection.
    int[] tagNos = {30, 31, 127, 128, 16383, 16384};
    for (int tagNo : tagNos) {
      for (boolean explicit : new boolean[]{true, false}) {
        String title = "SEQUENCE/SET of " + (explicit ? "EXPLICIT" : "IMPLICIT")
            + " [" + tagNo + "]";

        DERTaggedObject bcTagged = new DERTaggedObject(explicit, tagNo, new ASN1Integer(5));
        Asn1TaggedObject tagged = new Asn1TaggedObject(explicit, tagNo, new Asn1Integer(5));

        assertSameAsBc(title, new DERSequence(bcTagged), new Asn1Sequence(tagged),
            Asn1Sequence.class);
        assertSameAsBc(title, new DERSet(bcTagged), new Asn1Set(tagged), Asn1Set.class);
      }
    }
  }

  @Test
  public void testChoiceIsAlwaysExplicitlyTagged() throws Exception {
    // X.680 31.2.7: the tagging of a CHOICE type is always EXPLICIT.
    Asn1Encodable choice = new Asn1Encodable() {
      @Override
      public boolean isChoice() {
        return true;
      }

      @Override
      public Asn1Primitive toAsn1Primitive() {
        return new Asn1IA5String("a");
      }
    };

    Assert.assertEquals("[0] CHOICE", "a003160161",
        Hex.encode(Asn1TaggedObject.newImplicit(0, choice).getEncoded()));
    Assert.assertEquals("[0] IMPLICIT IA5String", "800161",
        Hex.encode(Asn1TaggedObject.newImplicit(0, new Asn1IA5String("a")).getEncoded()));
  }

  // ---------------- primitive types ----------------

  @Test
  public void testIntegerEdgeCases() throws Exception {
    long[] values = {127, 128, 255, 256, -128, -129, -256, Long.MAX_VALUE, Long.MIN_VALUE};
    for (long value : values) {
      BigInteger v = BigInteger.valueOf(value);
      assertSameAsBc("INTEGER " + value, new ASN1Integer(v), new Asn1Integer(v),
          Asn1Integer.class);
    }
  }

  @Test
  public void testOid() throws Exception {
    String[] oids = {"0.0", "1.2.840.113549.1.1.11", "2.999.1", "2.5.29.15",
        "1.3.6.1.4.1.311.20.2.3", "2.25.329800735698586629295641978511506172918"};
    for (String oid : oids) {
      assertSameAsBc("OID " + oid, new ASN1ObjectIdentifier(oid), new Asn1Oid(oid),
          Asn1Oid.class);
      Asn1Oid decoded = Asn1Oid.fromEncoded(new Asn1Oid(oid).getEncoded());
      Assert.assertEquals("OID " + oid, oid, decoded.getId());
    }
  }

  @Test
  public void testBitStringNamedBits() throws Exception {
    // DER: trailing zero bits of a named bit list are removed (X.690 11.2.2).
    int[][] flagsList = {{0}, {1}, {0, 5}, {7}, {8}, {0, 5, 8}, {2, 15}};
    for (int[] flags : flagsList) {
      int bcFlags = 0;
      for (int flag : flags) {
        // org.bouncycastle.asn1.x509.KeyUsage: bit n is (1 << (7 - n)) of the first byte,
        // and (1 << (15 - n)) of the second byte.
        bcFlags |= (flag < 8) ? (1 << (7 - flag)) : (1 << (23 - flag));
      }
      byte[] bcEncoded = new org.bouncycastle.asn1.x509.KeyUsage(bcFlags).getEncoded();
      Asn1BitString bs = new Asn1BitString(flags);
      Assert.assertEquals("flags " + Arrays.toString(flags),
          Hex.encode(bcEncoded), Hex.encode(bs.getEncoded()));
    }

    Assert.assertEquals("no flags", "030100",
        Hex.encode(new Asn1BitString(new int[0]).getEncoded()));
  }

  @Test
  public void testBitStringUnusedBits() throws Exception {
    byte[] value = {(byte) 0xf0};
    assertSameAsBc("BIT STRING with 4 unused bits",
        new DERBitString(value, 4), new Asn1BitString(value, 4), Asn1BitString.class);
  }

  @Test
  public void testBmpString() throws Exception {
    for (String value : new String[]{"", "A", "äöü", "中文", "😀"}) {
      assertSameAsBc("BMPString '" + value + "'", new DERBMPString(value),
          new Asn1BmpString(value), Asn1BmpString.class);
    }
  }

  @Test
  public void testDerSetOrdering() throws Exception {
    // DER: the elements of a SET OF are sorted by their encodings (X.690 11.6).
    ASN1Encodable[] bcValues = {new ASN1Integer(256), new ASN1Integer(1), new ASN1Integer(-1),
        new ASN1Integer(0), new DEROctetString(new byte[]{1, 2}), new DEROctetString(new byte[0])};
    Asn1Encodable[] values = {new Asn1Integer(256), new Asn1Integer(1), new Asn1Integer(-1),
        new Asn1Integer(0), new Asn1OctetString(new byte[]{1, 2}),
        new Asn1OctetString(new byte[0])};

    byte[] bcEncoded = new DERSet(bcValues).getEncoded();
    Assert.assertEquals("SET", Hex.encode(bcEncoded), Hex.encode(new Asn1Set(values).getEncoded()));

    Asn1Set decoded = Asn1Set.fromEncoded(bcEncoded);
    Assert.assertArrayEquals("SET re-encoded", bcEncoded, decoded.getEncoded());
  }

  // ---------------- text strings ----------------

  @Test
  public void testPrintableStringDecodingIsLenient() throws Exception {
    // '*', '@' and '_' are not in the PrintableString character set, but are used in
    // real-world certificates.
    for (String value : new String[]{"*.example.com", "a@b_c", "a&b"}) {
      byte[] encoded = encodeString(Asn1Tags.PRINTABLE_STRING, value.getBytes());
      Asn1Primitive p = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(value + ": class", p instanceof Asn1PrintableString);
      Assert.assertEquals(value, ((Asn1PrintableString) p).getString());
      Assert.assertArrayEquals(value + ": re-encoded", encoded, p.getEncoded());
    }

    // The constructor stays strict.
    try {
      new Asn1PrintableString("*");
      Assert.fail("IllegalArgumentException expected");
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

  @Test
  public void testInvalidTextStringContentIsKept() throws Exception {
    Object[][] cases = {
        {"PrintableString with 0xE9", Asn1Tags.PRINTABLE_STRING, "e9"},
        {"IA5String with 0xE9", Asn1Tags.IA5_STRING, "41e9"},
        {"UTF8String truncated", Asn1Tags.UTF8_STRING, "c3"},
        {"UTF8String overlong '/'", Asn1Tags.UTF8_STRING, "c0af"},
        {"UTF8String CESU-8 surrogate", Asn1Tags.UTF8_STRING, "eda080"},
        {"BMPString with odd length", Asn1Tags.BMP_STRING, "0041ff"}};

    for (Object[] c : cases) {
      String title = (String) c[0];
      byte[] encoded = encodeString((int) c[1], Hex.decode((String) c[2]));

      // The content is not valid: decoded as Asn1Any which keeps the encoding unchanged.
      Asn1Primitive p = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": class " + p.getClass().getSimpleName(), p instanceof Asn1Any);
      Assert.assertArrayEquals(title + ": re-encoded", encoded, p.getEncoded());

      // In a SEQUENCE
      byte[] seqEncoded = new Asn1Sequence(p).getEncoded();
      Assert.assertArrayEquals(title + ": SEQUENCE re-encoded", seqEncoded,
          Asn1Sequence.fromEncoded(seqEncoded).getEncoded());
    }
  }

  @Test
  public void testValidTextStrings() throws Exception {
    Object[][] cases = {
        {Asn1Tags.UTF8_STRING, "äöü 中文 😀", Asn1Utf8String.class},
        {Asn1Tags.IA5_STRING, "a@b.c\u0000\u007f", Asn1IA5String.class},
        {Asn1Tags.PRINTABLE_STRING, "Abc 123'()+,-./:=?", Asn1PrintableString.class}};
    for (Object[] c : cases) {
      int tag = (int) c[0];
      String value = (String) c[1];
      byte[] content = tag == Asn1Tags.UTF8_STRING
          ? value.getBytes(java.nio.charset.StandardCharsets.UTF_8) : value.getBytes();
      byte[] encoded = encodeString(tag, content);
      Asn1Primitive p = Asn1Util.readAsn1Object(encoded);
      Assert.assertEquals(value + ": class", c[2], p.getClass());
      Assert.assertEquals(value, ((AbstractAsn1String) p).getString());
      Assert.assertArrayEquals(value + ": re-encoded", encoded, p.getEncoded());
    }
  }

  @Test
  public void testBerConstructedUtf8StringSplitCharacter() throws Exception {
    // 'é' (c3 a9) split into two pieces of a BER constructed UTF8String
    byte[] ber = Hex.decode("2c800c01c30c01a90000");
    Asn1Primitive p = Asn1Util.readAsn1Object(ber);
    Assert.assertTrue("class", p instanceof Asn1Utf8String);
    Assert.assertEquals("é", ((Asn1Utf8String) p).getString());
    Assert.assertEquals("DER", "0c02c3a9", Hex.encode(p.getEncoded()));
  }

  @Test
  public void testTypedAccessorsRejectInvalidTextString() throws Exception {
    byte[] invalidUtf8 = Hex.decode("30030c01c3");
    byte[] implicitInvalidIa5 = Hex.decode("30038201e9");
    byte[] explicitInvalidUtf8 = Hex.decode("3005a0030c01c3");

    assertCodecException("getUtf8StringAt",
        () -> Asn1Sequence.fromEncoded(invalidUtf8).getUtf8StringAt(0));
    assertCodecException("getString",
        () -> Asn1Sequence.fromEncoded(invalidUtf8).getString(0));
    assertCodecException("getIA5StringTaggedAt IMPLICIT",
        () -> Asn1Sequence.fromEncoded(implicitInvalidIa5).getIA5StringTaggedAt(0, false));
    assertCodecException("getUtf8StringTaggedAt EXPLICIT",
        () -> Asn1Sequence.fromEncoded(explicitInvalidUtf8).getUtf8StringTaggedAt(0, true));
    assertCodecException("Asn1Utf8String.fromEncoded",
        () -> Asn1Utf8String.fromEncoded(Hex.decode("0c01c3")));
    assertCodecException("asUtf8String",
        () -> Asn1Util.readAsn1Object(Hex.decode("0c01c3")).asUtf8String());

    // valid content
    Assert.assertEquals("o", Asn1Sequence.fromEncoded(Hex.decode("300382016f"))
        .getIA5StringTaggedAt(0, false).getString());
  }

  // ---------------- equals and hashCode ----------------

  @Test
  public void testEqualsAndHashCode() throws Exception {
    Asn1Sequence seq = new Asn1Sequence(new Asn1Integer(1), new Asn1Oid("1.2.3"));
    Asn1Sequence seq2 = Asn1Sequence.fromEncoded(seq.getEncoded());
    Assert.assertEquals("SEQUENCE", seq, seq2);
    Assert.assertEquals("SEQUENCE hashCode", seq.hashCode(), seq2.hashCode());

    Asn1Set set = new Asn1Set(new Asn1Integer(1), new Asn1Oid("1.2.3"));
    Assert.assertNotEquals("SEQUENCE vs SET", seq, set);

    Assert.assertNotEquals("INTEGER vs ENUMERATED", new Asn1Integer(1),
        new Asn1Enumerated(1));
    Assert.assertNotEquals("UTF8String vs IA5String", new Asn1Utf8String("a"),
        new Asn1IA5String("a"));

    Assert.assertFalse("primitive equals null", new Asn1Integer(1).equals(null));
    Assert.assertFalse("SEQUENCE equals null", seq.equals(null));

    // composite (non-primitive) Asn1Encodable
    IntegerSeq iseq = new IntegerSeq(0, new Asn1Integer(1), new Asn1Integer(2));
    IntegerSeq iseq2 = new IntegerSeq(0, new Asn1Integer(1), new Asn1Integer(2));
    Assert.assertEquals("IntegerSeq", iseq, iseq2);
    Assert.assertEquals("IntegerSeq hashCode", iseq.hashCode(), iseq2.hashCode());
    Assert.assertFalse("IntegerSeq equals null", iseq.equals(null));
  }

  // ---------------- malformed input ----------------

  @Test
  public void testMalformedInputThrowsCodecException() {
    String[] inputs = {
        "",                    // empty
        "30",                  // missing length
        "3005020101",          // content shorter than the length
        "0482ffff",            // length beyond the input
        "04847fffffff00",      // huge length
        "04850000000001aa",    // length with more than 4 bytes
        "0200",                // INTEGER without content
        "0102ffff",            // BOOLEAN with 2 octets
        "050100",              // NULL with content
        "0300",                // BIT STRING without the unused-bits octet
        "030108",              // BIT STRING with 8 unused bits
        "0a050100000000",      // ENUMERATED exceeding int
        "0480",                // indefinite length for a primitive encoding
        "3003020101ff",        // trailing bytes
    };

    for (String hex : inputs) {
      byte[] encoded = Hex.decode(hex);
      assertCodecException("decode " + hex, () -> Asn1Util.readAsn1Object(encoded));
    }
  }

  @Test
  public void testNestingDepthLimit() throws Exception {
    // allowed: MAX_DEPTH levels
    byte[] encoded = nestedDefinite(0x30, Asn1Decoder.MAX_DEPTH - 1);
    Assert.assertArrayEquals("max depth", encoded, Asn1Util.readAsn1Object(encoded).getEncoded());

    // too deep: definite length
    byte[] tooDeep = nestedDefinite(0x30, Asn1Decoder.MAX_DEPTH);
    assertCodecException("definite length", () -> Asn1Util.readAsn1Object(tooDeep));
    assertCodecException("definite length, stream",
        () -> Asn1Util.readAsn1Object(new ByteArrayInputStream(tooDeep)));

    // too deep: indefinite length, without stack overflow
    int n = 100_000;
    byte[] indefinite = new byte[2 * n];
    for (int i = 0; i < n; i++) {
      indefinite[2 * i] = 0x30;
      indefinite[2 * i + 1] = (byte) 0x80;
    }
    assertCodecException("indefinite length", () -> Asn1Util.readAsn1Object(indefinite));

    // too deep: indefinite length tagged objects
    for (int i = 0; i < n; i++) {
      indefinite[2 * i] = (byte) 0xA0;
    }
    assertCodecException("indefinite length tagged", () -> Asn1Util.readAsn1Object(indefinite));
  }

  @Test
  public void testDeeplyNestedTaggedObjectToDer() throws Exception {
    // The content of a definite-length tagged object is decoded when it is DER-encoded,
    // the nesting across the tagged objects must not cause the stack overflow.
    byte[] encoded = nestedDefinite(0xA0, 10_000);
    Asn1Primitive p = Asn1Util.readAsn1Object(encoded);
    Assert.assertArrayEquals("re-encoded", encoded, p.getEncoded(Asn1Encoding.DER));
  }

  @Test
  public void testStreamDecoder() throws Exception {
    // empty OCTET STRING
    Asn1Primitive p = Asn1Util.readAsn1Object(Asn1Tags.OCTET_STRING,
        new ByteArrayInputStream(Hex.decode("0400")));
    Assert.assertEquals("empty OCTET STRING", "0400", Hex.encode(p.getEncoded()));

    // a huge length must not allocate the memory before the content is read
    assertCodecException("huge length", () -> Asn1Util.readAsn1Object(Asn1Tags.OCTET_STRING,
        new ByteArrayInputStream(Hex.decode("04847fffffff00"))));
  }

  // ---------------- helpers ----------------

  private static void assertSameAsBc(String title, ASN1Encodable bcObj, Asn1Encodable obj,
                                     Class<? extends Asn1Primitive> expectedClass)
      throws Exception {
    byte[] bcEncoded = bcObj.toASN1Primitive().getEncoded("DER");
    Assert.assertEquals(title, Hex.encode(bcEncoded),
        Hex.encode(obj.getEncoded(Asn1Encoding.DER)));

    Asn1Primitive decoded = Asn1Util.readAsn1Object(bcEncoded);
    Assert.assertEquals(title + ": decoded class", expectedClass, decoded.getClass());
    Assert.assertArrayEquals(title + ": re-encoded", bcEncoded, decoded.getEncoded());
    Assert.assertEquals(title + ": equals", obj.toAsn1Primitive(), decoded);
  }

  /**
   * Returns the given number of nested definite-length constructed TLVs with the given tag
   * around a NULL.
   */
  private static byte[] nestedDefinite(int tag, int levels) {
    byte[] r = Hex.decode("0500");
    for (int i = 0; i < levels; i++) {
      int len = r.length;
      byte[] lenBytes = len < 0x80 ? new byte[]{(byte) len}
          : len < 0x100 ? new byte[]{(byte) 0x81, (byte) len}
          : len < 0x10000 ? new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len}
          : new byte[]{(byte) 0x83, (byte) (len >> 16), (byte) (len >> 8), (byte) len};
      byte[] outer = new byte[1 + lenBytes.length + len];
      outer[0] = (byte) tag;
      System.arraycopy(lenBytes, 0, outer, 1, lenBytes.length);
      System.arraycopy(r, 0, outer, 1 + lenBytes.length, len);
      r = outer;
    }
    return r;
  }

  private static byte[] encodeString(int tag, byte[] content) {
    byte[] r = new byte[2 + content.length];
    r[0] = (byte) tag;
    r[1] = (byte) content.length;
    System.arraycopy(content, 0, r, 2, content.length);
    return r;
  }

  private static void assertCodecException(String title, Decoder decoder) {
    try {
      Object r = decoder.decode();
      Assert.fail(title + ": CodecException expected, but got " + r);
    } catch (CodecException e) {
      // expected
    } catch (Throwable t) {
      Assert.fail(title + ": CodecException expected, but got " + t);
    }
  }

}
