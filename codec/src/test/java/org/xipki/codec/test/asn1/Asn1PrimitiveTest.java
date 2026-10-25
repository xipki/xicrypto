// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.bouncycastle.asn1.*;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.*;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * @author Lijun Liao (xipki)
 */
public class Asn1PrimitiveTest {

  @Test
  public void tesHighTagNo() throws Exception {
    // encode
    byte[] bcEncoded;

    int tagNo = 100;
    {
      ASN1Integer v1 = new ASN1Integer(BigInteger.valueOf(1));
      ASN1Sequence v = new DERSequence(v1);
      ASN1TaggedObject it = new DERTaggedObject(false, tagNo, v);
      bcEncoded = it.getEncoded("DER");
    }

    byte[] encoded;

    {
      Asn1Integer v1 = new Asn1Integer(1);
      Asn1Sequence v = new Asn1Sequence(v1);
      Asn1TaggedObject it = new Asn1TaggedObject(false, tagNo, v);
      encoded = it.getEncoded(Asn1Encoding.DER);
    }

    String title = "high tagNo";
    Assert.assertArrayEquals(title, bcEncoded, encoded);

    // decode
    Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1TaggedObject);
    byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
  }

  @Test
  public void testNull() throws Exception {
    byte[] bcEncoded = DERNull.INSTANCE.getEncoded("DER");
    byte[] encoded = Asn1Null.INSTANCE.getEncoded(Asn1Encoding.DER);

    String title = "null";
    Assert.assertArrayEquals(title, bcEncoded, encoded);

    // decode
    Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Null);
    byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
  }

  @Test
  public void testBoolean() throws Exception {
    boolean[] values = {true, false};
    for (boolean value : values) {
      byte[] bcEncoded = ASN1Boolean.getInstance(value).getEncoded("DER");
      byte[] encoded = (value ? Asn1Boolean.TRUE : Asn1Boolean.FALSE).getEncoded(Asn1Encoding.DER);

      String title = "boolean " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Boolean);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testInteger() throws Exception {
    BigInteger[] values = {
        BigInteger.ZERO,
        BigInteger.ONE,
        BigInteger.ONE.negate(),
        new BigInteger("123456789abcdef011", 16),
        new BigInteger("123456789abcdef011", 16).negate(),
    };

    for (BigInteger value : values) {
      byte[] bcEncoded = new ASN1Integer(value).getEncoded("DER");
      byte[] encoded = new Asn1Integer(value).getEncoded(Asn1Encoding.DER);

      String title = "integer " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Integer);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testEnumerated() throws Exception {
    int[] values = {0, 2, 5, 10};

    for (int value : values) {
      byte[] bcEncoded = new ASN1Enumerated(value).getEncoded("DER");
      byte[] encoded = new Asn1Enumerated(value).getEncoded(Asn1Encoding.DER);

      String title = "enumerated " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Enumerated);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testGeneralizedTime() throws Exception {
    Instant[] values = {Instant.ofEpochSecond(0), Instant.now()};

    for (Instant value : values) {
      byte[] bcEncoded = new ASN1GeneralizedTime(Date.from(value)).getEncoded("DER");
      byte[] encoded = new Asn1GeneralizedTime(value).getEncoded(Asn1Encoding.DER);

      String title = "GeneralizedTime " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1GeneralizedTime);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testUtcTime() throws Exception {
    Instant[] values = {Instant.ofEpochSecond(0),
        Instant.now().truncatedTo(ChronoUnit.SECONDS)};

    for (Instant value : values) {
      byte[] bcEncoded = new ASN1UTCTime(Date.from(value)).getEncoded("DER");
      byte[] encoded = new Asn1UtcTime(value).getEncoded(Asn1Encoding.DER);

      String title = "UTCTime " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1UtcTime);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testIA5String() throws Exception {
    String[] values = {"An IA5String", "!\"#$%&'()*+,-./", "  Hello world ",
        "Hello\tWorld", "Hello\nWorld", "Hello\rWorld"};

    for (String value : values) {
      byte[] bcEncoded = new DERIA5String(value, true).getEncoded("DER");
      byte[] encoded = new Asn1IA5String(value).getEncoded(Asn1Encoding.DER);

      String title = "IA5String " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1IA5String);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testPrintableString() throws Exception {
    String[] values = {"An Printable String", "'()+,-./", "  Hello world ",
        "Hello World"};

    for (String value : values) {
      byte[] encoded = new Asn1PrintableString(value).getEncoded(Asn1Encoding.DER);
      byte[] bcEncoded = new DERPrintableString(value, true).getEncoded("DER");

      String title = "PrintableString " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1PrintableString);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testUTF8String() throws Exception {
    String[] values = {"An UTF8 String", "!\"#$%&'()*+,-./", "  Hello world ",
        "Hello\tWorld", "Hello\nWorld", "Hello\rWorld"};

    for (String value : values) {
      byte[] bcEncoded = new DERUTF8String(value).getEncoded("DER");
      byte[] encoded = new Asn1Utf8String(value).getEncoded(Asn1Encoding.DER);

      String title = "UTF8String " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Utf8String);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testOID() throws Exception {
    String[] values = {"1.2.3.4", "1.3.6.1.4.1.45522"};

    for (String value : values) {
      byte[] bcEncoded = new ASN1ObjectIdentifier(value).getEncoded("DER");
      byte[] encoded = new Asn1Oid(value).getEncoded(Asn1Encoding.DER);

      String title = "OID " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Oid);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testRelativeOID() throws Exception {
    String[] values = {"3.4", "45522.1"};

    for (String value : values) {
      byte[] bcEncoded = new ASN1RelativeOID(value).getEncoded("DER");
      byte[] encoded = new Asn1RelativeOid(value).getEncoded(Asn1Encoding.DER);

      String title = "Relative OID " + value;
      Assert.assertArrayEquals(title, bcEncoded, encoded);

      // decode
      Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
      Assert.assertTrue(title + ": decoded class", dv instanceof Asn1RelativeOid);
      byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
    }
  }

  @Test
  public void testSequence() throws Exception {
    byte[] bcEncoded;

    {
      ASN1Integer v1 = new ASN1Integer(BigInteger.valueOf(1));
      ASN1Sequence v = new DERSequence(v1);
      bcEncoded = v.getEncoded("DER");
    }

    byte[] encoded;

    {
      Asn1Integer v1 = new Asn1Integer(1);
      Asn1Sequence v = new Asn1Sequence(v1);
      encoded = v.getEncoded(Asn1Encoding.DER);
    }

    String title = "SEQUENCE";
    Assert.assertArrayEquals(title, bcEncoded, encoded);

    // decode
    Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Sequence);
    byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
  }

  @Test
  public void testSet() throws Exception {
    BigInteger v1 = BigInteger.TEN;
    byte[] v2 = new byte[] {1, 2, 3, 4};

    byte[] bcEncoded;

    {
      ASN1Set v = new DERSet(new ASN1Encodable[] {new ASN1Integer(v1), new DEROctetString(v2)});
      bcEncoded = v.getEncoded("DER");

      ASN1Set v_ = new DERSet(new ASN1Encodable[] {new DEROctetString(v2), new ASN1Integer(v1)});
      byte[] bcEncoded_ = v_.getEncoded("DER");
      Assert.assertArrayEquals("BC SET sort", bcEncoded, bcEncoded_);
    }

    byte[] encoded;
    {
      Asn1Set v = new Asn1Set(new Asn1Integer(v1), new Asn1OctetString(v2));
      encoded = v.getEncoded(Asn1Encoding.DER);

      Asn1Set v_ = new Asn1Set(new Asn1OctetString(v2), new Asn1Integer(v1));
      byte[] encoded_ = v_.getEncoded(Asn1Encoding.DER);
      Assert.assertArrayEquals("My SET sort", encoded, encoded_);
    }

    String title = "SET";
    Assert.assertArrayEquals(title, bcEncoded, encoded);

    // decode
    Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Set);
    byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
  }

  @Test
  public void testImplicitTaggedSequence() throws Exception {
    testTaggedSequence(false);
  }

  @Test
  public void testExplicitTaggedSequence() throws Exception {
    testTaggedSequence(true);
  }

  private void testTaggedSequence(boolean explicit) throws Exception {
    byte[] bcEncoded;

    {
      ASN1Integer v1 = new ASN1Integer(BigInteger.valueOf(1));
      ASN1Sequence v = new DERSequence(v1);
      ASN1TaggedObject it = new DERTaggedObject(explicit, 1, v);
      bcEncoded = it.getEncoded("DER");
    }

    byte[] encoded;

    {
      Asn1Integer v1 = new Asn1Integer(1);
      Asn1Sequence v = new Asn1Sequence(v1);
      Asn1TaggedObject it = new Asn1TaggedObject(explicit, 1, v);
      encoded = it.getEncoded(Asn1Encoding.DER);
    }

    String title = explicit ? "explicit" : "implicit";
    Assert.assertArrayEquals(title, bcEncoded, encoded);

    // decode
    Asn1Primitive dv = Asn1Util.readAsn1Object(encoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1TaggedObject);
    byte[] encoded2 = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": decoded re-encoded", bcEncoded, encoded2);
  }

  // [1] IMPLICIT [2] IMPLICIT SEQUENCE { INTEGER }
  @Test
  public void testNestedImplicit() throws Exception {
    testNestedTagged(false);
  }

  // [1] EXPLICIT [2] EXPLICIT SEQUENCE { INTEGER }
  @Test
  public void testNestedExplicit() throws Exception {
    testNestedTagged(true);
  }

  private void testNestedTagged(boolean explicit) throws Exception {
    byte[] bcEncoded;
    {
      ASN1Integer v1 = new ASN1Integer(BigInteger.valueOf(1));
      ASN1Sequence v = new DERSequence(v1);

      ASN1TaggedObject innerTag = new DERTaggedObject(explicit, 2, v);
      ASN1TaggedObject outerTag = new DERTaggedObject(explicit, 1, innerTag);
      bcEncoded = outerTag.getEncoded("DER");
    }

    byte[] encoded;
    {
      Asn1Integer v1 = new Asn1Integer(1);
      Asn1Sequence v = new Asn1Sequence(v1);

      Asn1TaggedObject innerTag = new Asn1TaggedObject(explicit, 2, v);
      Asn1TaggedObject outerTag = new Asn1TaggedObject(explicit, 1, innerTag);
      encoded = outerTag.getEncoded(Asn1Encoding.DER);
    }

    Assert.assertArrayEquals((explicit ? "explicit" : "implicit") + "encoded", bcEncoded, encoded);
  }

  @Test
  public void testVisibleString() throws Exception {
    // X.680 VisibleString, universal tag 26: 0x20-0x7E
    byte[] expected = new DERVisibleString("Hello World!").getEncoded();
    Asn1VisibleString str = Asn1VisibleString.fromEncoded(expected);
    Assert.assertEquals("Hello World!", str.getString());
    Assert.assertArrayEquals(expected, str.getEncoded());
    Assert.assertArrayEquals(expected, new Asn1VisibleString("Hello World!").getEncoded());

    for (String invalid : new String[]{"a\nb", "\u00e9"}) {
      try {
        new Asn1VisibleString(invalid);
        Assert.fail("invalid VisibleString accepted: " + invalid);
      } catch (IllegalArgumentException e) {
        // expected
      }
    }

    // non-ASCII content
    try {
      Asn1VisibleString.fromEncoded(new byte[]{0x1a, 0x01, (byte) 0xe9});
      Assert.fail("non-ASCII VisibleString accepted");
    } catch (CodecException e) {
      // expected
    }
  }

}
