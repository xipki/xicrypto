// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1RelativeOid;
import org.xipki.codec.asn1.Asn1StreamParser;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.DssSigValue;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tests the limits against the malicious ASN.1 input, analog to the BouncyCastle CVEs
 * CVE-2025-8885 (huge OID), CVE-2026-13506 (nesting depth across lazy decoding) and
 * CVE-2026-14682 (allocation of the declared length).
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1ResourceLimitTest {

  private static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    int n = value.length;
    if (n < 0x80) {
      out.write(n);
    } else if (n < 0x100) {
      out.write(0x81);
      out.write(n);
    } else if (n < 0x10000) {
      out.write(0x82);
      out.write(n >> 8);
      out.write(n);
    } else {
      out.write(0x83);
      out.write(n >> 16);
      out.write(n >> 8);
      out.write(n);
    }
    out.writeBytes(value);
    return out.toByteArray();
  }

  private static BufferedInputStream stream(String hex) {
    return new BufferedInputStream(new ByteArrayInputStream(Hex.decode(hex)));
  }

  /**
   * Encoded OID 1.2.(one huge arc), the arc consists of n - 1 bytes.
   */
  private static byte[] hugeOidContent(int n) {
    byte[] v = new byte[n];
    Arrays.fill(v, (byte) 0xFF);
    v[0] = 0x2A;
    v[n - 1] = 0x01;
    return v;
  }

  @Test
  public void testOidLength() throws Exception {
    int max = Asn1Oid.MAX_ENCODED_LENGTH;
    Asn1Primitive p = Asn1Util.readAsn1Object(tlv(0x06, hugeOidContent(max)));
    Assert.assertTrue(p instanceof Asn1Oid);

    try {
      Asn1Util.readAsn1Object(tlv(0x06, hugeOidContent(max + 1)));
      Assert.fail("OID longer than " + max + " bytes accepted");
    } catch (CodecException ex) {
      // expected
    }

    try {
      Asn1Util.readAsn1Object(tlv(0x0D, hugeOidContent(max + 1)));
      Assert.fail("RELATIVE-OID longer than " + max + " bytes accepted");
    } catch (CodecException ex) {
      // expected
    }

    StringBuilder sb = new StringBuilder("1.2");
    while (sb.length() <= Asn1Oid.MAX_STRING_LENGTH) {
      sb.append(".1");
    }

    try {
      new Asn1Oid(sb.toString());
      Assert.fail("OID string longer than " + Asn1Oid.MAX_STRING_LENGTH + " accepted");
    } catch (IllegalArgumentException ex) {
      // expected
    }

    try {
      new Asn1RelativeOid(sb.substring(4));
      Assert.fail("RELATIVE-OID string longer than " + Asn1Oid.MAX_STRING_LENGTH + " accepted");
    } catch (IllegalArgumentException ex) {
      // expected
    }
  }

  @Test
  public void testSequenceWithTrailingElement() throws Exception {
    String r = "0221008f" + "ff".repeat(31);
    String s = "0220" + "11".repeat(32);
    DssSigValue.fromEncoded(Hex.decode("3045" + r + s));

    try {
      DssSigValue.fromEncoded(Hex.decode("3047" + r + s + "0500"));
      Assert.fail("SEQUENCE with trailing element accepted");
    } catch (CodecException ex) {
      // expected
    }
  }

  @Test
  public void testStreamParserReadBlock() throws Exception {
    String value = "11".repeat(200);
    String block = "3081c8" + value;
    BufferedInputStream is = stream(block + "0500");
    Assert.assertEquals(block, Hex.encode(Asn1StreamParser.readBlock(is, "block")));
    Assert.assertEquals(value,
        Hex.encode(Asn1StreamParser.readValue(0x05, stream("0581c8" + value), "value")));
    // the remaining NULL
    Assert.assertEquals("0500", Hex.encode(Asn1StreamParser.readBlock(is, "NULL")));
  }

  @Test(timeout = 10000)
  public void testStreamParserTruncatedSkip() throws Exception {
    // INTEGER with declared length 100, but only 2 bytes.
    try {
      Asn1StreamParser.skipField(stream("02640102"));
      Assert.fail("truncated input accepted");
    } catch (EOFException ex) {
      // expected
    }
  }

  @Test
  public void testStreamParserHugeLength() throws Exception {
    // declared length 0x7ffffff0 in 7 bytes, shall not allocate the declared length.
    try {
      Asn1StreamParser.readBlock(stream("30847ffffff000"), "block");
      Assert.fail("truncated input accepted");
    } catch (EOFException ex) {
      // expected
    }
  }

  @Test
  public void testStreamParserInvalidLength() {
    String[] invalids = {
        "30800000",     // indefinite length
        "308480000000", // length with the highest bit set
        "3085010000000000", // 5 length bytes
        "30",           // missing length
        "308201",       // truncated length
    };

    for (String invalid : invalids) {
      try {
        Asn1StreamParser.readBlock(stream(invalid), "block");
        Assert.fail("invalid length accepted: " + invalid);
      } catch (IOException ex) {
        // expected
      }
    }
  }

  /**
   * The definite-length values of the tagged objects are decoded by new decoders while being
   * DER-encoded. The nesting depth limit shall apply across them.
   */
  @Test
  public void testNestedTaggedObjects() throws Throwable {
    // levels of: [0] EXPLICIT SEQUENCE^98 {...}
    byte[] encoded = Hex.decode("0500");
    for (int level = 0; level < 70; level++) {
      for (int i = 0; i < 98; i++) {
        encoded = tlv(0x30, encoded);
      }
      encoded = tlv(0xa0, encoded);
    }
    final byte[] input = tlv(0x30, encoded);

    AtomicReference<Throwable> error = new AtomicReference<>();
    // run in a thread with small stack: about 6800 nested objects would overflow it.
    Thread thread = new Thread(null, () -> {
      try {
        Asn1Primitive p = Asn1Util.readAsn1Object(input);
        Assert.assertArrayEquals(input, p.getEncoded(Asn1Encoding.DER));
        p.hashCode();
        Assert.assertEquals(p, Asn1Util.readAsn1Object(input));
      } catch (Throwable t) {
        error.set(t);
      }
    }, "nested", 256 * 1024);
    thread.start();
    thread.join();

    if (error.get() != null) {
      throw error.get();
    }
  }

  /**
   * The BER-encoded nested tagged objects shall still be converted to DER.
   */
  @Test
  public void testNestedTaggedObjectsToDer() throws Exception {
    // [0] { [1] { SEQUENCE (indefinite) { NULL } } }
    byte[] ber = Hex.decode("300a" + "a008" + "a106" + "308005000000");
    byte[] der = Asn1Util.readAsn1Object(ber).getEncoded(Asn1Encoding.DER);
    Assert.assertEquals("3008" + "a006" + "a104" + "30020500", Hex.encode(der));
  }

}
