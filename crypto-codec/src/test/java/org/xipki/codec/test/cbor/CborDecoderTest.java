// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.cbor;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.ByteArrayCborEncoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.cbor.StreamCborDecoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;

/**
 * CborDecoder test: the byte array and the stream decoder.
 *
 * @author Lijun Liao (xipki)
 */
public class CborDecoderTest {

  @Test
  public void testDecode() throws Exception {
    byte[] encoded = Hex.decode("a26161016162820203");
    for (CborDecoder decoder : decoders(encoded)) {
      Assert.assertEquals("{\"a\": 1, \"b\": [2, 3]}", String.valueOf(decoder.readNext()));
      Assert.assertEquals(9, decoder.streamOffset());
    }
  }

  @Test
  public void testPeekTypes() throws Exception {
    // the stream decoder could only peek 1 byte.
    for (CborDecoder decoder : decoders(Hex.decode("820102"))) {
      CborType[] types = decoder.peek2Types();
      Assert.assertEquals(2, types.length);
      Assert.assertEquals(2, decoder.readArrayLength());
    }
  }

  @Test
  public void testHugeDeclaredLength() throws Exception {
    // text string and byte string with declared length 2^31 - 1, but without content:
    // must be rejected without allocating the declared length.
    for (String hex : new String[] {"7a7fffffff", "5a7fffffff"}) {
      for (CborDecoder decoder : decoders(Hex.decode(hex))) {
        Assert.assertThrows(CodecException.class, decoder::readNext);
      }
    }
  }

  @Test
  public void testHugeArrayAndMapLength() {
    // array and map with declared length 2^31 - 1, but without content:
    // must be rejected without allocating the declared length.
    for (String hex : new String[] {"9a7fffffff", "ba7fffffff", "8301", "a201"}) {
      ByteArrayCborDecoder decoder = new ByteArrayCborDecoder(Hex.decode(hex));
      Assert.assertThrows(hex, CodecException.class, decoder::readNext);
    }
  }

  @Test
  public void testIndefiniteLength() {
    // break is not supported by readNext
    for (String hex : new String[] {"9f01ff", "bf0101ff"}) {
      for (CborDecoder decoder : decoders(Hex.decode(hex))) {
        Assert.assertThrows(hex, CodecException.class, decoder::readNext);
      }
    }
  }

  @Test
  public void testReadUint() throws Exception {
    Assert.assertEquals(BigInteger.valueOf(10),
        new ByteArrayCborDecoder(Hex.decode("0a")).readUint());
    // negative integer -11
    Assert.assertThrows(CodecException.class,
        () -> new ByteArrayCborDecoder(Hex.decode("2a")).readUint());
  }

  @Test
  public void testAlternative() throws Exception {
    // tag 101 [0, ...]: alternative 128
    Assert.assertEquals(128,
        new ByteArrayCborDecoder(Hex.decode("d865820000")).readAlternative());
    // tag 101 [2^64 - 1, ...]: too large
    Assert.assertThrows(CodecException.class, () -> new ByteArrayCborDecoder(
        Hex.decode("d865821bffffffffffffffff00")).readAlternative());
  }

  @Test
  public void testReadEncodedItem() throws Exception {
    String[] items = {
        "00", "17", "1818", "1b7fffffffffffffff", "3bffffffffffffffff", // integers
        "40", "4401020304", "60", "6449455446", // strings
        "5f42010243030405ff", "7f6161ff", // indefinite-length strings
        "80", "83010203", "8301820203820405", // arrays
        "a0", "a26162016161820203", // map, keys not in deterministic order
        "9f018202039f0405ffff", "bf6161016162f5ff", // indefinite-length array and map
        "c11a514b67b0", "d8186449455446", "d9d9f7a1616101", // tags
        "f4", "f5", "f6", "f7", "f820", "f93c00", "fa3fc00000", "fb3ff199999999999a", // simple
        "1900ff", "f90000"}; // non-preferred encodings
    for (String hex : items) {
      // followed by a second item to ensure the first one is read exactly.
      byte[] encoded = Hex.decode(hex + "8301" + hex + "02" + "03");
      for (CborDecoder decoder : decoders(encoded)) {
        CborEncodedItem item = decoder.readEncodedItem();
        Assert.assertEquals(hex, Hex.encode(item.getEncoded()));
        Assert.assertEquals(hex.length() / 2, decoder.streamOffset());
        Assert.assertEquals(hex, "8301" + hex + "02",
            Hex.encode(decoder.readEncodedItem().getEncoded()));
        Assert.assertEquals("03", Hex.encode(decoder.readEncodedItem().getEncoded()));
        Assert.assertEquals(encoded.length, decoder.streamOffset());
      }

      CborEncodedItem item = CborEncodedItem.getInstance(Hex.decode(hex));
      // re-encoding writes the original bytes unchanged
      try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()) {
        encoder.writeArrayStart(1);
        encoder.writeObject(item);
        Assert.assertEquals("81" + hex, Hex.encode(encoder.toByteArray()));
      }
    }
  }

  @Test
  public void testReadEncodedItemThenDecode() throws Exception {
    CborEncodedItem item = new ByteArrayCborDecoder(
        Hex.decode("a26162016161820203")).readEncodedItem();
    Assert.assertTrue(item.type().isMap());
    Assert.assertEquals("{\"a\": [2, 3], \"b\": 1}", String.valueOf(item.decoder().readNext()));
  }

  @Test
  public void testReadEncodedItemInvalid() {
    String[] invalid = {
        "", "18", "1c", "1f", "3f", "df", "ff", "f818", // invalid heads, break, simple value
        "4401", "62", "830102", "a1", "c1", // too short
        "5f01ff", "5f6161ff", "5f5f4101ffff", "5f41", // invalid chunks
        "bf01ff", "9f01", // odd map, missing break
        "5b0000000080000000", "9b7fffffffffffffff", "bb7fffffffffffffff"}; // too long
    for (String hex : invalid) {
      for (CborDecoder decoder : decoders(Hex.decode(hex))) {
        Assert.assertThrows(hex, CodecException.class, decoder::readEncodedItem);
      }
    }

    // trailing bytes
    Assert.assertThrows(CodecException.class,
        () -> CborEncodedItem.getInstance(Hex.decode("0001")));

    // nesting depth
    String deep = "81".repeat(CborDecoder.MAX_ENCODED_ITEM_DEPTH + 1) + "00";
    for (CborDecoder decoder : decoders(Hex.decode(deep))) {
      Assert.assertThrows(CodecException.class, decoder::readEncodedItem);
    }
    String ok = "81".repeat(CborDecoder.MAX_ENCODED_ITEM_DEPTH) + "00";
    for (CborDecoder decoder : decoders(Hex.decode(ok))) {
      try {
        Assert.assertEquals(ok, Hex.encode(decoder.readEncodedItem().getEncoded()));
      } catch (CodecException e) {
        Assert.fail(e.getMessage());
      }
    }
  }

  private static CborDecoder[] decoders(byte[] encoded) {
    return new CborDecoder[] {new ByteArrayCborDecoder(encoded),
        new StreamCborDecoder(new ByteArrayInputStream(encoded))};
  }

}
