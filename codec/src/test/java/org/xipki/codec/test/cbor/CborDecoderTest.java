// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.cbor;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.cbor.StreamCborDecoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.ByteArrayInputStream;

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
      Assert.assertEquals("{a=1, b=[2, 3]}", String.valueOf(decoder.readNext()));
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
    Assert.assertEquals(java.math.BigInteger.valueOf(10),
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

  private static CborDecoder[] decoders(byte[] encoded) {
    return new CborDecoder[] {new ByteArrayCborDecoder(encoded),
        new StreamCborDecoder(new ByteArrayInputStream(encoded))};
  }

}
