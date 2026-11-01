// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Base64;
import org.xipki.codec.Base64.DecodeOption;

import java.nio.charset.StandardCharsets;

/**
 * Tests the decoders of {@link Base64} with {@link DecodeOption}.
 *
 * @author Lijun Liao (xipki)
 */
public class Base64DecodeOptionTest {

  @FunctionalInterface
  private interface Decoder {
    byte[] decode(String text, DecodeOption option);
  }

  /** 0xFB 0xFF: the characters 62 and 63 of the alphabets ('+' '/' or '-' '_'). */
  private static final byte[] DATA = {(byte) 0xFB, (byte) 0xFF, 'x', 'y', 'z'};

  private static final String STD = "+/94eXo=";

  private static final String URL = "-_94eXo=";

  private static final String COMMON = "eHl6"; // "xyz", in both alphabets

  private static final Decoder[] DECODERS = {
      Base64::decode,
      Base64::decodeFast,
      (s, o) -> Base64.decode(s.toCharArray(), o),
      (s, o) -> Base64.decodeFast(s.toCharArray(), o),
      (s, o) -> Base64.decode(s.getBytes(StandardCharsets.US_ASCII), o),
      (s, o) -> Base64.decodeFast(s.getBytes(StandardCharsets.US_ASCII), o)};

  @Test
  public void testOptions() {
    for (int i = 0; i < DECODERS.length; i++) {
      Decoder dec = DECODERS[i];
      String desc = "decoder " + i;

      Assert.assertArrayEquals(desc, DATA, dec.decode(STD, DecodeOption.ANY));
      Assert.assertArrayEquals(desc, DATA, dec.decode(URL, DecodeOption.ANY));
      Assert.assertArrayEquals(desc, DATA, dec.decode(STD, DecodeOption.BASE64_ONLY));
      Assert.assertArrayEquals(desc, DATA, dec.decode(URL, DecodeOption.BASE64URL_ONLY));
      assertRejected(desc, dec, STD, DecodeOption.BASE64URL_ONLY);
      assertRejected(desc, dec, URL, DecodeOption.BASE64_ONLY);

      // without padding, and with the characters common to both alphabets
      String unpadded = URL.substring(0, URL.length() - 1);
      Assert.assertArrayEquals(desc, DATA, dec.decode(unpadded, DecodeOption.BASE64URL_ONLY));
      for (DecodeOption option : DecodeOption.values()) {
        Assert.assertArrayEquals(desc + " " + option, "xyz".getBytes(StandardCharsets.US_ASCII),
            dec.decode(COMMON, option));
      }
    }
  }

  /** The decoders without option accept both alphabets. */
  @Test
  public void testWithoutOption() {
    for (String text : new String[]{STD, URL}) {
      byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
      Assert.assertArrayEquals(DATA, Base64.decode(text));
      Assert.assertArrayEquals(DATA, Base64.decodeFast(text));
      Assert.assertArrayEquals(DATA, Base64.decode(text.toCharArray()));
      Assert.assertArrayEquals(DATA, Base64.decodeFast(text.toCharArray()));
      Assert.assertArrayEquals(DATA, Base64.decode(bytes));
      Assert.assertArrayEquals(DATA, Base64.decodeFast(bytes));
    }
  }

  /** decodeFast falls back to decode for inner whitespaces, with the same option. */
  @Test
  public void testFastWithWhitespace() {
    String std = "+/94\neXo=";
    Assert.assertArrayEquals(DATA, Base64.decodeFast(std, DecodeOption.BASE64_ONLY));
    assertRejected("fallback", Base64::decodeFast, std, DecodeOption.BASE64URL_ONLY);
  }

  private static void assertRejected(String desc, Decoder dec, String text,
                                     DecodeOption option) {
    try {
      dec.decode(text, option);
      Assert.fail(desc + ": " + text + " accepted with " + option);
    } catch (IllegalArgumentException e) {
      // expected
    }
  }

}
