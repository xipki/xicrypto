// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * BASE64 encoding tests.
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractBase64Test {

  private static final int startLen = 0;

  private static final int endLen = 200;

  private static final Random rnd = new Random();

  protected abstract String jdkEncode(byte[] data);

  protected abstract byte[] encodeToByte(byte[] data, boolean wrapLongLine, boolean withPadding);

  protected abstract String encodeToString(byte[] data, boolean wrapLongLine, boolean withPadding);

  protected abstract byte[] decode(byte[] data);

  protected abstract byte[] decode(String data);

  protected abstract byte[] decodeFast(byte[] data);

  protected abstract byte[] decodeFast(String data);

  @Test
  public void testEncodeWrapLineWithPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineWithPadding", data, true, true);
    }
  }

  @Test
  public void testEncodeWrapLineNoPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineNoPadding", data, true, false);
    }
  }

  @Test
  public void testEncodeSingleLineWithPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineWithPadding", data, false, true);
    }
  }

  @Test
  public void testEncodeSingleLineNoPadding() {
    for (int len = startLen; len < endLen; len++) {
      byte[] data = new byte[len];
      rnd.nextBytes(data);
      check("testEncodeWrapLineNoPadding", data, false, false);
    }
  }

  @Test
  public void testDecodeWrap64() {
    // e.g. EST responses wrapped at 64 characters
    byte[] data = new byte[1000];
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i * 7);
    }

    String encoded = java.util.Base64.getMimeEncoder(64, new byte[] {'\r', '\n'})
        .encodeToString(data) + "\r\n";
    Assert.assertArrayEquals(data, decode(encoded));
    Assert.assertArrayEquals(data, decodeFast(encoded));
    byte[] encodedBytes = encoded.getBytes(StandardCharsets.US_ASCII);
    Assert.assertArrayEquals(data, decode(encodedBytes));
    Assert.assertArrayEquals(data, decodeFast(encodedBytes));
  }

  @Test
  public void testDecodeInvalid() {
    String[] invalids = {"=", "==", "A", "AB=", "AB===", "A=BC", "AB*C", "ABCD\u0100", "AB\"C"};
    for (String invalid : invalids) {
      Assert.assertThrows("decode " + invalid, IllegalArgumentException.class,
          () -> decode(invalid));
      Assert.assertThrows("decodeFast " + invalid, IllegalArgumentException.class,
          () -> decodeFast(invalid));
      if (invalid.indexOf('\u0100') == -1) {
        byte[] bytes = invalid.getBytes(StandardCharsets.US_ASCII);
        Assert.assertThrows("decode(byte[]) " + invalid, IllegalArgumentException.class,
            () -> decode(bytes));
        Assert.assertThrows("decodeFast(byte[]) " + invalid, IllegalArgumentException.class,
            () -> decodeFast(bytes));
      }
    }

    // whitespaces around the data are allowed
    Assert.assertArrayEquals(new byte[] {0}, decodeFast(" AA== \r\n"));
    Assert.assertArrayEquals(new byte[] {0}, decode(" AA== \r\n"));
    Assert.assertArrayEquals(new byte[0], decodeFast("  "));
  }

  private void check(String desc, byte[] data, boolean wrapLongLine, boolean withPadding) {
    int len = data.length;

    System.out.println(desc + " len=" + len);

    String expectedEncoded = jdkEncode(data);

    if (!withPadding) {
      if (expectedEncoded.endsWith("==")) {
        expectedEncoded = expectedEncoded.substring( 0, expectedEncoded.length() - 2);
      } else if (expectedEncoded.endsWith("=")) {
        expectedEncoded = expectedEncoded.substring( 0, expectedEncoded.length() - 1);
      }
    }

    if (wrapLongLine) {
      int numCharsPerLine = 76;
      int eLen = expectedEncoded.length();
      if (eLen > numCharsPerLine) {
        StringBuilder sb = new StringBuilder(
            expectedEncoded.length() + eLen / numCharsPerLine * 2 + 2);

        int index = 0;
        while (index < eLen) {
          int blen = Math.min(numCharsPerLine, eLen - index);
          sb.append(expectedEncoded, index, index + blen);
          sb.append("\r\n");
          index += blen;
        }
        sb.delete(sb.length() - 2, sb.length());
        expectedEncoded = sb.toString();
      }
    }

    // encodeToString
    {
      String encodedStr = encodeToString(data, wrapLongLine, withPadding);
      Assert.assertEquals(expectedEncoded, encodedStr);

      byte[] decodedFast = decodeFast(encodedStr);
      Assert.assertArrayEquals(data, decodedFast);

      byte[] decoded = decode(encodedStr);
      Assert.assertArrayEquals(data, decoded);
    }

    // encodeToByte
    {
      byte[] encodedBytes = encodeToByte(data, wrapLongLine, withPadding);
      Assert.assertEquals(expectedEncoded, new String(encodedBytes, StandardCharsets.US_ASCII));

      byte[] decodedFast = decodeFast(encodedBytes);
      Assert.assertArrayEquals(data, decodedFast);

      byte[] decoded = decode(encodedBytes);
      Assert.assertArrayEquals(data, decoded);
    }
  }

}
