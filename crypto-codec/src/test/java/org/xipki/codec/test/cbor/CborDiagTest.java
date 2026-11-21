// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.cbor;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.cbor.CborDiag;
import org.xipki.codec.Hex;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * CborDiag test.
 *
 * @author Lijun Liao (xipki)
 */
public class CborDiagTest {

  @Test
  public void testIntegers() throws Exception {
    assertDiag("1bffffffffffffffff", "uint64(18446744073709551615)");
    assertDiag("3bffffffffffffffff", "nint64(-18446744073709551616)");
    assertDiag("3b8000000000000000", "nint64(-9223372036854775809)");
    assertDiag("3b0000000000000000", "nint64(-1)");
    assertDiag("3863", "nint8(-100)");
  }

  @Test
  public void testStructures() throws Exception {
    assertDiag("a26161016162820203", "map(2)", "\"a\"", "array[2]");
    assertDiag("9f018202039f0405ffff", "array[*]", "<break>");
    assertDiag("f97c00", "half precision float(Infinity)");
    assertDiag("0102", "1 unused bytes");
  }

  private static void assertDiag(String hex, String... expectedParts) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    new CborDiag(Hex.decode(hex)).print(out);
    String text = out.toString(StandardCharsets.UTF_8.name());
    for (String part : expectedParts) {
      Assert.assertTrue(hex + ": '" + part + "' not in\n" + text, text.contains(part));
    }
  }

}
