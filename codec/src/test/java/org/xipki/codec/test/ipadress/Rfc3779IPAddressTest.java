// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.ipadress;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.ipadress.IPAddressFamily;
import org.xipki.codec.ipadress.Rfc3779IPAddress;

import java.util.Random;

/**
 * Tests for {@link Rfc3779IPAddress}.
 *
 * @author Lijun Liao (xipki)
 */
public class Rfc3779IPAddressTest {

  private static void assertPrefix(boolean ipv4, String str, String expectedHex,
                                   int expectedUnusedBits, String expectedString) {
    Rfc3779IPAddress addr =
        Rfc3779IPAddress.getInstance(ipv4, str, Rfc3779IPAddress.Context.PREFIX);
    Assert.assertEquals(str, expectedHex, Hex.encode(addr.value()));
    Assert.assertEquals(str, expectedUnusedBits, addr.unusedBits());

    int afi = ipv4 ? IPAddressFamily.AFI_IPv4 : IPAddressFamily.AFI_IPv6;
    Assert.assertEquals(str, expectedString, addr.toString(afi, Rfc3779IPAddress.Context.PREFIX));
  }

  @Test
  public void zeroLengthPrefix() {
    assertPrefix(true, "0.0.0.0/0", "", 0, "0.0.0.0/0");
    assertPrefix(false, "::/0", "", 0, "::/0");
    // the host bits are not part of the prefix.
    assertPrefix(true, "1.2.3.4/0", "", 0, "0.0.0.0/0");
  }

  @Test
  public void nonZeroLengthPrefix() {
    assertPrefix(true, "10.0.0.0/20", "0a0000", 4, "10.0.0.0/20");
    assertPrefix(true, "192.168.1.5/24", "c0a801", 0, "192.168.1.0/24");
    assertPrefix(true, "1.2.3.4", "01020304", 0, "1.2.3.4/32");
    assertPrefix(false, "2001:db8::/32", "20010db8", 0, "2001:db8::/32");
  }

  @Test
  public void zeroLengthRangeBoundaries() {
    Rfc3779IPAddress empty = new Rfc3779IPAddress(new byte[0]);
    int v4 = IPAddressFamily.AFI_IPv4;
    int v6 = IPAddressFamily.AFI_IPv6;
    Assert.assertEquals("0.0.0.0", empty.toString(v4, Rfc3779IPAddress.Context.RANGE_MIN));
    Assert.assertEquals("255.255.255.255", empty.toString(v4, Rfc3779IPAddress.Context.RANGE_MAX));
    Assert.assertEquals("0::", empty.toString(v6, Rfc3779IPAddress.Context.RANGE_MIN));
    Assert.assertEquals("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        empty.toString(v6, Rfc3779IPAddress.Context.RANGE_MAX));
  }

  private static void assertRange(boolean ipv4, Rfc3779IPAddress.Context context, String str,
                                  String expectedHex, int expectedUnusedBits) {
    Rfc3779IPAddress addr = Rfc3779IPAddress.getInstance(ipv4, str, context);
    String desc = context + " " + str;
    Assert.assertEquals(desc, expectedHex, Hex.encode(addr.value()));
    Assert.assertEquals(desc, expectedUnusedBits, addr.unusedBits());
  }

  @Test
  public void rangeMinEncoding() {
    Rfc3779IPAddress.Context ctx = Rfc3779IPAddress.Context.RANGE_MIN;
    assertRange(true, ctx, "10.1.2.3", "0a010203", 0);
    assertRange(true, ctx, "10.0.0.0", "0a", 1);
    assertRange(true, ctx, "0.1.0.0", "0001", 0);
    assertRange(true, ctx, "192.168.0.0", "c0a8", 3);
    assertRange(true, ctx, "0.0.0.0", "", 0);
    assertRange(false, ctx, "2001:db8::", "20010db8", 3);
    assertRange(false, ctx, "::", "", 0);
  }

  @Test
  public void rangeMaxEncoding() {
    Rfc3779IPAddress.Context ctx = Rfc3779IPAddress.Context.RANGE_MAX;
    assertRange(true, ctx, "10.1.2.3", "0a010200", 2);
    assertRange(true, ctx, "10.255.255.255", "0a", 0);
    assertRange(true, ctx, "127.255.255.255", "00", 7);
    assertRange(true, ctx, "192.168.255.255", "c0a8", 0);
    assertRange(true, ctx, "192.168.1.255", "c0a800", 1);
    assertRange(true, ctx, "0.0.1.255", "000000", 1);
    assertRange(true, ctx, "255.255.255.255", "", 0);
    assertRange(false, ctx, "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "20010db8", 0);
    assertRange(false, ctx, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "", 0);
  }

  @Test
  public void c509RangeEncodingUsesWholeBytes() {
    assertRange(true, Rfc3779IPAddress.Context.C509_RANGE_MIN, "192.168.0.0", "c0a8", 0);
    assertRange(true, Rfc3779IPAddress.Context.C509_RANGE_MIN, "10.0.0.0", "0a", 0);
    assertRange(true, Rfc3779IPAddress.Context.C509_RANGE_MAX, "192.168.1.255", "c0a801", 0);
    assertRange(true, Rfc3779IPAddress.Context.C509_RANGE_MAX, "127.255.255.255", "7f", 0);
  }

  @Test
  public void rangeRoundTrip() {
    Random rnd = new Random(1);
    Rfc3779IPAddress.Context[] contexts =
        {Rfc3779IPAddress.Context.RANGE_MIN, Rfc3779IPAddress.Context.RANGE_MAX};
    for (Rfc3779IPAddress.Context context : contexts) {
      for (int i = 0; i < 100_000; i++) {
        long bits = rnd.nextInt() & 0xFFFFFFFFL;
        long defaultBits = (1L << rnd.nextInt(33)) - 1;
        bits = (context == Rfc3779IPAddress.Context.RANGE_MAX)
            ? bits | defaultBits : bits & ~defaultBits;
        String str = (bits >>> 24) + "." + ((bits >>> 16) & 0xFF) + "."
            + ((bits >>> 8) & 0xFF) + "." + (bits & 0xFF);

        Rfc3779IPAddress addr = Rfc3779IPAddress.getIPv4Instance(str, context);
        Assert.assertEquals(context + " " + str, str,
            addr.toString(IPAddressFamily.AFI_IPv4, context));
      }
    }
  }

  @Test
  public void invalidConstructorArguments() {
    Assert.assertThrows(IllegalArgumentException.class, () -> new Rfc3779IPAddress(new byte[0], 1));
    Assert.assertThrows(NullPointerException.class, () -> new Rfc3779IPAddress(null));
  }

  @Test
  public void parseSevenSegmentsWithDoubleColon() {
    assertPrefix(false, "1:2:3:4:5:6:7::",
        "00010002000300040005000600070000", 0, "1:2:3:4:5:6:7::/128");
    assertPrefix(false, "::2:3:4:5:6:7:8",
        "00000002000300040005000600070008", 0, "0:2:3:4:5:6:7:8/128");
  }

  @Test
  public void getInstanceAcceptsEmbeddedIpv4() {
    Rfc3779IPAddress addr =
        Rfc3779IPAddress.getIPv6Instance("::ffff:1.2.3.4", Rfc3779IPAddress.Context.PREFIX);
    Assert.assertEquals("00000000000000000000ffff01020304", Hex.encode(addr.value()));
    Assert.assertEquals(0, addr.unusedBits());
  }

  @Test
  public void getInstanceRejectsMisplacedOrInvalidEmbeddedIpv4() {
    String[] invalids = {"1.2.3.4::", "::1.2", "::1.2.3.256"};
    for (String invalid : invalids) {
      Assert.assertThrows(invalid, IllegalArgumentException.class,
          () -> Rfc3779IPAddress.getIPv6Instance(invalid, Rfc3779IPAddress.Context.PREFIX));
    }
  }

}
