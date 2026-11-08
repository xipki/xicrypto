// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.ipadress;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.ipadress.IPAddressUtil;

/**
 * Tests for {@link IPAddressUtil}.
 *
 * @author Lijun Liao (xipki)
 */
public class IPAddressUtilTest {

  private static void assertEncoding(String expectedHex, String ip) {
    byte[] encoded = IPAddressUtil.ipAddrToGeneralNameEncoding(ip);
    Assert.assertNotNull(ip, encoded);
    Assert.assertEquals(ip, expectedHex, Hex.encode(encoded));
  }

  @Test
  public void ipv4() {
    assertEncoding("c0a80105", "192.168.1.5");
  }

  @Test
  public void ipv4WithMask() {
    assertEncoding("c0a80105ffffff00", "192.168.1.5/24");
    assertEncoding("c0a80105ffffff00", "192.168.1.5/255.255.255.0");
    assertEncoding("0a000000fffff000", "10.0.0.0/20");
    assertEncoding("0000000000000000", "0.0.0.0/0");
    assertEncoding("01020304ffffffff", "1.2.3.4/32");
  }

  @Test
  public void ipv6() {
    assertEncoding("20010db8000000000000000000000001", "2001:db8::1");
    assertEncoding("00000000000000000000000000000000", "::");
    assertEncoding("00000000000000000000000000000001", "::1");
    assertEncoding("00010000000000000000000000000000", "1::");
    assertEncoding("00010002000300040005000600070008", "1:2:3:4:5:6:7:8");
  }

  @Test
  public void ipv6WithEmbeddedIpv4() {
    assertEncoding("00000000000000000000ffff01020304", "::ffff:1.2.3.4");
    assertEncoding("00010002000300040005000601020304", "1:2:3:4:5:6:1.2.3.4");
    assertEncoding("000000000000000000000000fffefdfc", "::255.254.253.252");
  }

  @Test
  public void ipv6WithMask() {
    assertEncoding("20010db8000000000000000000000001ffffffffffffffff0000000000000000",
        "2001:db8::1/64");
    assertEncoding("20010db8000000000000000000000001ffffffff000000000000000000000000",
        "2001:db8::1/ffff:ffff::");
    assertEncoding("0000000000000000000000000000000100000000000000000000000000000fff",
        "::1/::fff");
    assertEncoding("00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
        "::/128");
    assertEncoding("0000000000000000000000000000000000000000000000000000000000000000",
        "::/0");
  }

  @Test
  public void invalidAddresses() {
    String[] invalids = {"", "abc", "1.2.3", "1.2.3.256", "1.2.3.4/33", "1.2.3.4/",
        ":", ":1:2", "1:2:", "1::2:", ":1::2", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9",
        "::/129", "::1.2.3"};
    for (String invalid : invalids) {
      Assert.assertNull(invalid, IPAddressUtil.ipAddrToGeneralNameEncoding(invalid));
    }
  }

  @Test
  public void validIpv6() {
    String[] valids = {"::", "::1", "1::", "1:2:3:4:5:6:7:8",
        // "::" stands for exactly one segment at the start, in the middle and at the end.
        "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3::5:6:7:8",
        // embedded IPv4 covers two segments.
        "::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "::2:3:4:5:6:1.2.3.4", "1:2:3:4:5::1.2.3.4"};
    for (String valid : valids) {
      Assert.assertTrue(valid, IPAddressUtil.isValidIPv6(valid));
    }
  }

  @Test
  public void invalidIpv6() {
    String[] invalids = {"", ":", ":::", "1", "1:2", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9",
        // "::" with eight other segments leaves no segment for it.
        "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1:2:3:4::5:6:7:8",
        "1:2:3:4:5:6::1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "1.2.3.4",
        "1::2::3", "::1::", ":1:2", "1:2:", "12345::", "g::"};
    for (String invalid : invalids) {
      Assert.assertFalse(invalid, IPAddressUtil.isValidIPv6(invalid));
    }
  }

}
