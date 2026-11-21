// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.c509;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.C509DhSigStaticSignatureValue;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;

/**
 * C509DhSigStaticSignatureValue test.
 *
 * @author Lijun Liao (xipki)
 */
public class C509DhSigStaticSignatureValueTest {

  @Test
  public void messageDigest() throws Exception {
    String hex = "4401020304";
    C509DhSigStaticSignatureValue v = C509DhSigStaticSignatureValue.parse(Hex.decode(hex));
    Assert.assertFalse(v.hasIssuerAndSerialNumber());
    Assert.assertNull(v.issuer());
    Assert.assertEquals(hex, Hex.encode(v.getEncoded()));
  }

  @Test
  public void issuerKeptInOriginalEncoding() throws Exception {
    // [{2: "b", 1: "a"}, h'05', h'01020304']: issuer map keys not in deterministic order
    String issuerHex = "a2026162016161";
    String hex = "83" + issuerHex + "4105" + "4401020304";
    C509DhSigStaticSignatureValue v = C509DhSigStaticSignatureValue.parse(Hex.decode(hex));
    Assert.assertTrue(v.hasIssuerAndSerialNumber());
    Assert.assertEquals(issuerHex, Hex.encode(v.issuer().getEncoded()));
    Assert.assertEquals(BigInteger.valueOf(5), v.serialNumber());
    Assert.assertEquals(hex, Hex.encode(v.getEncoded()));

    C509DhSigStaticSignatureValue built = new C509DhSigStaticSignatureValue(
        Hex.decode("01020304"), CborEncodedItem.getInstance(Hex.decode(issuerHex)),
        BigInteger.valueOf(5));
    Assert.assertEquals(v, built);
    Assert.assertEquals(v.hashCode(), built.hashCode());
  }

  @Test
  public void nullIssuerRejected() {
    Assert.assertThrows(CodecException.class,
        () -> C509DhSigStaticSignatureValue.parse(Hex.decode("83f641054401020304")));
  }

}
