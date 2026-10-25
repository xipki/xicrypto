// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.bouncycastle.asn1.*;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1Set;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.Hex;

import java.math.BigInteger;
import java.util.Random;

/**
 * @author Lijun Liao (xipki)
 */
public class Asn1BerPrimitiveTest {

  @Test
  public void testBerSequence() throws Exception {
    byte[] bcBerEncoded = new BERSequence(new ASN1Integer(BigInteger.ONE)).getEncoded();
    byte[] bcDerEncoded = new DERSequence(new ASN1Integer(BigInteger.ONE)).getEncoded();

    // decode
    String title = "SEQUENCE BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Sequence);
    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testImplicitTaggedBerSequence() throws Exception {
    testTaggedBerSequence(false);
  }

  @Test
  public void testExplicitTaggedBerSequence() throws Exception {
    testTaggedBerSequence(true);
  }

  private void testTaggedBerSequence(boolean explicit) throws Exception {
    byte[] bcBerEncoded = new BERTaggedObject(explicit, 1,
        new BERSequence(new ASN1Integer(BigInteger.ONE))).getEncoded();
    byte[] bcDerEncoded = new DERTaggedObject(explicit, 1,
        new BERSequence(new ASN1Integer(BigInteger.ONE))).getEncoded();

    System.out.println("BER: " + Hex.encode(bcBerEncoded));
    System.out.println("DER: " + Hex.encode(bcDerEncoded));

    ASN1StreamParser bcParser = new ASN1StreamParser(bcBerEncoded);
    ASN1Encodable bcO = bcParser.readObject();

    // decode
    String title = "Tagged SEQUENCE BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1TaggedObject);

    Asn1TaggedObject to = (Asn1TaggedObject) dv;
    if (explicit) {
      Assert.assertTrue(title + ": decoded class content",
          to.getExplicitBase() instanceof Asn1Sequence);
    } else {
      to.getImplicitSequenceBase();
    }

    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testBerSequence2() throws Exception {
    byte[] value = new byte[1200];
    new Random().nextBytes(value);

    byte[] bcBerEncoded = new BERSequence(new BEROctetString(value)).getEncoded();
    byte[] bcDerEncoded = new DERSequence(new DEROctetString(value)).getEncoded();

    // decode
    String title = "SEQUENCE BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Sequence);
    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testImplicitTaggedBerSequence2() throws Exception {
    testTaggedBerSequence2(false);
  }

  @Test
  public void testExplicitTaggedBerSequence2() throws Exception {
    testTaggedBerSequence2(true);
  }

  private void testTaggedBerSequence2(boolean explicit) throws Exception {
    byte[] value = new byte[1200];
    new Random().nextBytes(value);

    byte[] bcBerEncoded = new BERTaggedObject(explicit, 1,
        new BERSequence(new BEROctetString(value))).getEncoded();
    byte[] bcDerEncoded = new BERTaggedObject(explicit, 1,
        new DERSequence(new DEROctetString(value))).getEncoded("DER");

    // decode
    String title = "SEQUENCE BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);

    Asn1TaggedObject to = (Asn1TaggedObject) dv;
    if (explicit) {
      Assert.assertTrue(title + ": decoded class content",
          to.getExplicitBase() instanceof Asn1Sequence);
    } else {
      to.getImplicitSequenceBase();
    }

    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testBerSet() throws Exception {
    byte[] bcBerEncoded = new BERSet(new ASN1Integer(BigInteger.ONE)).getEncoded();
    byte[] bcDerEncoded = new DERSet(new ASN1Integer(BigInteger.ONE)).getEncoded();

    // decode
    String title = "SET BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Set);
    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testImplicitTaggedBerSet() throws Exception {
    testTaggedBerSet(false);
  }

  @Test
  public void testExplicitTaggedBerSet() throws Exception {
    testTaggedBerSet(true);
  }

  private void testTaggedBerSet(boolean explicit) throws Exception {
    byte[] bcBerEncoded = new BERTaggedObject(explicit, 1,
        new BERSet(new ASN1Integer(BigInteger.ONE))).getEncoded();
    byte[] bcDerEncoded = new DERTaggedObject(explicit, 1,
        new DERSet(new ASN1Integer(BigInteger.ONE))).getEncoded("DER");

    System.out.println("BER: " + Hex.encode(bcBerEncoded));
    System.out.println("DER: " + Hex.encode(bcDerEncoded));

    // decode
    String title = "SET BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);

    Asn1TaggedObject to = (Asn1TaggedObject) dv;
    if (explicit) {
      Assert.assertTrue(title + ": decoded class content",
          to.getExplicitBase() instanceof Asn1Set);
    } else {
      to.getImplicitSetBase();
    }

    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testBerSet2() throws Exception {
    byte[] value = new byte[1200];
    new Random().nextBytes(value);

    byte[] bcBerEncoded = new BERSet(new BEROctetString(value)).getEncoded();
    byte[] bcDerEncoded = new DERSet(new DEROctetString(value)).getEncoded();

    // decode
    String title = "SET BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1Set);
    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

  @Test
  public void testImplicitTaggedBerSet2() throws Exception {
    testTaggedBerSet2(false);
  }

  @Test
  public void testExplicitTaggedBerSet2() throws Exception {
    testTaggedBerSet2(true);
  }

  private void testTaggedBerSet2(boolean explicit) throws Exception {
    byte[] value = new byte[1200];
    new Random().nextBytes(value);

    byte[] bcBerEncoded = new BERTaggedObject(explicit, 1,
        new BERSet(new BEROctetString(value))).getEncoded();
    byte[] bcDerEncoded = new BERTaggedObject(explicit, 1,
        new DERSet(new DEROctetString(value))).getEncoded("DER");

    // decode
    String title = "SET BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);

    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1TaggedObject);

    Asn1TaggedObject to = (Asn1TaggedObject) dv;
    if (explicit) {
      Assert.assertTrue(title + ": decoded class content",
          to.getExplicitBase() instanceof Asn1Set);
    } else {
      to.getImplicitSetBase();
    }

    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertEquals(title + ": DER re-encoded",
        Hex.encode(bcDerEncoded), Hex.encode(derEncoded));
  }

  @Test
  public void testBerOctetString() throws Exception {
    byte[] value = new byte[1200];
    new Random().nextBytes(value);

    byte[] bcBerEncoded = new BEROctetString(value).getEncoded();
    byte[] bcDerEncoded = new DEROctetString(value).getEncoded();

    // decode
    String title = "OCTET STRING BER Test";
    Asn1Primitive dv = Asn1Util.readAsn1Object(bcBerEncoded);
    Assert.assertTrue(title + ": decoded class", dv instanceof Asn1OctetString);
    byte[] derEncoded = dv.getEncoded(Asn1Encoding.DER);
    Assert.assertArrayEquals(title + ": DER re-encoded", bcDerEncoded, derEncoded);
  }

}
