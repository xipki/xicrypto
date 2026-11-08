// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.asn1;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.exception.CodecException;

/**
 * Unexpected tags must cause a {@link CodecException}, and no unchecked exception.
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1TagCheckTest {

  private static void assertInvalidSequence(String hex) {
    byte[] encoded = Hex.decode(hex);
    Assert.assertThrows(hex, CodecException.class, () -> Asn1Sequence.fromEncoded(encoded));
  }

  private static void assertInvalidTaggedSequence(String hex) throws CodecException {
    Asn1Sequence seq = Asn1Sequence.fromEncoded(Hex.decode(hex));
    Assert.assertThrows(hex, CodecException.class, () -> seq.getSequenceTaggedAt(0, true));
  }

  @Test
  public void sameTagNumberOfOtherClass() {
    assertInvalidSequence("7000"); // application
    assertInvalidSequence("b000"); // context-specific
    assertInvalidSequence("f000"); // private
  }

  @Test
  public void messageNamesTheTagClass() throws CodecException {
    CodecException ex = Assert.assertThrows(CodecException.class,
        () -> Asn1Sequence.fromEncoded(Hex.decode("7000")));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains(
        "application with tag 16, but expected universal with tag 16"));

    Asn1Sequence seq = Asn1Sequence.fromEncoded(Hex.decode("3006a28070000000"));
    ex = Assert.assertThrows(CodecException.class, () -> seq.getSequenceTaggedAt(0, true));
    Assert.assertTrue(ex.getMessage(), ex.getMessage().contains(
        "tagged with tagNo 16, but expected universal with tagNo 16"));
  }

  @Test
  public void primitiveSequence() {
    assertInvalidSequence("1000");
    assertInvalidSequence("30021000");
  }

  @Test
  public void explicitBaseOfOtherType() throws CodecException {
    assertInvalidTaggedSequence("3005a203040100");   // OCTET STRING
    assertInvalidTaggedSequence("3004a2027000");     // application class
    assertInvalidTaggedSequence("3006a28004000000"); // indefinite, OCTET STRING
    assertInvalidTaggedSequence("3006a28070000000"); // indefinite, application class
  }

  @Test
  public void explicitBaseOfExpectedType() throws CodecException {
    Asn1Sequence seq = Asn1Sequence.fromEncoded(Hex.decode("3004a2023000"));
    Assert.assertEquals(0, seq.getSequenceTaggedAt(0, true).size());

    // indefinite length
    seq = Asn1Sequence.fromEncoded(Hex.decode("3006a28030000000"));
    Assert.assertEquals(0, seq.getSequenceTaggedAt(0, true).size());
  }

}
