// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.c509;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.x509.SubjectPublicKeyInfo;
import org.xipki.codec.c509.C509KeyPair;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.C509SubjectPublicKeyInfo;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * C509SubjectPublicKeyInfo: encoding, decoding and conversion from and to X.509.
 *
 * @author Lijun Liao (xipki)
 */
public class C509SubjectPublicKeyInfoTest {

  private static void check(C509SubjectPublicKey key) throws Exception {
    C509SubjectPublicKeyInfo info = new C509SubjectPublicKeyInfo(key);
    byte[] encoded = info.getEncoded();

    // an array of 2 elements around the two fields of the TBSCertificate
    byte[] fields = key.getEncoded();
    Assert.assertEquals((byte) 0x82, encoded[0]);
    Assert.assertArrayEquals(fields, Arrays.copyOfRange(encoded, 1, encoded.length));

    C509SubjectPublicKeyInfo copy = C509SubjectPublicKeyInfo.parse(encoded);
    Assert.assertEquals(info, copy);
    Assert.assertEquals(info.hashCode(), copy.hashCode());
    Assert.assertArrayEquals(encoded, copy.getEncoded());

    SubjectPublicKeyInfo x509 = info.toX509SubjectPublicKey();
    Assert.assertEquals(info, C509SubjectPublicKeyInfo.fromSubjectPublicKeyInfo(x509));
  }

  @Test
  public void ecKey() throws Exception {
    check(C509KeyPair.generateECKeyPair(ConstPublicKeyAlgorithm.ec_secp256r1, false)
        .subjectPublicKey());
    check(C509KeyPair.generateECKeyPair(ConstPublicKeyAlgorithm.ec_secp384r1, true)
        .subjectPublicKey());
  }

  @Test
  public void rsaKey() throws Exception {
    // F4: the modulus only
    check(C509KeyPair.generateRSAKeyPair(2048).subjectPublicKey());
    // another exponent: [modulus, exponent]
    check(C509KeyPair.generateRSAKeyPair(2048, BigInteger.valueOf(3)).subjectPublicKey());
  }

  @Test
  public void ed25519Key() throws Exception {
    check(C509KeyPair.generateKeyPair(ConstPublicKeyAlgorithm.ed25519).subjectPublicKey());
  }

  @Test
  public void invalidArrayLength() {
    // [12, h'00', 0]: 3 elements
    Assert.assertThrows(CodecException.class,
        () -> C509SubjectPublicKeyInfo.parse(Hex.decode("830c410000")));
  }

}
