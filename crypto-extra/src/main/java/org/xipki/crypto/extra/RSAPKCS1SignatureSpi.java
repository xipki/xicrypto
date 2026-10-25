// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.DigestInfo;

import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * RSASSA-PKCS1-v1_5 (RFC 8017, section 8.2) with a hash of the {@link Primitives}, used for
 * SHA3-224, SHA3-256, SHA3-384 and SHA3-512 on the JDKs without these signatures (JDK 11 to 15).
 * <p>
 * The DigestInfo has the AlgorithmIdentifier with NULL parameters (RFC 8017, A.2.4), as written
 * by the JDK and BouncyCastle. The verification computes the expected encoding and compares it in
 * constant time (RFC 8017, 8.2.2); the DigestInfo is not parsed.
 *
 * @author Lijun Liao (xipki)
 */
public class RSAPKCS1SignatureSpi extends RsaSignatureSpi {

  private final Asn1Oid hashOid;

  /**
   * Constructor.
   * @param primitives the source of the digest and the raw RSA operation.
   * @param digestAlg the JCA name of the hash, e.g. "SHA3-256".
   * @param hashOid the OID of the hash, for the DigestInfo.
   */
  public RSAPKCS1SignatureSpi(Primitives primitives, String digestAlg, Asn1Oid hashOid) {
    super(primitives, digest(primitives, digestAlg));
    this.hashOid = hashOid;
  }

  /**
   * EMSA-PKCS1-v1_5-ENCODE (RFC 8017, 9.2): 0x00 || 0x01 || PS (0xFF) || 0x00 || DigestInfo.
   */
  @Override
  byte[] encode(byte[] hash, int modBits) throws SignatureException {
    int emLen = (modBits + 7) / 8;
    byte[] t = new DigestInfo(AlgorithmIdentifier.ofNullParams(hashOid), hash)
        .getEncoded(Asn1Encoding.DER);
    if (emLen < t.length + 11) {
      throw new SignatureException("RSA key too small for " + hashOid.getId());
    }
    byte[] em = new byte[emLen];
    em[1] = 0x01;
    Arrays.fill(em, 2, emLen - t.length - 1, (byte) 0xFF);
    System.arraycopy(t, 0, em, emLen - t.length, t.length);
    return em;
  }

  @Override
  boolean matches(byte[] hash, byte[] m, int modBits) {
    try {
      return MessageDigest.isEqual(encode(hash, modBits), m);
    } catch (SignatureException e) {
      // key too small for the hash
      return false;
    }
  }

}
