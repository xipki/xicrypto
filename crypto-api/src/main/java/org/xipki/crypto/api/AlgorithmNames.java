// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.GmOIDs;
import org.xipki.codec.asn1.oid.IanaOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;

import java.util.HashMap;
import java.util.Map;

/**
 * Backend-neutral mapping of algorithm OIDs to JCA standard names.
 *
 * @author Lijun Liao (xipki)
 */
public final class AlgorithmNames {

  private static final Map<Asn1Oid, String> DIGEST_NAMES = new HashMap<>();

  private static final Map<Asn1Oid, String> HMAC_NAMES = new HashMap<>();

  static {
    DIGEST_NAMES.put(OiwOIDs.idSHA1,           "SHA-1");
    DIGEST_NAMES.put(NistOIDs.id_sha224,       "SHA-224");
    DIGEST_NAMES.put(NistOIDs.id_sha256,       "SHA-256");
    DIGEST_NAMES.put(NistOIDs.id_sha384,       "SHA-384");
    DIGEST_NAMES.put(NistOIDs.id_sha512,       "SHA-512");
    DIGEST_NAMES.put(NistOIDs.id_sha512_224,   "SHA-512/224");
    DIGEST_NAMES.put(NistOIDs.id_sha512_256,   "SHA-512/256");
    DIGEST_NAMES.put(NistOIDs.id_sha3_224,     "SHA3-224");
    DIGEST_NAMES.put(NistOIDs.id_sha3_256,     "SHA3-256");
    DIGEST_NAMES.put(NistOIDs.id_sha3_384,     "SHA3-384");
    DIGEST_NAMES.put(NistOIDs.id_sha3_512,     "SHA3-512");
    DIGEST_NAMES.put(NistOIDs.id_shake128,     "SHAKE128-256");
    DIGEST_NAMES.put(NistOIDs.id_shake256,     "SHAKE256-512");
    DIGEST_NAMES.put(GmOIDs.sm3,               "SM3");

    HMAC_NAMES.put(IanaOIDs.hmacSHA1,              "HmacSHA1");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA1,       "HmacSHA1");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA224,     "HmacSHA224");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA256,     "HmacSHA256");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA384,     "HmacSHA384");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA512,     "HmacSHA512");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA512_224, "HmacSHA512/224");
    HMAC_NAMES.put(PkcsOIDs.id_hmacWithSHA512_256, "HmacSHA512/256");
    HMAC_NAMES.put(NistOIDs.id_hmacWithSHA3_224,   "HmacSHA3-224");
    HMAC_NAMES.put(NistOIDs.id_hmacWithSHA3_256,   "HmacSHA3-256");
    HMAC_NAMES.put(NistOIDs.id_hmacWithSHA3_384,   "HmacSHA3-384");
    HMAC_NAMES.put(NistOIDs.id_hmacWithSHA3_512,   "HmacSHA3-512");
  }

  private AlgorithmNames() {
  }

  /**
   * Returns the JCA standard name of the digest algorithm, e.g. "SHA-256".
   * @param oid the digest algorithm OID.
   * @return the name, or the dotted OID if the algorithm is unknown.
   */
  public static String getDigestName(Asn1Oid oid) {
    String name = DIGEST_NAMES.get(oid);
    return name != null ? name : oid.getId();
  }

  /**
   * Returns the JCA standard name of the HMAC algorithm, e.g. "HmacSHA256".
   * @param oid the HMAC algorithm OID.
   * @return the name, or null if the algorithm is unknown.
   */
  public static String getHmacName(Asn1Oid oid) {
    return HMAC_NAMES.get(oid);
  }

}
