// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * Xipki OIDs.
 *
 * @author Lijun Liao (xipki)
 */
public final class XipkiOIDs {

  /**
   * registered PEN for xipki.org: 45522
   */
  private static final Asn1Oid id_xipki = OIDs.initOid("1.3.6.1.4.1.45522", "id-pen-xipki");

  private static final Asn1Oid id_xipki_cmp = OIDs.initOid("1.3.6.1.4.1.45522.2", "id-xipki-cmp");

  public static final Asn1Oid id_xipki_cmp_kem_encapkey = OIDs.initOid(
      "1.3.6.1.4.1.45522.2.3", "id-xipki-cmp-kem-encapkey");

  private static final Asn1Oid id_xipki_alg = OIDs.initOid("1.3.6.1.4.1.45522.3", "id-xipki-alg");

  public static final Asn1Oid id_alg_dhPop_x25519 = OIDs.initOid(
      "1.3.6.1.4.1.45522.3.1", "id-xipki-alg-dhPop-x25519");

  public static final Asn1Oid id_alg_dhPop_x448 = OIDs.initOid(
      "1.3.6.1.4.1.45522.3.2", "id-xipki-alg-dhPop-x448");

  public static final Asn1Oid id_alg_KEM_HMAC_SHA256 = OIDs.initOid(
      "1.3.6.1.4.1.45522.3.3", "id-xipki-alg-KEM-HMAC-SHA256");

  public static final Asn1Oid id_alg_ECIES_hkdfsha256_aes256_gcm = OIDs.initOid(
      "1.3.6.1.4.1.45522.3.4", "idxipki-alg-ECIES_HKDFSHA512_AES256_GCM");

}
