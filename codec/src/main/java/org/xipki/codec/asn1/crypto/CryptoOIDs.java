// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * OIDs used for this module.
 * @author Lijun Liao (xipki)
 */
public interface CryptoOIDs {

  /**  1.2.840.113549.2.7 */
  Asn1Oid id_hmacWithSHA1        = new Asn1Oid("1.2.840.113549.2.7");

  /** PKCS#1: 1.2.840.113549.1.1.8 */
  Asn1Oid id_mgf1                 = new Asn1Oid("1.2.840.113549.1.1.8");

  /** PKCS#1: 1.2.840.113549.1.1.9 */
  Asn1Oid id_pSpecified           = new Asn1Oid("1.2.840.113549.1.1.9");

  /** OID: 1.3.14.3.2.26 */
  Asn1Oid idSHA1                  = new Asn1Oid("1.3.14.3.2.26");

}
