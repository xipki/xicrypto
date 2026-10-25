// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * EC Curve OIDs.
 *
 * @author Lijun Liao (xipki)
 */
public class CurveOIDs {

  public static final Asn1Oid id_X25519 = AlgorithmOIDs.id_X25519;

  public static final Asn1Oid id_X448 = AlgorithmOIDs.id_X448;

  public static final Asn1Oid id_ED25519 = AlgorithmOIDs.id_Ed25519;

  public static final Asn1Oid id_ED448 = AlgorithmOIDs.id_Ed448;

  public static final Asn1Oid sm2p256v1 = GmOIDs.sm2p256v1;

  public static final Asn1Oid frp256v1 = OIDs.initOid("1.2.250.1.223.101.256.1", "frp256v1");

  public static final Asn1Oid secp192r1 = X9OIDs.prime192v1;

  public static final Asn1Oid secp224r1 = OIDs.initOid("1.3.132.0.33", "secp224r1");

  public static final Asn1Oid secp256r1 = X9OIDs.prime256v1;

  public static final Asn1Oid secp384r1 = OIDs.initOid("1.3.132.0.34", "secp384r1");

  public static final Asn1Oid secp521r1 = OIDs.initOid("1.3.132.0.35", "secp521r1");

  public static final Asn1Oid brainpoolP192r1 = TeleTrustOIDs.brainpoolP192r1;

  public static final Asn1Oid brainpoolP224r1 = TeleTrustOIDs.brainpoolP224r1;

  public static final Asn1Oid brainpoolP256r1 = TeleTrustOIDs.brainpoolP256r1;

  public static final Asn1Oid brainpoolP384r1 = TeleTrustOIDs.brainpoolP384r1;

  public static final Asn1Oid brainpoolP512r1 = TeleTrustOIDs.brainpoolP512r1;

}
