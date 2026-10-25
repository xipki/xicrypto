// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class GmOIDs {

  private GmOIDs() {
  }

  public static final Asn1Oid sm4_ecb = OIDs.initOid("1.2.156.10197.1.104.1", "sm4-ecb");

  public static final Asn1Oid sm4_cbc = OIDs.initOid("1.2.156.10197.1.104.2", "sm4-cbc");

  public static final Asn1Oid sm4_gcm = OIDs.initOid("1.2.156.10197.1.104.8", "sm4-gcm");

  public static final Asn1Oid sm4_ccm = OIDs.initOid("1.2.156.10197.1.104.9", "sm4-ccm");

  public static final Asn1Oid sm4_xts = OIDs.initOid("1.2.156.10197.1.104.10", "sm4-xts");

  public static final Asn1Oid sm4_wrap = OIDs.initOid("1.2.156.10197.1.104.11", "sm4-wrap");

  public static final Asn1Oid sm4_wrap_pad = OIDs.initOid(
      "1.2.156.10197.1.104.12", "sm4-wrap-pad");

  public static final Asn1Oid sm4_ocb = OIDs.initOid("1.2.156.10197.1.104.100", "sm4-ocb");

  public static final Asn1Oid sm2p256v1 = OIDs.initOid("1.2.156.10197.1.301", "sm2p256v1");

  public static final Asn1Oid sm2sign = OIDs.initOid("1.2.156.10197.1.301.1", "sm2sign");

  public static final Asn1Oid sm2exchange = OIDs.initOid("1.2.156.10197.1.301.2", "sm2exchange");

  public static final Asn1Oid sm2encrypt_with_sm3 = OIDs.initOid(
      "1.2.156.10197.1.301.3.2.1", "sm2encrypt-with-sm3");

  public static final Asn1Oid sm3 = OIDs.initOid("1.2.156.10197.1.401", "sm3");

  public static final Asn1Oid hmac_sm3 = OIDs.initOid("1.2.156.10197.1.401.2", "hmac-sm3");

  public static final Asn1Oid sm2sign_with_sm3 = OIDs.initOid(
      "1.2.156.10197.1.501", "sm2sign-with-sm3");

}
