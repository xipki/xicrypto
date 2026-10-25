// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class TeleTrustOIDs {

  private TeleTrustOIDs() {
  }

  public static final Asn1Oid ripemd160 = OIDs.initOid("1.3.36.3.2.1", "ripemd160");

  public static final Asn1Oid ripemd256 = OIDs.initOid("1.3.36.3.2.3", "ripemd256");

  public static final Asn1Oid teleTrustRSAsignatureAlgorithm = OIDs.initOid(
      "1.3.36.3.3.1", "teleTrustRSAsignatureAlgorithm");

  public static final Asn1Oid rsaSignatureWithripemd160 = OIDs.initOid(
      "1.3.36.3.3.1.2", "rsaSignatureWithripemd160");

  public static final Asn1Oid rsaSignatureWithripemd256 = OIDs.initOid(
      "1.3.36.3.3.1.4", "rsaSignatureWithripemd256");

  public static final Asn1Oid ecSignWithSha1 = OIDs.initOid("1.3.36.3.3.2.1", "ecSignWithSha1");

  public static final Asn1Oid ecSignWithRipemd160 = OIDs.initOid(
      "1.3.36.3.3.2.2", "ecSignWithRipemd160");

  public static final Asn1Oid brainpoolP160r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1");

  public static final Asn1Oid brainpoolP160t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.2", "brainpoolP160t1");

  public static final Asn1Oid brainpoolP192r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.3", "brainpoolP192r1");

  public static final Asn1Oid brainpoolP192t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.4", "brainpoolP192t1");

  public static final Asn1Oid brainpoolP224r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.5", "brainpoolP224r1");

  public static final Asn1Oid brainpoolP224t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.6", "brainpoolP224t1");

  public static final Asn1Oid brainpoolP256r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1");

  public static final Asn1Oid brainpoolP256t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.8", "brainpoolP256t1");

  public static final Asn1Oid brainpoolP320r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.9", "brainpoolP320r1");

  public static final Asn1Oid brainpoolP320t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.10", "brainpoolP320t1");

  public static final Asn1Oid brainpoolP384r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1");

  public static final Asn1Oid brainpoolP384t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.12", "brainpoolP384t1");

  public static final Asn1Oid brainpoolP512r1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1");

  public static final Asn1Oid brainpoolP512t1 = OIDs.initOid(
      "1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1");

}
