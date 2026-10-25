// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class BsiOIDs {

  private BsiOIDs() {
  }

  public static final Asn1Oid ecdsa_plain_SHA1 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.1", "ecdsa-plain-SHA1");

  public static final Asn1Oid ecdsa_plain_SHA224 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.2", "ecdsa-plain-SHA224");

  public static final Asn1Oid ecdsa_plain_SHA256 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.3", "ecdsa-plain-SHA256");

  public static final Asn1Oid ecdsa_plain_SHA384 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.4", "ecdsa-plain-SHA384");

  public static final Asn1Oid ecdsa_plain_SHA512 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.5", "ecdsa-plain-SHA512");

  public static final Asn1Oid ecdsa_plain_RIPEMD160 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.6", "ecdsa-plain-RIPEMD160");

  public static final Asn1Oid ecdsa_plain_SHA3_224 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.8", "ecdsa-plain-SHA3-224");

  public static final Asn1Oid ecdsa_plain_SHA3_256 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.9", "ecdsa-plain-SHA3-256");

  public static final Asn1Oid ecdsa_plain_SHA3_384 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.10", "ecdsa-plain-SHA3-384");

  public static final Asn1Oid ecdsa_plain_SHA3_512 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.4.1.11", "ecdsa-plain-SHA3-512");

  public static final Asn1Oid ecka_eg_X963kdf = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1", "ecka-eg-X963kdf");

  public static final Asn1Oid ecka_eg_X963kdf_SHA1 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1.1", "ecka-eg-X963kdf-SHA1");

  public static final Asn1Oid ecka_eg_X963kdf_SHA224 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1.2", "ecka-eg-X963kdf-SHA224");

  public static final Asn1Oid ecka_eg_X963kdf_SHA256 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1.3", "ecka-eg-X963kdf-SHA256");

  public static final Asn1Oid ecka_eg_X963kdf_SHA384 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1.4", "ecka-eg-X963kdf-SHA384");

  public static final Asn1Oid ecka_eg_X963kdf_SHA512 = OIDs.initOid(
      "0.4.0.127.0.7.1.1.5.1.1.5", "ecka-eg-X963kdf-SHA512");

}
