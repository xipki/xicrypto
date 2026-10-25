// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class SecOIDs {

  private SecOIDs() {
  }

  public static final Asn1Oid dhSinglePass_stdDH_sha224kdf_scheme = OIDs.initOid(
      "1.3.132.1.11.0", "dhSinglePass-stdDH-sha224kdf-scheme");

  public static final Asn1Oid dhSinglePass_stdDH_sha256kdf_scheme = OIDs.initOid(
      "1.3.132.1.11.1", "dhSinglePass-stdDH-sha256kdf-scheme");

  public static final Asn1Oid dhSinglePass_stdDH_sha384kdf_scheme = OIDs.initOid(
      "1.3.132.1.11.2", "dhSinglePass-stdDH-sha384kdf-scheme");

  public static final Asn1Oid dhSinglePass_stdDH_sha512kdf_scheme = OIDs.initOid(
      "1.3.132.1.11.3", "dhSinglePass-stdDH-sha512kdf-scheme");

  public static final Asn1Oid dhSinglePass_cofactorDH_sha224kdf_scheme = OIDs.initOid(
      "1.3.132.1.14.0", "dhSinglePass-cofactorDH-sha224kdf-scheme");

  public static final Asn1Oid dhSinglePass_cofactorDH_sha256kdf_scheme = OIDs.initOid(
      "1.3.132.1.14.1", "dhSinglePass-cofactorDH-sha256kdf-scheme");

  public static final Asn1Oid dhSinglePass_cofactorDH_sha384kdf_scheme = OIDs.initOid(
      "1.3.132.1.14.2", "dhSinglePass-cofactorDH-sha384kdf-scheme");

  public static final Asn1Oid dhSinglePass_cofactorDH_sha512kdf_scheme = OIDs.initOid(
      "1.3.132.1.14.3", "dhSinglePass-cofactorDH-sha512kdf-scheme");

  public static final Asn1Oid mqvSinglePass_sha224kdf_scheme = OIDs.initOid(
      "1.3.132.1.15.0", "mqvSinglePass-sha224kdf-scheme");

  public static final Asn1Oid mqvSinglePass_sha256kdf_scheme = OIDs.initOid(
      "1.3.132.1.15.1", "mqvSinglePass-sha256kdf-scheme");

  public static final Asn1Oid mqvSinglePass_sha384kdf_scheme = OIDs.initOid(
      "1.3.132.1.15.2", "mqvSinglePass-sha384kdf-scheme");

  public static final Asn1Oid mqvSinglePass_sha512kdf_scheme = OIDs.initOid(
      "1.3.132.1.15.3", "mqvSinglePass-sha512kdf-scheme");

}
