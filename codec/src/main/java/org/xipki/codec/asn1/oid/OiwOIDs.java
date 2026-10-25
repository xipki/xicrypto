// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class OiwOIDs {

  private OiwOIDs() {
  }

  public static final Asn1Oid md5WithRSA = OIDs.initOid("1.3.14.3.2.3", "md5WithRSA");

  public static final Asn1Oid desECB = OIDs.initOid("1.3.14.3.2.6", "desECB");

  public static final Asn1Oid desCBC = OIDs.initOid("1.3.14.3.2.7", "desCBC");

  public static final Asn1Oid desOFB = OIDs.initOid("1.3.14.3.2.8", "desOFB");

  public static final Asn1Oid desCFB = OIDs.initOid("1.3.14.3.2.9", "desCFB");

  public static final Asn1Oid desEDE = OIDs.initOid("1.3.14.3.2.17", "desEDE");

  public static final Asn1Oid idSHA1 = OIDs.initOid("1.3.14.3.2.26", "SHA1");

  public static final Asn1Oid dsaWithSHA1 = OIDs.initOid("1.3.14.3.2.27", "dsaWithSHA1");

  public static final Asn1Oid sha1WithRSA = OIDs.initOid("1.3.14.3.2.29", "sha1WithRSA");

  public static final Asn1Oid elGamalAlgorithm = OIDs.initOid("1.3.14.7.2.1.1", "elGamalAlgorithm");

}
