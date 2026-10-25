// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class X9OIDs {

  private X9OIDs() {
  }

  public static final Asn1Oid id_fieldType = OIDs.initOid("1.2.840.10045.1", "id-fieldType");

  public static final Asn1Oid prime_field = OIDs.initOid("1.2.840.10045.1.1", "prime-field");

  public static final Asn1Oid characteristic_two_field = OIDs.initOid(
      "1.2.840.10045.1.2", "characteristic-two-field");

  public static final Asn1Oid gnBasis = OIDs.initOid("1.2.840.10045.1.2.3.1", "gnBasis");

  public static final Asn1Oid tpBasis = OIDs.initOid("1.2.840.10045.1.2.3.2", "tpBasis");

  public static final Asn1Oid ppBasis = OIDs.initOid("1.2.840.10045.1.2.3.3", "ppBasis");

  public static final Asn1Oid id_ecSigType = OIDs.initOid("1.2.840.10045.4", "id-ecSigType");

  public static final Asn1Oid ecdsa_with_SHA1 = OIDs.initOid(
      "1.2.840.10045.4.1", "ecdsa-with-SHA1");

  public static final Asn1Oid id_publicKeyType = OIDs.initOid(
      "1.2.840.10045.2", "id-publicKeyType");

  public static final Asn1Oid id_ecPublicKey = OIDs.initOid("1.2.840.10045.2.1", "id-ecPublicKey");

  public static final Asn1Oid ecdsa_with_SHA2 = OIDs.initOid(
      "1.2.840.10045.4.3", "ecdsa-with-SHA2");

  public static final Asn1Oid ecdsa_with_SHA224 = OIDs.initOid(
      "1.2.840.10045.4.3.1", "ecdsa-with-SHA224");

  public static final Asn1Oid ecdsa_with_SHA256 = OIDs.initOid(
      "1.2.840.10045.4.3.2", "ecdsa-with-SHA256");

  public static final Asn1Oid ecdsa_with_SHA384 = OIDs.initOid(
      "1.2.840.10045.4.3.3", "ecdsa-with-SHA384");

  public static final Asn1Oid ecdsa_with_SHA512 = OIDs.initOid(
      "1.2.840.10045.4.3.4", "ecdsa-with-SHA512");

  public static final Asn1Oid primeCurve = OIDs.initOid("1.2.840.10045.3.1", "primeCurve");

  public static final Asn1Oid prime192v1 = OIDs.initOid("1.2.840.10045.3.1.1", "secp192r1");

  public static final Asn1Oid prime192v2 = OIDs.initOid("1.2.840.10045.3.1.2", "prime192v2");

  public static final Asn1Oid prime192v3 = OIDs.initOid("1.2.840.10045.3.1.3", "prime192v3");

  public static final Asn1Oid prime239v1 = OIDs.initOid("1.2.840.10045.3.1.4", "prime239v1");

  public static final Asn1Oid prime239v2 = OIDs.initOid("1.2.840.10045.3.1.5", "prime239v2");

  public static final Asn1Oid prime239v3 = OIDs.initOid("1.2.840.10045.3.1.6", "prime239v3");

  public static final Asn1Oid prime256v1 = OIDs.initOid("1.2.840.10045.3.1.7", "secp256r1");

  public static final Asn1Oid id_dsa = OIDs.initOid("1.2.840.10040.4.1", "id-dsa");

  public static final Asn1Oid id_dsa_with_sha1 = OIDs.initOid(
      "1.2.840.10040.4.3", "id-dsa-with-sha1");

  public static final Asn1Oid dhSinglePass_stdDH_sha1kdf_scheme = OIDs.initOid(
      "1.3.133.16.840.63.0.2", "dhSinglePass-stdDH-sha1kdf-scheme");

  public static final Asn1Oid dhSinglePass_cofactorDH_sha1kdf_scheme = OIDs.initOid(
      "1.3.133.16.840.63.0.3", "dhSinglePass-cofactorDH-sha1kdf-scheme");

  public static final Asn1Oid mqvSinglePass_sha1kdf_scheme = OIDs.initOid(
      "1.3.133.16.840.63.0.16", "mqvSinglePass-sha1kdf-scheme");

  public static final Asn1Oid dhpublicnumber = OIDs.initOid("1.2.840.10046.2.1", "dhpublicnumber");

  public static final Asn1Oid dhStatic = OIDs.initOid("1.2.840.10046.3.1", "dhStatic");

  public static final Asn1Oid dhEphem = OIDs.initOid("1.2.840.10046.3.2", "dhEphem");

  public static final Asn1Oid dhOneFlow = OIDs.initOid("1.2.840.10046.3.3", "dhOneFlow");

  public static final Asn1Oid dhHybrid1 = OIDs.initOid("1.2.840.10046.3.4", "dhHybrid1");

  public static final Asn1Oid dhHybrid2 = OIDs.initOid("1.2.840.10046.3.5", "dhHybrid2");

  public static final Asn1Oid dhHybridOneFlow = OIDs.initOid(
      "1.2.840.10046.3.6", "dhHybridOneFlow");

  public static final Asn1Oid mqv2 = OIDs.initOid("1.2.840.10046.3.7", "mqv2");

  public static final Asn1Oid mqv1 = OIDs.initOid("1.2.840.10046.3.8", "mqv1");

  public static final Asn1Oid x9_44 = OIDs.initOid("1.3.133.16.840.9.44", "x9-44");

  public static final Asn1Oid x9_44_components = OIDs.initOid(
      "1.3.133.16.840.9.44.1", "x9-44-components");

  public static final Asn1Oid id_kdf_kdf2 = OIDs.initOid("1.3.133.16.840.9.44.1.1", "id-kdf-kdf2");

  public static final Asn1Oid id_kdf_kdf3 = OIDs.initOid("1.3.133.16.840.9.44.1.2", "id-kdf-kdf3");

}
