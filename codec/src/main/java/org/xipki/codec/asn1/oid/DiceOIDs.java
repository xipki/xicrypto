// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.oid;

import org.xipki.codec.asn1.Asn1Oid;

/**
 * @author Lijun Liao (xipki)
 */
public final class DiceOIDs {

  private DiceOIDs() {
  }

  public static final Asn1Oid tcg_dice = OIDs.initOid("2.23.133.5.4", "tcg-dice");

  public static final Asn1Oid tcg_dice_ueid = OIDs.initOid("2.23.133.5.4.4", "tcg-dice-ueid");

  public static final Asn1Oid tcg_dice_kp_identityInit = OIDs.initOid(
      "2.23.133.5.4.100.6", "tcg-dice-kp-identityInit");

  public static final Asn1Oid tcg_dice_kp_identityLoc = OIDs.initOid(
      "2.23.133.5.4.100.7", "tcg-dice-kp-identityLoc");

  public static final Asn1Oid tcg_dice_kp_attestInit = OIDs.initOid(
      "2.23.133.5.4.100.8", "tcg-dice-kp-attestInit");

  public static final Asn1Oid tcg_dice_kp_attestLoc = OIDs.initOid(
      "2.23.133.5.4.100.9", "tcg-dice-kp-attestLoc");

  public static final Asn1Oid tcg_dice_kp_assertInit = OIDs.initOid(
      "2.23.133.5.4.100.10", "tcg-dice-kp-assertInit");

  public static final Asn1Oid tcg_dice_kp_assertLoc = OIDs.initOid(
      "2.23.133.5.4.100.11", "tcg-dice-kp-assertLoc");

  public static final Asn1Oid tcg_dice_kp_eca = OIDs.initOid(
      "2.23.133.5.4.100.12", "tcg-dice-kp-eca");

}
