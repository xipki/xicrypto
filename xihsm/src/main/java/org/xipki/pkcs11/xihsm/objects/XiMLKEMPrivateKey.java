// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.pkcs11.xihsm.util.XiConstants;

import java.util.Arrays;
import java.util.List;

/**
 * Xi MLKEMPrivate Key.
 * <p>
 * PKCS#11 v3.2, section 6.68.3: CKA_SEED is the seed (d || z, 64 bytes) of ML-KEM.KeyGen, and
 * CKA_VALUE the decapsulation key dk of FIPS 203, both raw. At least one of them is present.
 *
 * @author Lijun Liao (xipki)
 */
public class XiMLKEMPrivateKey extends XiPrivateKey {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final XiConstants.P11MlkemVariant variant;

  /**
   * The seed d || z, may be null.
   */
  private final byte[] seed;

  /**
   * The decapsulation key dk of FIPS 203, may be null if only the seed is known and the crypto
   * backend cannot compute dk.
   */
  private final byte[] value;

  /**
   * Constructor.
   * @param seed the seed d || z (64 bytes), may be null.
   * @param value the decapsulation key dk of FIPS 203, may be null. Computed from the seed if
   *        null.
   * @throws HsmException if both seed and value are null, their lengths are invalid, or they
   *         do not match.
   */
  public XiMLKEMPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, long handle, boolean inToken,
      Long keyGenMechanism, XiConstants.P11MlkemVariant variant, byte[] seed, byte[] value)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, PKCS11T.CKK_ML_KEM, keyGenMechanism);
    this.variant = Args.notNull(variant, "variant");

    if (seed == null && value == null) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCOMPLETE,
          "at least one of CKA_SEED and CKA_VALUE must be present");
    }

    if (seed != null && seed.length != XiConstants.P11MlkemVariant.SEED_SIZE) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "invalid length of CKA_SEED: " + seed.length);
    }

    if (value != null && value.length != variant.getDkSize()) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "invalid length of CKA_VALUE: " + value.length + " != " + variant.getDkSize());
    }

    if (seed != null) {
      byte[] expanded = expand(variant, seed);
      if (expanded != null) {
        if (value == null) {
          value = expanded;
        } else if (!Arrays.equals(expanded, value)) {
          throw new HsmException(PKCS11T.CKR_TEMPLATE_INCONSISTENT,
              "CKA_SEED and CKA_VALUE do not match");
        }
      }
    }

    this.seed = seed;
    this.value = value;
  }

  /**
   * Computes dk from the seed.
   * @return dk, or null if the crypto backend cannot compute it.
   */
  private static byte[] expand(XiConstants.P11MlkemVariant variant, byte[] seed) {
    try {
      return cryptoApi.expandMlkemSeed(variant.getCryptoVariant(), seed);
    } catch (UnsupportedOperationException e) {
      return null;
    }
  }

  /**
   * Returns the PKCS#8 encoded private key, the privateKey is the ML-KEM-PrivateKey of
   * RFC 9935.
   */
  @Override
  public byte[] getEncoded() throws HsmException {
    try {
      return KeyInfoUtil.buildPrivateKeyInfo(variant.getOid(),
          new MlkemPrivateKey(seed, value).getEncoded()).getEncoded();
    } catch (CodecException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error encoding " + getClass().getName(),
          ex);
    }
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs) throws HsmException {
    XiTemplateChecker.assertMlkemPrivateKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, PKCS11T.CKA_PARAMETER_SET, variant.getCode());

    if (withAll || isRevealable()) {
      if (seed != null) {
        addAttr(res, types, PKCS11T.CKA_SEED, seed);
      }

      if (value != null) {
        addAttr(res, types, PKCS11T.CKA_VALUE, value);
      }
    }
  }

  @Override
  public byte[] decapsulateKey(XiMechanism mechanism, byte[] encapsulatedKey)
      throws HsmException {
    // the crypto backends accept the seed (64 bytes) and dk
    byte[] sk = (seed != null) ? seed : value;
    try {
      return cryptoApi.decapsulateKey(variant.getCryptoVariant(), sk, encapsulatedKey);
    } catch (RuntimeException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error decapsulating key", e);
    }
  }

  public static XiMLKEMPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, LoginState loginState,
      ObjectInitMethod initMethod, long handle, boolean inToken, XiTemplate attrs,
      Long keyGenMechanism) throws HsmException {
    long variantCode = attrs.removeNonNullLong(PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MlkemVariant variant = XiConstants.P11MlkemVariant.ofCode(variantCode);
    byte[] seed = attrs.removeByteArray(PKCS11T.CKA_SEED);
    byte[] value = attrs.removeByteArray(PKCS11T.CKA_VALUE);

    XiMLKEMPrivateKey ret = new XiMLKEMPrivateKey(vendor, cku,
        newObjectMethod, handle, inToken, keyGenMechanism, variant, seed, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
