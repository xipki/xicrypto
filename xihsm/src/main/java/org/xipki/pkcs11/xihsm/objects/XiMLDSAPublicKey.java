// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.codec.util.Args;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiAttribute;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.attr.XiTemplateChecker;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;
import org.xipki.pkcs11.xihsm.util.XiConstants;

import java.util.List;

/**
 * Xi MLDSAPublic Key.
 *
 * @author Lijun Liao (xipki)
 */
public class XiMLDSAPublicKey extends XiPublicKey {

  private final XiConstants.P11MldsaVariant variant;

  private final byte[] value;

  public XiMLDSAPublicKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      XiConstants.P11MldsaVariant variant, byte[] value) throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, PKCS11T.CKK_ML_DSA, keyGenMechanism);

    this.variant = Args.notNull(variant, "variant");
    this.value = Args.notNull(value, "value");
    // the raw public key of FIPS 203 / 204, not the SubjectPublicKeyInfo
    if (value.length != variant.getPkSize()) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "invalid length of CKA_VALUE (pk): " + value.length + " != " + variant.getPkSize());
    }
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs) throws HsmException {
    XiTemplateChecker.assertMldsaPublicKeyAttributesSettable(attrs);
  }

  @Override
  protected void doGetAttributes(List<XiAttribute> res, long[] types, boolean withAll)
      throws HsmException {
    super.doGetAttributes(res, types, withAll);
    addAttr(res, types, PKCS11T.CKA_PARAMETER_SET, variant.getCode());
    addAttr(res, types, PKCS11T.CKA_VALUE, value);
  }

  public static XiMLDSAPublicKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, LoginState loginState,
      ObjectInitMethod initMethod, long handle, boolean inToken, XiTemplate attrs,
      Long keyGenMechanism) throws HsmException {
    long variantCode = attrs.removeNonNullLong(PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MldsaVariant variant = XiConstants.P11MldsaVariant.ofCode(variantCode);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiMLDSAPublicKey ret = new XiMLDSAPublicKey(vendor, cku, newObjectMethod,
                              handle, inToken, keyGenMechanism, variant, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
