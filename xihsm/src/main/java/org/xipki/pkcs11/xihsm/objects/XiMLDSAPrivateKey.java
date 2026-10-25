// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.NullParams;
import org.xipki.pkcs11.wrapper.params.SIGN_ADDITIONAL_CONTEXT;
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

import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;

/**
 * Xi MLDSAPrivate Key.
 * <p>
 * PKCS#11 v3.2, section 6.67.3: CKA_SEED is the seed (xi, 32 bytes) of ML-DSA.KeyGen, and
 * CKA_VALUE the private key sk of ML-DSA.KeyGen_internal of FIPS 204, both raw. At least one
 * of them is present.
 *
 * @author Lijun Liao (xipki)
 */
public class XiMLDSAPrivateKey extends XiPrivateKey {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final XiConstants.P11MldsaVariant variant;

  /**
   * The seed xi, may be null.
   */
  private final byte[] seed;

  /**
   * The private key sk of FIPS 204, may be null if only the seed is known and the crypto
   * backend cannot compute sk.
   */
  private final byte[] value;

  private final java.security.PrivateKey jceKey;

  /**
   * Constructor.
   * @param seed the seed xi (32 bytes), may be null.
   * @param value the private key sk of FIPS 204, may be null. Computed from the seed if null.
   * @throws HsmException if both seed and value are null, their lengths are invalid, or they
   *         do not match.
   */
  public XiMLDSAPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      long handle, boolean inToken, Long keyGenMechanism,
      XiConstants.P11MldsaVariant variant, byte[] seed, byte[] value) throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken, PKCS11T.CKK_ML_DSA, keyGenMechanism);
    this.variant = Args.notNull(variant, "variant");

    if (seed == null && value == null) {
      throw new HsmException(PKCS11T.CKR_TEMPLATE_INCOMPLETE,
          "at least one of CKA_SEED and CKA_VALUE must be present");
    }

    if (seed != null && seed.length != XiConstants.P11MldsaVariant.SEED_SIZE) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "invalid length of CKA_SEED: " + seed.length);
    }

    if (value != null && value.length != variant.getSkSize()) {
      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID,
          "invalid length of CKA_VALUE: " + value.length + " != " + variant.getSkSize());
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

    try {
      this.jceKey = cryptoApi.getPrivateKey(KeyInfoUtil.buildPrivateKeyInfo(variant.getOid(),
          new MldsaPrivateKey(seed, value).getEncoded()));
    } catch (Exception e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error building JCE ML-DSA private key");
    }
  }

  /**
   * Computes sk from the seed.
   * @return sk, or null if the crypto backend cannot compute it.
   */
  private static byte[] expand(XiConstants.P11MldsaVariant variant, byte[] seed) {
    try {
      return cryptoApi.expandMldsaSeed(variant.getCryptoVariant(), seed);
    } catch (UnsupportedOperationException e) {
      return null;
    }
  }

  /**
   * Returns the PKCS#8 encoded private key, the privateKey is the ML-DSA-PrivateKey of
   * RFC 9881.
   */
  @Override
  public byte[] getEncoded() throws HsmException {
    try {
      return KeyInfoUtil.buildPrivateKeyInfo(variant.getOid(),
          new MldsaPrivateKey(seed, value).getEncoded()).getEncoded();
    } catch (CodecException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error encoding " + getClass().getName(), ex);
    }
  }

  @Override
  protected void assertAttributesSettable(XiTemplate attrs) throws HsmException {
    XiTemplateChecker.assertMldsaPrivateKeyAttributesSettable(attrs);
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
  public byte[] sign(XiMechanism mechanism, byte[] data, SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED, "CKA_SIGN != TRUE");
    }

    long ckm = mechanism.getCkm();
    if (ckm != PKCS11T.CKM_ML_DSA) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "Invalid mechanism " + PKCS11T.ckmCodeToName(ckm));
    }

    byte[] context = null;
    CkParams params = mechanism.getParameter();
    if (params != null && !params.equals(NullParams.INSTANCE)) {
      if (!(params instanceof SIGN_ADDITIONAL_CONTEXT)) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "Mechanism.parameters is not a CK_SIGN_ADDITIONAL_CONTEXT");
      }

      SIGN_ADDITIONAL_CONTEXT sac = (SIGN_ADDITIONAL_CONTEXT) params;
      // The signatures are always hedged.
      if (sac.hedgeVariant() == PKCS11T.CKH_DETERMINISTIC_REQUIRED) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "deterministic ML-DSA signature is not supported");
      } else if (sac.hedgeVariant() != PKCS11T.CKH_HEDGE_PREFERRED
          && sac.hedgeVariant() != PKCS11T.CKH_HEDGE_REQUIRED) {
        throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
            "invalid hedgeVariant " + sac.hedgeVariant());
      }

      context = sac.context();
    }

    Signature sig;
    try {
      sig = cryptoApi.newSignature("ML-DSA");
      sig.initSign(jceKey, random);
      if (context != null) {
        KeyInfoUtil.setContext(sig, context);
      }
    } catch (Exception e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "error initializing Signature instance: " + e.getMessage(), e);
    }

    try {
      sig.update(data);
      return sig.sign();
    } catch (Exception e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error sign()", e);
    }
  }

  public static XiMLDSAPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod, long handle,
      boolean inToken, XiTemplate attrs, Long keyGenMechanism) throws HsmException {
    long variantCode = attrs.removeNonNullLong(PKCS11T.CKA_PARAMETER_SET);
    XiConstants.P11MldsaVariant variant = XiConstants.P11MldsaVariant.ofCode(variantCode);
    byte[] seed = attrs.removeByteArray(PKCS11T.CKA_SEED);
    byte[] value = attrs.removeByteArray(PKCS11T.CKA_VALUE);
    XiMLDSAPrivateKey ret = new XiMLDSAPrivateKey(vendor, cku, newObjectMethod,
                              handle, inToken, keyGenMechanism, variant, seed, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

}
