// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.objects;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.crypt.EdwardsCurveEnum;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.pkcs11.xihsm.util.Origin;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

/**
 * Xi Edwards ECPrivate Key.
 *
 * @author Lijun Liao (xipki)
 */
public class XiEdwardsECPrivateKey extends XiECPrivateKey {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final EdwardsCurveEnum curve;

  private final PrivateKey jceSk;

  public XiEdwardsECPrivateKey(
      XiHsmVendor vendor, long cku, Origin newObjectMethod, long handle,
      boolean inToken, Long keyGenMechanism, byte[] ecParams, byte[] sk)
      throws HsmException {
    super(vendor, cku, newObjectMethod, handle, inToken,
        PKCS11T.CKK_EC_EDWARDS, keyGenMechanism, ecParams, sk);

    this.curve = EdwardsCurveEnum.ofEcParamsNonNull(ecParams);
    try {
      PrivateKeyInfo skInfo = new PrivateKeyInfo(
          new AlgorithmIdentifier(Asn1Oid.fromEncoded(curve.getEncodedOid())),
          new Asn1OctetString(sk));
      this.jceSk = cryptoApi.getPrivateKey(skInfo);
    } catch (CodecException | InvalidKeySpecException ex) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          "could not build JCE " + curve + " key", ex);
    }
  }

  public static XiEdwardsECPrivateKey newInstance(
      XiHsmVendor vendor, long cku, Origin newObjectMethod,
      LoginState loginState, ObjectInitMethod initMethod,
      long handle, boolean inToken, XiTemplate attrs, Long keyGenMechanism)
      throws HsmException {
    byte[] ecParams = attrs.removeNonNullByteArray(PKCS11T.CKA_EC_PARAMS);
    byte[] value = attrs.removeNonNullByteArray(PKCS11T.CKA_VALUE);

    XiEdwardsECPrivateKey ret = new XiEdwardsECPrivateKey(vendor, cku,
        newObjectMethod, handle, inToken, keyGenMechanism, ecParams, value);
    ret.updateAttributes(loginState, initMethod, attrs);
    return ret;
  }

  @Override
  public byte[] getEncoded() throws HsmException {
    return new PrivateKeyInfo(
        new AlgorithmIdentifier(new Asn1Oid(curve.getOid())),
        new Asn1OctetString(value)).getEncoded();
  }

  @Override
  public byte[] sign(XiMechanism mechanism, byte[] data, SecureRandom random)
      throws HsmException {
    if (!isSign()) {
      throw new HsmException(PKCS11T.CKR_KEY_FUNCTION_NOT_PERMITTED, "CKA_SIGN != TRUE");
    }

    long ckm = mechanism.getCkm();
    if (ckm != PKCS11T.CKM_EDDSA) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_INVALID,
          "Invalid mechanism " + PKCS11T.ckmCodeToName(ckm));
    }

    XiEdwardsECPublicKey.checkMechanismParameters(curve, mechanism);
    try {
      Signature sig = cryptoApi.newSignature(curve.getOid());
      sig.initSign(jceSk);
      sig.update(data);
      return sig.sign();
    } catch (GeneralSecurityException e) {
      throw new HsmException(PKCS11T.CKR_SIGNATURE_INVALID, "could not sign", e);
    }
  }

}
