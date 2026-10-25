// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.composite;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.ECPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.crypto.core.Pkcs1Util;
import org.xipki.crypto.core.WeierstraussCurveEnum;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.SecretWithEncapImpl;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Composite Kem Util.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeKemUtil {

  private static final CryptoApi crypto = CryptoApiFactory.get();

  public static SecretWithEncap encap(CompositeKemSuite algoSuite, byte[] pk, SecureRandom rnd)
      throws XiSecurityException {
    CompKemMlkemVariant mlkemVariant = algoSuite.pqcVariant();
    CompKemTradVariant tradVariant = algoSuite.tradVariant();
    byte[] mlkemPk = Arrays.copyOfRange(pk, 0, mlkemVariant.pkSize());
    byte[] tradPk = Arrays.copyOfRange(pk, mlkemVariant.pkSize(), pk.length);

    SecretWithEncap mlkemRes = mlKemEncapsulate(mlkemVariant, mlkemPk, rnd);
    SecretWithEncap tradRes  = tradEcapsulate(tradVariant, tradPk, rnd);
    byte[] k = sha3256Kdf(mlkemRes.secret(), tradRes.secret(), tradRes.encap(),
                tradPk, algoSuite.label());
    byte[] ct = org.xipki.codec.util.Arrays.concatenate(mlkemRes.encap(), tradRes.encap());
    return new SecretWithEncapImpl(k, ct);
  }

  private static SecretWithEncap mlKemEncapsulate(
      CompKemMlkemVariant variant, byte[] pk, SecureRandom rnd) {
    KeySpec keySpec = variant == CompKemMlkemVariant.mlkem768
                      ? KeySpec.MLKEM768 : KeySpec.MLKEM1024;
    return KemUtil.encapsulateKey(keySpec, pk, rnd);
  }

  private static SecretWithEncap tradEcapsulate(
      CompKemTradVariant variant, byte[] pk, SecureRandom rnd) throws XiSecurityException {
    switch (variant) {
      case X25519: {
        byte[] tmpSk = crypto.generateX25519PrivateKey(rnd);
        byte[] tmpPk = crypto.generateX25519PublicKey(tmpSk);
        byte[] k = crypto.calculateX25519Agreement(tmpSk, pk);
        return new SecretWithEncapImpl(k, tmpPk);
      }
      case X448: {
        byte[] tmpSk = crypto.generateX448PrivateKey(rnd);
        byte[] tmpPk = crypto.generateX448PublicKey(tmpSk);
        byte[] k = crypto.calculateX448Agreement(tmpSk, pk);
        return new SecretWithEncapImpl(k, tmpPk);
      }
      case ECDH_P256:
      case ECDH_P384:
      case ECDH_P521:
      case ECDH_BP256:
      case ECDH_BP384: {
        WeierstraussCurveEnum curveEnum;
        switch (variant) {
          case ECDH_P256:
            curveEnum = WeierstraussCurveEnum.P256;
            break;
          case ECDH_P384:
            curveEnum = WeierstraussCurveEnum.P384;
            break;
          case ECDH_P521:
            curveEnum = WeierstraussCurveEnum.P521;
            break;
          case ECDH_BP256:
            curveEnum = WeierstraussCurveEnum.BP256;
            break;
          default:
            curveEnum = WeierstraussCurveEnum.BP384;
            break;
        }

        BigInteger order = curveEnum.getOrder();
        byte[] tmpSk = new byte[curveEnum.getFieldByteSize()];
        rnd.nextBytes(tmpSk);
        BigInteger tmpSkBn = new BigInteger(1, tmpSk).mod(order);

        byte[] tmpPk = curveEnum.multiplyBase(tmpSkBn).normalize().getEncoded(false);

        // the x coordinate from the fixed-length encoding, not via BigInteger (leading zeros)
        byte[] encoded = curveEnum.decodePoint(pk)
            .multiply(tmpSkBn).normalize().getEncoded(false);
        byte[] agreedSs = Arrays.copyOfRange(encoded, 1, 1 + curveEnum.getFieldByteSize());
        return new SecretWithEncapImpl(agreedSs, tmpPk);
      }
      case RSA2048_OAEP:
      case RSA3072_OAEP:
      case RSA4096_OAEP: {
        byte[] k = new byte[32];
        rnd.nextBytes(k);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
            variant.keySpec().algorithmIdentifier(), pk);

        try {
          RSAPublicKey jceSk = (RSAPublicKey) KeyInfoUtil.getPublicKey(spki);
          BigInteger modulus = jceSk.getModulus();
          Cipher cipher = crypto.newCipher("RSA/ECB/NoPadding");
          cipher.init(Cipher.ENCRYPT_MODE, jceSk);
          byte[] em = Pkcs1Util.RSAES_OAEP_ENCODE(k, modulus.bitLength(), HashAlgo.SHA256, rnd);
          byte[] ct = cipher.doFinal(em);
          return new SecretWithEncapImpl(k, ct);
        } catch (XiSecurityException e) {
          throw e;
        } catch (Exception e) {
          throw new XiSecurityException(e);
        }
      }
      default:
        throw new IllegalStateException("shall not reach here");
    }
  }

  public static byte[] sha3256Kdf(
      byte[] mlkemSS, byte[] tradSS, byte[] tradCT, byte[] tradPK, byte[] label) {
    return HashAlgo.SHA3_256.hash(mlkemSS, tradSS, tradCT, tradPK, label);
  }

  public static byte[] decap(CompositeKemSuite algoSuite, byte[] sk, byte[] pk, byte[] ct)
      throws XiSecurityException {
    CompKemMlkemVariant mlkemVariant = algoSuite.pqcVariant();

    byte[] mlkemSk = Arrays.copyOfRange(sk, 0, mlkemVariant.skSize());
    int off = mlkemVariant.skSize();
    byte[] tradSk  = Arrays.copyOfRange(sk, off, sk.length);

    byte[] mlkemCT  = Arrays.copyOfRange(ct, 0, mlkemVariant.ctSize());
    byte[] tradCT   = Arrays.copyOfRange(ct, mlkemVariant.ctSize(), ct.length);
    byte[] tradPk   = Arrays.copyOfRange(pk, mlkemVariant.pkSize(), pk.length);

    byte[] mlkemSS = decapMlkem(mlkemVariant, mlkemSk, mlkemCT);
    byte[] tradSS  = decapTrad(algoSuite.tradVariant(), tradSk, tradCT);
    return sha3256Kdf(mlkemSS, tradSS, tradCT, tradPk, algoSuite.label());
  }

  private static byte[] decapMlkem(CompKemMlkemVariant variant, byte[] sk, byte[] ct) {
    KeySpec keySpec = (variant == CompKemMlkemVariant.mlkem768)
        ? KeySpec.MLKEM768 : KeySpec.MLKEM1024;
    return KemUtil.decapsulateKey(keySpec, sk, ct);
  }

  private static byte[] decapTrad(CompKemTradVariant variant, byte[] sk, byte[] ct)
      throws XiSecurityException {
    switch (variant) {
      case X25519:
      case X448: {
        boolean isX448 = variant == CompKemTradVariant.X448;
        int size = isX448 ? 56 : 32;
        if (sk.length != size) {
          throw new XiSecurityException("invalid sk.length " + sk.length);
        }
        if (ct.length != size) {
          throw new XiSecurityException("invalid ct.length " + sk.length);
        }
        byte[] r;
        if (isX448) {
          r = crypto.calculateX448Agreement(sk, ct);
        } else {
          r = crypto.calculateX25519Agreement(sk, ct);
        }
        return r;
      }
      case RSA2048_OAEP:
      case RSA3072_OAEP:
      case RSA4096_OAEP: {
        try {
          PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
              AlgorithmIdentifier.ofNullParams(AlgorithmOIDs.id_rsaEncryption),
              Asn1OctetString.fromEncoded(sk));
          RSAPrivateKey jceSk = (RSAPrivateKey) KeyInfoUtil.getPrivateKey(privateKeyInfo);
          BigInteger modulus = jceSk.getModulus();
          Cipher cipher = crypto.newCipher("RSA/ECB/NoPadding");
          cipher.init(Cipher.DECRYPT_MODE, jceSk);
          byte[] em = cipher.doFinal(ct);
          return Pkcs1Util.RSAES_OAEP_DECODE(em, modulus.bitLength(), HashAlgo.SHA256);
        } catch (XiSecurityException e) {
          throw e;
        } catch (Exception e) {
          throw new XiSecurityException(e);
        }
      }
      case ECDH_P256:
      case ECDH_P384:
      case ECDH_P521:
      case ECDH_BP256:
      case ECDH_BP384: {
        WeierstraussCurveEnum curve;
        switch (variant) {
          case ECDH_P256:
            curve = WeierstraussCurveEnum.P256;
            break;
          case ECDH_P384:
            curve = WeierstraussCurveEnum.P384;
            break;
          case ECDH_P521:
            curve = WeierstraussCurveEnum.P521;
            break;
          case ECDH_BP256:
            curve = WeierstraussCurveEnum.BP256;
            break;
          default:
            curve = WeierstraussCurveEnum.BP384;
            break;
        }

        ECPrivateKey asn1Sk;
        try {
          asn1Sk = ECPrivateKey.fromEncoded(sk);
        } catch (CodecException e) {
          throw new XiSecurityException(e);
        }

        byte[] encoded = curve.decodePoint(ct).multiply(
            asn1Sk.bnPrivateKey()).normalize().getEncoded(false);
        return Arrays.copyOfRange(encoded, 1, 1 + encoded.length / 2);
      }
      default:
        throw new IllegalStateException("unknown variant " + variant);
    }
  }

}
