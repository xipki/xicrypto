// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.xihsm.util;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.pkcs11.wrapper.PKCS11T;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

/**
 * Xi Constants.
 *
 * @author Lijun Liao (xipki)
 */
public class XiConstants {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  /**
   * P11 MLDSA Variant enumeration.
   */
  public enum P11MldsaVariant {

    MLDSA44(PKCS11T.CKP_ML_DSA_44, NistOIDs.id_ml_dsa_44, MldsaVariant.ml_dsa_44, 1312, 2560),

    MLDSA65(PKCS11T.CKP_ML_DSA_65, NistOIDs.id_ml_dsa_65, MldsaVariant.ml_dsa_65, 1952, 4032),

    MLDSA87(PKCS11T.CKP_ML_DSA_87, NistOIDs.id_ml_dsa_87, MldsaVariant.ml_dsa_87, 2592, 4896);

    /**
     * Length of the seed (xi) in bytes.
     */
    public static final int SEED_SIZE = 32;

    private final long code;

    private final Asn1Oid oid;

    private final MldsaVariant cryptoVariant;

    private final int pkSize;

    private final int skSize;

    P11MldsaVariant(long code, Asn1Oid oid, MldsaVariant cryptoVariant, int pkSize, int skSize) {
      this.code = code;
      this.oid = oid;
      this.cryptoVariant = cryptoVariant;
      this.pkSize = pkSize;
      this.skSize = skSize;
    }

    public MldsaVariant getCryptoVariant() {
      return cryptoVariant;
    }

    /**
     * Returns the length of the public key pk of FIPS 204.
     * @return the length in bytes.
     */
    public int getPkSize() {
      return pkSize;
    }

    /**
     * Returns the length of the private key sk of FIPS 204.
     * @return the length in bytes.
     */
    public int getSkSize() {
      return skSize;
    }

    public long getCode() {
      return code;
    }

    public Asn1Oid getOid() {
      return oid;
    }

    public KeyPair generateKeyPair() throws HsmException {
      try {
        KeyPairGenerator gen = cryptoApi.newKeyPairGenerator(oid.getId());
        return gen.generateKeyPair();
      } catch (Exception e) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error generating keypair " + name(), e);
      }
    }

    public static P11MldsaVariant ofCode(long code) throws HsmException {
      for (P11MldsaVariant variant : P11MldsaVariant.values()) {
        if (code == variant.code) {
          return variant;
        }
      }

      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID, "unknown MLDSA variant " + code);
    }

  }

  /**
   * P11 MLKEM Variant enumeration.
   */
  public enum P11MlkemVariant {

    MLKEM512 (PKCS11T.CKP_ML_KEM_512,  NistOIDs.id_ml_kem_512,  MlkemVariant.ml_kem_512,
        800,  1632),
    MLKEM768 (PKCS11T.CKP_ML_KEM_768,  NistOIDs.id_ml_kem_768,  MlkemVariant.ml_kem_768,
        1184, 2400),
    MLKEM1024(PKCS11T.CKP_ML_KEM_1024, NistOIDs.id_ml_kem_1024, MlkemVariant.ml_kem_1024,
        1568, 3168);

    /**
     * Length of the seed (d || z) in bytes.
     */
    public static final int SEED_SIZE = 64;

    private final long code;

    private final Asn1Oid oid;

    private final MlkemVariant cryptoVariant;

    private final int ekSize;

    private final int dkSize;

    P11MlkemVariant(long code, Asn1Oid oid, MlkemVariant cryptoVariant, int ekSize, int dkSize) {
      this.code = code;
      this.oid = oid;
      this.cryptoVariant = cryptoVariant;
      this.ekSize = ekSize;
      this.dkSize = dkSize;
    }

    public MlkemVariant getCryptoVariant() {
      return cryptoVariant;
    }

    /**
     * Returns the length of the encapsulation key ek of FIPS 203.
     * @return the length in bytes.
     */
    public int getEkSize() {
      return ekSize;
    }

    /**
     * Returns the length of the decapsulation key dk of FIPS 203.
     * @return the length in bytes.
     */
    public int getDkSize() {
      return dkSize;
    }

    public KeyPair generateKeyPair(SecureRandom random) throws HsmException {
      try {
        return cryptoApi.generateKeyPair(cryptoVariant, random);
      } catch (Exception e) {
        throw new HsmException(PKCS11T.CKR_GENERAL_ERROR, "error generating keypair " + name(), e);
      }
    }

    public long getCode() {
      return code;
    }

    public Asn1Oid getOid() {
      return oid;
    }

    public static P11MlkemVariant ofCode(long code) throws HsmException {
      for (P11MlkemVariant variant : P11MlkemVariant.values()) {
        if (code == variant.code) {
          return variant;
        }
      }

      throw new HsmException(PKCS11T.CKR_ATTRIBUTE_VALUE_INVALID, "unknown MLKEM variant " + code);
    }

  }

}
