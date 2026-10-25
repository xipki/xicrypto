// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.encap;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_DECAPSULATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKK_AES;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_KEM;

/**
 * This demo program uses a PKCS#11 module to encapsulate and decapsulate a
 * secret key.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class MlkemEncapDecapKeyTest {

  /**
   * Nested class Cloudhsm.
   */
  public static class Cloudhsm extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }

  }

  /**
   * Nested class CloudhsmVendorGcm.
   */
  public static class CloudhsmVendorGcm extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }

  }

  /**
   * Nested class Luna.
   */
  public static class Luna extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.luna();
    }

  }

  /**
   * Nested class Ncipher.
   */
  public static class Ncipher extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.ncipher();
    }

  }

  /**
   * Nested class Sansec.
   */
  public static class Sansec extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }

  }

  /**
   * Nested class Tass.
   */
  public static class Tass extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
    }

  }

  /**
   * Nested class Softhsm.
   */
  public static class Softhsm extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }

  }

  /**
   * Nested class Utimaco.
   */
  public static class Utimaco extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.utimaco();
    }

  }

  /**
   * Nested class Xihsm.
   */
  public static class Xihsm extends Base {

    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.xihsm();
    }

  }

  private static abstract class Base extends TestBase {

    @Test
    public void mlkem512() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM512);
    }

    @Test
    public void mlkem768() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM768);
    }

    @Test
    public void mlkem1024() throws TokenException {
      testMlkem(PKCS11KeyPairType.MLKEM1024);
    }

    private void testMlkem(PKCS11KeyPairType keyPairType) throws TokenException {
      // the encapsulation is done in software with the public key, the decapsulation on the token
      Assume.assumeTrue("ML-KEM decapsulation unsupported",
          getToken().supportsMechanism(CKM_ML_KEM, CKF_DECAPSULATE));

      LOG.info("##################################################");
      LOG.info("generate ML-LEM key pair {}", keyPairType);

      PKCS11KeyPairSpec spec = new PKCS11KeyPairSpec()
          .keyPairType(keyPairType).token(false)
          .encapsulate(true).decapsulate(true);

      PKCS11Token token = getToken();
      PKCS11KeyId keypairId = token.generateKeyPair(spec);

      // be sure that your token can process the specified mechanism
      CkMechanism mech = getSupportedMechanism(CKM_ML_KEM, CKF_DECAPSULATE, null);

      Template template = token.getAttrValues(keypairId.getPublicKeyHandle(),
          new AttributeTypes().parameterSet().value());
      MlkemVariant mlkemParams;
      long parameterSet = template.parameterSet();
      if (parameterSet == PKCS11T.CKP_ML_KEM_512) {
        mlkemParams = MlkemVariant.ml_kem_512;
      } else if (parameterSet == PKCS11T.CKP_ML_KEM_768) {
        mlkemParams = MlkemVariant.ml_kem_768;
      } else if (parameterSet == PKCS11T.CKP_ML_KEM_1024) {
        mlkemParams = MlkemVariant.ml_kem_1024;
      } else {
        throw new TokenException("invalid parameterSet 0x" + Functions.toFullHex(parameterSet));
      }

      byte[] value = template.value();
      SecretWithEncap encapKey = cryptoApi.encapsulateKey(mlkemParams, value, random);

      PKCS11SecretKeySpec aesKeySpec = new PKCS11SecretKeySpec()
          .keyType(CKK_AES).encrypt(true).decrypt(true).token(false)
          .sensitive(false).extractable(true);

      long hKey2;
      try {
        hKey2 = token.decapsulateKey(mech, keypairId.getHandle(), encapKey.encap(), aesKeySpec);
      } catch (PKCS11Exception e) {
        // e.g. the module implements a Cryptoki version < 3.2
        Assume.assumeFalse("C_DecapsulateKey is not supported",
            e.errorCode() == PKCS11T.CKR_FUNCTION_NOT_SUPPORTED);
        throw e;
      }

      try {
        byte[] secret = token.getAttrValues(hKey2, new AttributeTypes().value()).value();
        Assert.assertArrayEquals(keyPairType + ": decapsulated secret", encapKey.secret(), secret);
      } finally {
        token.destroyObject(hKey2);
        token.destroyObject(keypairId.getHandle());
        token.destroyObject(keypairId.getPublicKeyHandle());
      }

      LOG.info("##################################################");
    }
  }

}
