// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.keygeneration;

import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.MldsaPrivateKey;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PqcPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairType;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_DECAPSULATE;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_GENERATE_KEY_PAIR;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SIGN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_DSA;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_DSA_KEY_PAIR_GEN;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_KEM;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKM_ML_KEM_KEY_PAIR_GEN;

/**
 * The attributes CKA_SEED and CKA_VALUE of ML-DSA and ML-KEM keys (PKCS#11 v3.2, sections
 * 6.67 and 6.68): the raw values of FIPS 203 and FIPS 204, for generated and imported keys.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class PqcKeyAttributesTest {

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
   * Nested class Xihsm.
   */
  public static class Xihsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.xihsm();
    }
  }

  private static final byte[] DATA = "data to sign".getBytes();

  /**
   * ML-DSA parameter set: [pk, sk] sizes of FIPS 204.
   */
  private enum Mldsa {
    MLDSA44(PKCS11KeyPairType.MLDSA44, MldsaVariant.ml_dsa_44, NistOIDs.id_ml_dsa_44, 1312, 2560),
    MLDSA65(PKCS11KeyPairType.MLDSA65, MldsaVariant.ml_dsa_65, NistOIDs.id_ml_dsa_65, 1952, 4032),
    MLDSA87(PKCS11KeyPairType.MLDSA87, MldsaVariant.ml_dsa_87, NistOIDs.id_ml_dsa_87, 2592, 4896);

    final PKCS11KeyPairType type;
    final MldsaVariant variant;
    final Asn1Oid oid;
    final int pkSize;
    final int skSize;

    Mldsa(PKCS11KeyPairType type, MldsaVariant variant, Asn1Oid oid, int pkSize, int skSize) {
      this.type = type;
      this.variant = variant;
      this.oid = oid;
      this.pkSize = pkSize;
      this.skSize = skSize;
    }
  }

  /**
   * ML-KEM parameter set: [ek, dk] sizes of FIPS 203.
   */
  private enum Mlkem {
    MLKEM512 (PKCS11KeyPairType.MLKEM512,  MlkemVariant.ml_kem_512,  800,  1632),
    MLKEM768 (PKCS11KeyPairType.MLKEM768,  MlkemVariant.ml_kem_768,  1184, 2400),
    MLKEM1024(PKCS11KeyPairType.MLKEM1024, MlkemVariant.ml_kem_1024, 1568, 3168);

    final PKCS11KeyPairType type;
    final MlkemVariant variant;
    final int ekSize;
    final int dkSize;

    Mlkem(PKCS11KeyPairType type, MlkemVariant variant, int ekSize, int dkSize) {
      this.type = type;
      this.variant = variant;
      this.ekSize = ekSize;
      this.dkSize = dkSize;
    }
  }

  private static abstract class Base extends TestBase {

    @Test
    public void generatedMldsa44() throws Exception {
      testGeneratedMldsa(Mldsa.MLDSA44);
    }

    @Test
    public void generatedMldsa65() throws Exception {
      testGeneratedMldsa(Mldsa.MLDSA65);
    }

    @Test
    public void generatedMldsa87() throws Exception {
      testGeneratedMldsa(Mldsa.MLDSA87);
    }

    @Test
    public void generatedMlkem512() throws Exception {
      testGeneratedMlkem(Mlkem.MLKEM512);
    }

    @Test
    public void generatedMlkem768() throws Exception {
      testGeneratedMlkem(Mlkem.MLKEM768);
    }

    @Test
    public void generatedMlkem1024() throws Exception {
      testGeneratedMlkem(Mlkem.MLKEM1024);
    }

    @Test
    public void sensitiveValuesNotRevealed() throws Exception {
      assertSupport(CKM_ML_DSA_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
      // CKA_SENSITIVE = TRUE
      assertNotRevealed(generate(Mldsa.MLDSA44.type, true, true, false));
      // CKA_SENSITIVE = FALSE, CKA_EXTRACTABLE = FALSE
      assertNotRevealed(generate(Mldsa.MLDSA44.type, false, false, false));
    }

    @Test
    public void importedMldsa44() throws Exception {
      testImportedMldsa(Mldsa.MLDSA44);
    }

    @Test
    public void importedMldsa87() throws Exception {
      testImportedMldsa(Mldsa.MLDSA87);
    }

    @Test
    public void importedMlkem768() throws Exception {
      testImportedMlkem(Mlkem.MLKEM768);
    }

    private PKCS11KeyId generate(PKCS11KeyPairType type, boolean sensitive, boolean extractable,
                                 boolean kem) throws Exception {
      PKCS11KeyPairSpec spec = new PKCS11KeyPairSpec().keyPairType(type).token(false)
          .sensitive(sensitive).extractable(extractable);
      if (kem) {
        spec.deEncapsulate(true);
      } else {
        spec.signVerify(true);
      }
      return getToken().generateKeyPair(spec);
    }

    private void assertNotRevealed(PKCS11KeyId keyId) throws Exception {
      try {
        Template sk = privateAttrs(keyId.getHandle());
        Assert.assertNull("CKA_SEED revealed", sk.seed());
        Assert.assertNull("CKA_VALUE revealed", sk.value());
      } finally {
        destroy(keyId);
      }
    }

    private Template privateAttrs(long hKey) throws Exception {
      return getToken().getAttrValues(hKey, new AttributeTypes().parameterSet().seed().value());
    }

    private byte[] publicValue(long hKey) throws Exception {
      return getToken().getAttrValues(hKey, new AttributeTypes().value()).value();
    }

    private void destroy(PKCS11KeyId keyId) {
      PKCS11Token token = getToken();
      for (Long h : new Long[]{keyId.getHandle(), keyId.getPublicKeyHandle()}) {
        if (h != null) {
          try {
            token.destroyObject(h);
          } catch (Exception e) {
            LOG.warn("could not destroy object {}", h);
          }
        }
      }
    }

    private void testGeneratedMldsa(Mldsa p) throws Exception {
      assertSupport(CKM_ML_DSA_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
      PKCS11KeyId keyId = generate(p.type, false, true, false);
      try {
        byte[] pk = publicValue(keyId.getPublicKeyHandle());
        Template sk = privateAttrs(keyId.getHandle());

        Assert.assertEquals(p + ": length of public CKA_VALUE", p.pkSize, pk.length);
        Assert.assertNotNull(p + ": CKA_SEED", sk.seed());
        Assert.assertEquals(p + ": length of CKA_SEED", 32, sk.seed().length);
        Assert.assertNotNull(p + ": CKA_VALUE", sk.value());
        Assert.assertEquals(p + ": length of private CKA_VALUE", p.skSize, sk.value().length);

        // CKA_VALUE is sk of the seed
        byte[] expanded = expandMldsa(p, sk.seed());
        if (expanded != null) {
          Assert.assertArrayEquals(p + ": CKA_VALUE = sk(CKA_SEED)", expanded, sk.value());
        }

        // the private key from the token signs, the public CKA_VALUE verifies
        assertSignVerify(p, keyId.getHandle(), pk);
      } finally {
        destroy(keyId);
      }
    }

    private void testGeneratedMlkem(Mlkem p) throws Exception {
      assertSupport(CKM_ML_KEM_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
      PKCS11KeyId keyId = generate(p.type, false, true, true);
      try {
        byte[] ek = publicValue(keyId.getPublicKeyHandle());
        Template sk = privateAttrs(keyId.getHandle());

        Assert.assertEquals(p + ": length of public CKA_VALUE", p.ekSize, ek.length);
        Assert.assertNotNull(p + ": CKA_SEED", sk.seed());
        Assert.assertEquals(p + ": length of CKA_SEED", 64, sk.seed().length);
        Assert.assertNotNull(p + ": CKA_VALUE", sk.value());
        Assert.assertEquals(p + ": length of private CKA_VALUE", p.dkSize, sk.value().length);

        // ek belongs to the seed and to dk
        SecretWithEncap se = cryptoApi.encapsulateKey(p.variant, ek, random);
        Assert.assertArrayEquals(p + ": decapsulate with CKA_SEED", se.secret(),
            cryptoApi.decapsulateKey(p.variant, sk.seed(), se.encap()));
        Assert.assertArrayEquals(p + ": decapsulate with CKA_VALUE", se.secret(),
            cryptoApi.decapsulateKey(p.variant, sk.value(), se.encap()));
      } finally {
        destroy(keyId);
      }
    }

    /**
     * Imports the private key as RFC 9881 seed, expandedKey and both.
     */
    private void testImportedMldsa(Mldsa p) throws Exception {
      assertSupport(CKM_ML_DSA, CKF_SIGN);
      KeyPair kp = cryptoApi.generateKeyPair(p.variant, random);
      byte[] seed = PqcPrivateKey.fromEncoded(
          PrivateKeyInfo.fromPrivateKey(kp.getPrivate()).privateKey()).seed();
      byte[] expanded = expandMldsa(p, seed);
      byte[] pk = SubjectPublicKeyInfo.fromPublicKey(kp.getPublic()).subjectPublicKey();

      byte[][] forms = {
          new MldsaPrivateKey(seed, null).getEncoded(),
          expanded == null ? null : new MldsaPrivateKey(null, expanded).getEncoded(),
          expanded == null ? null : new MldsaPrivateKey(seed, expanded).getEncoded()};
      String[] names = {"seed", "expandedKey", "both"};

      for (int i = 0; i < forms.length; i++) {
        if (forms[i] == null) {
          continue;
        }
        String desc = p + " (" + names[i] + ")";
        byte[] pkcs8 = new PrivateKeyInfo(new AlgorithmIdentifier(p.oid), forms[i]).getEncoded();
        long hKey = getToken().importPrivateKey(pkcs8, null, new PKCS11KeyPairSpec()
            .keyPairType(p.type).token(false).sign(true).sensitive(false).extractable(true));
        try {
          Template sk = privateAttrs(hKey);
          if (i != 1) {
            Assert.assertArrayEquals(desc + ": CKA_SEED", seed, sk.seed());
          }
          if (sk.value() != null || i != 0) {
            Assert.assertArrayEquals(desc + ": CKA_VALUE", expanded, sk.value());
          }
          assertSignVerify(p, hKey, pk);
        } finally {
          getToken().destroyObject(hKey);
        }
      }
    }

    private void testImportedMlkem(Mlkem p) throws Exception {
      assertSupport(CKM_ML_KEM, CKF_DECAPSULATE);
      KeyPair kp = cryptoApi.generateKeyPair(p.variant, random);
      PrivateKeyInfo skInfo = PrivateKeyInfo.fromPrivateKey(kp.getPrivate());
      byte[] seed = PqcPrivateKey.fromEncoded(skInfo.privateKey()).seed();
      byte[] pkcs8 = new PrivateKeyInfo(skInfo.getPrivateKeyAlgorithm(),
          new MlkemPrivateKey(seed, null).getEncoded()).getEncoded();

      long hKey = getToken().importPrivateKey(pkcs8, null, new PKCS11KeyPairSpec()
          .keyPairType(p.type).token(false).decapsulate(true).sensitive(false).extractable(true));
      try {
        Template sk = privateAttrs(hKey);
        Assert.assertArrayEquals(p + ": CKA_SEED", seed, sk.seed());
        if (sk.value() != null) {
          Assert.assertEquals(p + ": length of CKA_VALUE", p.dkSize, sk.value().length);
        }
      } finally {
        getToken().destroyObject(hKey);
      }
    }

    private void assertSignVerify(Mldsa p, long hPrivateKey, byte[] pk) throws Exception {
      byte[] sig = getToken().sign(new CkMechanism(CKM_ML_DSA, null), hPrivateKey, DATA);
      PublicKey publicKey = cryptoApi.getPublicKey(
          new SubjectPublicKeyInfo(new AlgorithmIdentifier(p.oid), pk));
      Signature verifier = cryptoApi.newSignature("ML-DSA");
      verifier.initVerify(publicKey);
      verifier.update(DATA);
      Assert.assertTrue(p + ": signature of the token", verifier.verify(sig));
    }

    /**
     * Returns sk of the seed, or null if the crypto backend cannot compute it.
     */
    private static byte[] expandMldsa(Mldsa p, byte[] seed) {
      try {
        return cryptoApi.expandMldsaSeed(p.variant, seed);
      } catch (UnsupportedOperationException e) {
        return null;
      }
    }

  }

}
