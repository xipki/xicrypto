// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.api.test;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.xipki.codec.asn1.crypto.MlkemPrivateKey;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.speed.SpeedExecutor;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.MldsaVariant;
import org.xipki.crypto.api.MlkemVariant;
import org.xipki.crypto.api.SecretWithEncap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Performance tests every {@link CryptoApi} backend runs, with the {@link SpeedExecutor}.
 * A backend test extends this class and implements {@link #crypto()}.
 * <p>
 * The tests are named {@code *SpeedTest} and run only with the Maven profile
 * {@code speed}, e.g. {@code mvn test -Pspeed -pl crypto-openssl}. The duration of
 * each test and the number of threads are set by the Maven properties {@code speed.duration}
 * (default {@value #DEFAULT_DURATION}) and {@code speed.threads} (default 1), e.g.
 * {@code -Dspeed.duration=10s -Dspeed.threads=4}.
 * <p>
 * The algorithms not supported by a backend are skipped. A summary of all tests of the class
 * is printed at the end, and written to {@code target/<name>-speed-summary.txt} of the module,
 * {@code <name>} being the name of the backend.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CryptoApiSpeed {

  /** System property of the duration of each test, set by Maven (speed.duration). */
  private static final String PROP_DURATION = "xipki.speed.duration";

  /** System property of the number of threads, set by Maven (speed.threads). */
  private static final String PROP_THREADS = "xipki.speed.threads";

  /** System property of the directory of the summary file, set by Maven (target). */
  private static final String PROP_DIR = "xipki.speed.dir";

  private static final String DEFAULT_DURATION = "1s";

  /** The random of the backend under test. */
  private SecureRandom rnd() {
    return crypto().getSecureRandom();
  }

  /** The size of the data of the digests, MACs, ciphers and signatures. */
  private static final int DATA_LEN = 1024;

  /** The results of the class: {backend, test, speed, unit}. */
  private static final List<String[]> RESULTS = new ArrayList<>();

  protected abstract CryptoApi crypto();

  /**
   * An operation of the speed test, executed repeatedly by one thread.
   */
  @FunctionalInterface
  protected interface Operation {
    void run() throws Exception;
  }

  /**
   * Creates the operation of a thread, with its own objects (e.g. Signature, Cipher).
   */
  @FunctionalInterface
  protected interface OperationFactory {
    Operation create() throws Exception;
  }

  @AfterClass
  public static void printSummary() {
    synchronized (RESULTS) {
      if (RESULTS.isEmpty()) {
        return;
      }
      // sorted by test, the columns as wide as their longest value
      RESULTS.sort((a, b) -> a[1].compareTo(b[1]));
      int[] widths = new int[3];
      for (String[] r : RESULTS) {
        for (int i = 0; i < widths.length; i++) {
          widths[i] = Math.max(widths[i], r[i].length());
        }
      }

      String format = "%-" + widths[0] + "s  %-" + widths[1] + "s  %" + widths[2] + "s %s/s%n";
      StringBuilder sb = new StringBuilder("\n===== speed summary =====\n");
      for (String[] r : RESULTS) {
        sb.append(String.format(Locale.ROOT, format, (Object[]) r));
      }
      System.out.println(sb);

      // target/<backend>-speed-summary.txt
      Path file = Paths.get(System.getProperty(PROP_DIR, "target"),
          RESULTS.get(0)[0] + "-speed-summary.txt");
      RESULTS.clear();
      try {
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("speed summary written to " + file.toAbsolutePath());
      } catch (IOException e) {
        System.err.println("could not write the speed summary to " + file + ": "
            + e.getMessage());
      }
    }
  }

  /**
   * Executes the speed test of the operation. The test is skipped if the backend does not
   * support the algorithm, i.e. if the creation of the first operation fails with a
   * {@link GeneralSecurityException}.
   * @param name the name of the test, e.g. "SHA256withRSA (2048) sign".
   * @param unit the unit of the operation, e.g. "sign".
   * @param factory the factory of the operations.
   */
  protected void speed(String name, String unit, OperationFactory factory)
      throws Exception {
    // the first operation checks that the algorithm is supported and works
    try {
      factory.create().run();
    } catch (GeneralSecurityException | UnsupportedOperationException e) {
      Assume.assumeNoException(name + " not supported by " + crypto().name(), e);
    }

    final AtomicLong errors = new AtomicLong();
    SpeedExecutor executor = new SpeedExecutor(crypto().name() + ": " + name) {
      @Override
      protected Runnable getTester() throws Exception {
        Operation op = factory.create();
        return () -> {
          while (!stop()) {
            try {
              op.run();
              account(1, 0);
            } catch (Throwable t) {
              if (errors.getAndIncrement() == 0) {
                t.printStackTrace();
              }
              account(1, 1);
            }
          }
        };
      }
    };

    executor.setUnit(unit);
    executor.setDuration(System.getProperty(PROP_DURATION, DEFAULT_DURATION));
    executor.setThreads(Integer.getInteger(PROP_THREADS, 1));
    executor.execute();

    Assert.assertEquals(name + ": errors", 0, executor.getErrorAccount());
    Assert.assertTrue(name + ": nothing processed", executor.getAccount() > 0);

    synchronized (RESULTS) {
      RESULTS.add(new String[]{crypto().name(), name,
          String.format(Locale.ROOT, "%,d", executor.getAverageSpeed()), unit});
    }
  }

  private byte[] randomData() {
    byte[] data = new byte[DATA_LEN];
    rnd().nextBytes(data);
    return data;
  }

  // ---------- digests, MACs, ciphers ----------

  private void speedDigest(String algorithm) throws Exception {
    byte[] data = randomData();
    speed(algorithm + " (1 KiB)", "hash", () -> {
      MessageDigest md = crypto().newMessageDigest(algorithm);
      return () -> md.digest(data);
    });
  }

  @Test
  public void testSha256() throws Exception {
    speedDigest("SHA-256");
  }

  @Test
  public void testSha3256() throws Exception {
    speedDigest("SHA3-256");
  }

  @Test
  public void testSm3() throws Exception {
    speedDigest("SM3");
  }

  @Test
  public void testHmacSha256() throws Exception {
    byte[] data = randomData();
    SecretKey key = new SecretKeySpec(randomBytes(32), "HmacSHA256");
    speed("HmacSHA256 (1 KiB)", "mac", () -> {
      Mac mac = crypto().newMac("HmacSHA256");
      mac.init(key);
      return () -> mac.doFinal(data);
    });
  }

  @Test
  public void testAesGcm() throws Exception {
    byte[] data = randomData();
    SecretKey key = new SecretKeySpec(randomBytes(32), "AES");
    speed("AES-256-GCM encrypt (1 KiB)", "enc", () -> {
      Cipher cipher = crypto().newCipher("AES/GCM/NoPadding");
      return () -> {
        // a new IV for each encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, randomBytes(12)));
        cipher.doFinal(data);
      };
    });
  }

  private byte[] randomBytes(int len) {
    byte[] bytes = new byte[len];
    rnd().nextBytes(bytes);
    return bytes;
  }

  // ---------- signatures ----------

  private KeyPair keyPair(String algorithm, Object param) throws Exception {
    KeyPairGenerator kpGen = crypto().newKeyPairGenerator(algorithm);
    if (param instanceof Integer) {
      kpGen.initialize((Integer) param);
    } else if (param instanceof String) {
      kpGen.initialize(new ECGenParameterSpec((String) param));
    }
    return kpGen.generateKeyPair();
  }

  /** Speed test of the signing and the verification. */
  private void speedSignature(String sigAlg, String keyName, KeyPair kp,
                                  boolean withVerify) throws Exception {
    byte[] data = randomData();
    String prefix = sigAlg + (keyName == null ? "" : " (" + keyName + ")");
    speed(prefix + " sign", "sign", () -> {
      Signature sig = crypto().newSignature(sigAlg);
      return () -> {
        sig.initSign(kp.getPrivate());
        sig.update(data);
        sig.sign();
      };
    });

    if (!withVerify) {
      return;
    }

    Signature signer = crypto().newSignature(sigAlg);
    signer.initSign(kp.getPrivate());
    signer.update(data);
    byte[] sigValue = signer.sign();
    speed(prefix + " verify", "verify", () -> {
      Signature sig = crypto().newSignature(sigAlg);
      return () -> {
        sig.initVerify(kp.getPublic());
        sig.update(data);
        if (!sig.verify(sigValue)) {
          throw new IllegalStateException("signature invalid");
        }
      };
    });
  }

  private void speedSignature(String sigAlg, String keyAlg, Object keyParam,
                                  String keyName) throws Exception {
    KeyPair kp;
    try {
      kp = keyPair(keyAlg, keyParam);
    } catch (GeneralSecurityException | UnsupportedOperationException e) {
      Assume.assumeNoException(keyAlg + " not supported by " + crypto().name(), e);
      return;
    }
    speedSignature(sigAlg, keyName, kp, true);
  }

  @Test
  public void testRsaPkcs1() throws Exception {
    speedSignature("SHA256WITHRSA", "RSA", 2048, "RSA-2048");
  }

  @Test
  public void testRsaPss() throws Exception {
    speedSignature("SHA256WITHRSAANDMGF1", "RSA", 2048, "RSA-2048");
  }

  @Test
  public void testRsa3072() throws Exception {
    speedSignature("SHA256WITHRSA", "RSA", 3072, "RSA-3072");
  }

  @Test
  public void testEcdsaP256() throws Exception {
    speedSignature("SHA256WITHECDSA", "EC", "secp256r1", "P-256");
  }

  @Test
  public void testEcdsaP384() throws Exception {
    speedSignature("SHA384WITHECDSA", "EC", "secp384r1", "P-384");
  }

  @Test
  public void testEcdsaBrainpoolP256r1() throws Exception {
    speedSignature("SHA256WITHECDSA", "EC", "brainpoolP256r1", "brainpoolP256r1");
  }

  @Test
  public void testSm2() throws Exception {
    speedSignature("SM3WITHSM2", "EC", "sm2p256v1", "SM2");
  }

  @Test
  public void testEd25519() throws Exception {
    speedSignature("ED25519", "Ed25519", null, null);
  }

  @Test
  public void testEd448() throws Exception {
    speedSignature("ED448", "Ed448", null, null);
  }

  @Test
  public void testMldsa65() throws Exception {
    KeyPair kp;
    try {
      kp = crypto().generateKeyPair(MldsaVariant.ml_dsa_65);
    } catch (GeneralSecurityException | UnsupportedOperationException e) {
      Assume.assumeNoException("ML-DSA not supported by " + crypto().name(), e);
      return;
    }
    speedSignature("ML-DSA-65", null, kp, true);
  }

  // ---------- key agreement, KEM ----------

  private void speedKeyAgreement(String name, String kaAlg, String keyAlg, Object keyParam)
      throws Exception {
    KeyPair kp;
    KeyPair peer;
    try {
      kp = keyPair(keyAlg, keyParam);
      peer = keyPair(keyAlg, keyParam);
    } catch (GeneralSecurityException | UnsupportedOperationException e) {
      Assume.assumeNoException(name + " not supported by " + crypto().name(), e);
      return;
    }

    speed(name, "agreement", () -> {
      KeyAgreement ka = crypto().newKeyAgreement(kaAlg);
      return () -> {
        ka.init(kp.getPrivate());
        ka.doPhase(peer.getPublic(), true);
        ka.generateSecret();
      };
    });
  }

  @Test
  public void testEcdhP256() throws Exception {
    speedKeyAgreement("ECDH (P-256)", "ECDH", "EC", "secp256r1");
  }

  @Test
  public void testX25519() throws Exception {
    byte[] peerPk = crypto().generateX25519PublicKey(crypto().generateX25519PrivateKey());
    byte[] sk = crypto().generateX25519PrivateKey();
    speed("X25519", "agreement", () -> () -> crypto().calculateX25519Agreement(sk, peerPk));
  }

  @Test
  public void testMlkem768() throws Exception {
    KeyPair kp;
    try {
      kp = crypto().generateKeyPair(MlkemVariant.ml_kem_768);
    } catch (GeneralSecurityException | UnsupportedOperationException e) {
      Assume.assumeNoException("ML-KEM not supported by " + crypto().name(), e);
      return;
    }

    byte[] pk = SubjectPublicKeyInfo.fromEncoded(
        kp.getPublic().getEncoded()).subjectPublicKey();
    byte[] sk = MlkemPrivateKey.fromEncoded(
        PrivateKeyInfo.fromEncoded(
            kp.getPrivate().getEncoded()).privateKey()).seed();
    Assume.assumeNotNull(sk);

    speed("ML-KEM-768 encapsulate", "encap",
        () -> () -> crypto().encapsulateKey(MlkemVariant.ml_kem_768, pk));

    SecretWithEncap se = crypto().encapsulateKey(MlkemVariant.ml_kem_768, pk);
    speed("ML-KEM-768 decapsulate", "decap",
        () -> () -> crypto().decapsulateKey(MlkemVariant.ml_kem_768, sk, se.encap()));
  }

  // ---------- key generation ----------

  @Test
  public void testKeyGenP256() throws Exception {
    speed("EC key generation (P-256)", "keypair", () -> {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator("EC");
      kpGen.initialize(new ECGenParameterSpec("secp256r1"));
      return kpGen::generateKeyPair;
    });
  }

  @Test
  public void testKeyGenRsa2048() throws Exception {
    speed("RSA key generation (2048)", "keypair", () -> {
      KeyPairGenerator kpGen = crypto().newKeyPairGenerator("RSA");
      kpGen.initialize(2048);
      return kpGen::generateKeyPair;
    });
  }

}
