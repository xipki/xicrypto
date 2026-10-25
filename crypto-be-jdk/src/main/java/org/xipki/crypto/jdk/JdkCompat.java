// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.crypto.api.SecretWithEncap;
import org.xipki.crypto.api.SecretWithEncapImpl;

import javax.crypto.SecretKey;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * The differences between the JDK versions that crypto-be-jdk handles: the newer APIs are not used
 * at compile time (crypto-be-jdk is compiled with Java 11), see {@link Kem} for
 * {@code javax.crypto.KEM} (JDK 21+).
 * <p>
 * The minimal JDK versions of the algorithms that are not available in every JDK 11+:
 * <ul>
 *   <li>ML-DSA, ML-KEM: JDK {@value #PQC} (required; checked before the lookup),</li>
 *   <li>Ed25519, Ed448: JDK {@value #EDDSA}.</li>
 * </ul>
 * For the algorithms other than ML-DSA and ML-KEM, the JDK decides: the version is only given as
 * hint if the algorithm is not available.
 *
 * @author Lijun Liao (xipki)
 */
final class JdkCompat {

  /**
   * ML-DSA and ML-KEM: public API since JDK 24; the internals for the context and the seed
   * expansion are used and tested with JDK 25.
   */
  static final int PQC = 25;

  static final int EDDSA = 15;

  /** the feature version of the running JDK, e.g. 17. */
  static final int FEATURE = Runtime.version().feature();

  private static final Asn1Oid[] PQC_OIDS = {
      NistOIDs.id_ml_dsa_44, NistOIDs.id_ml_dsa_65, NistOIDs.id_ml_dsa_87,
      NistOIDs.id_ml_kem_512, NistOIDs.id_ml_kem_768, NistOIDs.id_ml_kem_1024};

  private static final Asn1Oid[] EDDSA_OIDS = {AlgorithmOIDs.id_Ed25519, AlgorithmOIDs.id_Ed448};

  private JdkCompat() {
  }

  /**
   * Throws if the algorithm is ML-DSA or ML-KEM and the running JDK is older than
   * {@value #PQC}.
   * @param type the JCA type, e.g. "KeyFactory".
   * @param algorithm the name or OID of the algorithm.
   * @throws NoSuchAlgorithmException if the JDK is too old for the algorithm.
   */
  static void checkPqc(String type, String algorithm) throws NoSuchAlgorithmException {
    checkPqc(type, algorithm, FEATURE);
  }

  static void checkPqc(String type, String algorithm, int feature)
      throws NoSuchAlgorithmException {
    if (feature < PQC && isPqc(algorithm)) {
      throw new NoSuchAlgorithmException(pqcMessage(type + " " + algorithm));
    }
  }

  /**
   * Returns the message for an ML-DSA or ML-KEM operation on a JDK older than {@value #PQC}.
   * @param what the operation or algorithm, e.g. "ML-DSA seed expansion".
   * @return the message.
   */
  static String pqcMessage(String what) {
    return what + " requires JDK " + PQC + " or later (ML-DSA, ML-KEM), running on "
        + Runtime.version();
  }

  static boolean isPqcAvailable() {
    return FEATURE >= PQC;
  }

  /**
   * Returns the hint for an algorithm that is not available, e.g.
   * " (requires JDK 15 or later, running on 11.0.22)", or an empty string.
   * @param type the JCA type.
   * @param algorithm the name or OID of the algorithm.
   * @param feature the feature version of the JDK.
   * @return the hint, or an empty string.
   */
  static String hint(String type, String algorithm, int feature) {
    int min = minVersion(type, algorithm);
    return (min > feature)
        ? " (requires JDK " + min + " or later, running on " + Runtime.version() + ")" : "";
  }

  /**
   * Returns the minimal JDK version of the algorithm, or 0 if it is available in JDK 11.
   */
  static int minVersion(String type, String algorithm) {
    if (isPqc(algorithm)) {
      return PQC;
    }

    String upper = algorithm.toUpperCase(Locale.ROOT);
    if (upper.equals("ED25519") || upper.equals("ED448") || upper.equals("EDDSA")
        || matches(algorithm, EDDSA_OIDS)) {
      return EDDSA;
    }

    return 0;
  }

  private static boolean isPqc(String algorithm) {
    String upper = algorithm.toUpperCase(Locale.ROOT).replace("-", "");
    return upper.startsWith("MLDSA") || upper.startsWith("MLKEM") || matches(algorithm, PQC_OIDS);
  }

  private static boolean matches(String algorithm, Asn1Oid[] oids) {
    for (Asn1Oid oid : oids) {
      if (oid.getId().equals(algorithm)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Access to {@code javax.crypto.KEM} (JDK 21+) through reflection, so that crypto-be-jdk can be
   * compiled with Java 11. The methods are public methods of public classes of {@code java.base},
   * no {@code --add-opens} is required.
   *
   * @author Lijun Liao (xipki)
   */
  static final class Kem {

    private static final Methods METHODS;

    private static final String UNAVAILABLE_REASON;

    static {
      Methods methods = null;
      String reason = null;
      try {
        methods = new Methods();
      } catch (ReflectiveOperationException | RuntimeException e) {
        reason = "javax.crypto.KEM (JDK 21+) is not available: " + e;
      }
      METHODS = methods;
      UNAVAILABLE_REASON = reason;
    }

    private static final class Methods {

      final Method getInstance;

      final Method newEncapsulator;

      final Method newEncapsulatorWithRandom;

      final Method encapsulate;

      final Method key;

      final Method encapsulation;

      final Method newDecapsulator;

      final Method decapsulate;

      Methods() throws ReflectiveOperationException {
        Class<?> kem = Class.forName("javax.crypto.KEM");
        Class<?> encapsulator = Class.forName("javax.crypto.KEM$Encapsulator");
        Class<?> encapsulated = Class.forName("javax.crypto.KEM$Encapsulated");
        Class<?> decapsulator = Class.forName("javax.crypto.KEM$Decapsulator");

        getInstance = kem.getMethod("getInstance", String.class, Provider.class);
        newEncapsulator = kem.getMethod("newEncapsulator", PublicKey.class);
        newEncapsulatorWithRandom = kem.getMethod("newEncapsulator", PublicKey.class,
            SecureRandom.class);
        encapsulate = encapsulator.getMethod("encapsulate");
        key = encapsulated.getMethod("key");
        encapsulation = encapsulated.getMethod("encapsulation");
        newDecapsulator = kem.getMethod("newDecapsulator", PrivateKey.class);
        decapsulate = decapsulator.getMethod("decapsulate", byte[].class);
      }

    }

    private Kem() {
    }

    /**
     * Returns {@code KEM.getInstance(algorithm, provider)}.
     * @param algorithm the algorithm, e.g. "ML-KEM".
     * @param provider the provider.
     * @return the KEM instance.
     * @throws NoSuchAlgorithmException if the KEM API is not available, or the provider does not
     *         support the algorithm.
     */
    static Object getInstance(String algorithm, Provider provider)
        throws NoSuchAlgorithmException {
      try {
        return invoke(methods().getInstance, null, algorithm, provider);
      } catch (NoSuchAlgorithmException e) {
        throw e;
      } catch (GeneralSecurityException e) {
        throw new NoSuchAlgorithmException(e.getMessage(), e);
      }
    }

    /**
     * Encapsulates a fresh secret to the public key.
     * @param kem the KEM instance of {@link #getInstance(String, Provider)}.
     * @param publicKey the public key.
     * @param random the source of randomness, or null for the default of the provider.
     * @return the shared secret and its encapsulation.
     * @throws GeneralSecurityException if the encapsulation failed.
     */
    static SecretWithEncap encapsulate(Object kem, PublicKey publicKey, SecureRandom random)
        throws GeneralSecurityException {
      Methods m = methods();
      Object encapsulator = (random == null)
          ? invoke(m.newEncapsulator, kem, publicKey)
          : invoke(m.newEncapsulatorWithRandom, kem, publicKey, random);
      Object encapsulated = invoke(m.encapsulate, encapsulator);
      SecretKey key = (SecretKey) invoke(m.key, encapsulated);
      byte[] encapsulation = (byte[]) invoke(m.encapsulation, encapsulated);
      return new SecretWithEncapImpl(key.getEncoded(), encapsulation);
    }

    /**
     * Decapsulates the shared secret.
     * @param kem the KEM instance of {@link #getInstance(String, Provider)}.
     * @param privateKey the private key.
     * @param encapsulation the encapsulated secret.
     * @return the shared secret.
     * @throws GeneralSecurityException if the decapsulation failed.
     */
    static byte[] decapsulate(Object kem, PrivateKey privateKey, byte[] encapsulation)
        throws GeneralSecurityException {
      Methods m = methods();
      Object decapsulator = invoke(m.newDecapsulator, kem, privateKey);
      SecretKey key = (SecretKey) invoke(m.decapsulate, decapsulator, (Object) encapsulation);
      return key.getEncoded();
    }

    private static Methods methods() throws NoSuchAlgorithmException {
      if (METHODS == null) {
        throw new NoSuchAlgorithmException(UNAVAILABLE_REASON);
      }
      return METHODS;
    }

    /**
     * Invokes the method and unwraps the exceptions it throws.
     */
    private static Object invoke(Method method, Object target, Object... args)
        throws GeneralSecurityException {
      try {
        return method.invoke(target, args);
      } catch (InvocationTargetException e) {
        Throwable cause = e.getCause();
        if (cause instanceof GeneralSecurityException) {
          throw (GeneralSecurityException) cause;
        } else if (cause instanceof RuntimeException) {
          throw (RuntimeException) cause;
        } else if (cause instanceof Error) {
          throw (Error) cause;
        }
        throw new GeneralSecurityException(cause);
      } catch (IllegalAccessException e) {
        throw new GeneralSecurityException("could not call " + method, e);
      }
    }

  }

}
