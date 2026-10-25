// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.ProviderException;
import java.security.SignatureException;

/**
 * Access to the internals of the JDK (25+) through reflection, for what the public API does not
 * offer: ML-DSA with a context string and the expansion of ML-DSA seeds ({@link Mldsa}), and
 * the expansion of ML-KEM seeds ({@link Mlkem}). Each requires its {@code --add-exports} JVM
 * option.
 *
 * @author Lijun Liao (xipki)
 */
final class JdkInternals {

  private JdkInternals() {
  }

  /**
   * Access to the FIPS 204 ML-DSA.Sign_internal and ML-DSA.Verify_internal of the JDK
   * (class sun.security.provider.ML_DSA), used to sign and verify with a non-empty context
   * string, which the public API of the JDK does not support.
   * <p>
   * The package sun.security.provider is not exported, the JVM option
   * {@value #ADD_EXPORTS} is required.
   *
   * TODO: remove this class, and call the public class and methods once MLDSA with
   *   context is supported in the future JDK version.
   *
   * @author Lijun Liao (xipki)
   */
  static final class Mldsa {

    static final String ADD_EXPORTS = "--add-exports java.base/sun.security.provider=ALL-UNNAMED";

    private static final Constructor<?> NEW_ML_DSA;

    private static final Method SIGN_INTERNAL;

    private static final Method SIG_ENCODE;

    private static final Method VERIFY_INTERNAL;

    private static final Method SEED_TO_EXPANDED;

    private static final String UNAVAILABLE_REASON;

    private static final String SEED_UNAVAILABLE_REASON;

    static {
      Constructor<?> newMlDsa = null;
      Method signInternal = null;
      Method sigEncode = null;
      Method verifyInternal = null;
      Method seedToExpanded = null;
      String reason = null;
      String seedReason = null;

      // sign and verify with context
      try {
        Class<?> mlDsa = Class.forName("sun.security.provider.ML_DSA");
        Class<?> mlDsaSig = Class.forName("sun.security.provider.ML_DSA$ML_DSA_Signature");

        newMlDsa = mlDsa.getConstructor(int.class);
        signInternal = mlDsa.getMethod("signInternal", byte[].class, byte[].class, byte[].class);
        sigEncode = mlDsa.getMethod("sigEncode", mlDsaSig);
        verifyInternal = mlDsa.getMethod("verifyInternal",
            byte[].class, byte[].class, byte[].class);

        // fails with IllegalAccessException if the package is not exported
        newMlDsa.newInstance(2);
      } catch (ReflectiveOperationException | RuntimeException e) {
        reason = (e instanceof IllegalAccessException)
            ? "the JVM option '" + ADD_EXPORTS + "' is required"
            : "the ML-DSA implementation of the JDK is not accessible: " + e;
      }

      // seed expansion, looked up separately: missing in some JDKs (e.g. JDK 25 GA)
      if (reason != null) {
        seedReason = reason;
      } else {
        try {
          Class<?> impls = Class.forName("sun.security.provider.ML_DSA_Impls");
          seedToExpanded = impls.getMethod("seedToExpanded", String.class, byte[].class);
        } catch (ReflectiveOperationException | RuntimeException e) {
          seedReason = "the ML-DSA seed expansion of the JDK is not accessible: " + e;
        }
      }

      NEW_ML_DSA = newMlDsa;
      SIGN_INTERNAL = signInternal;
      SIG_ENCODE = sigEncode;
      VERIFY_INTERNAL = verifyInternal;
      SEED_TO_EXPANDED = seedToExpanded;
      UNAVAILABLE_REASON = reason;
      SEED_UNAVAILABLE_REASON = seedReason;
    }

    private Mldsa() {
    }

    /**
     * Returns why the internals are not available.
     * @return the reason, or null if available.
     */
    static String unavailableReason() {
      return UNAVAILABLE_REASON;
    }

    /**
     * Returns why the seed expansion is not available.
     * @return the reason, or null if available.
     */
    static String seedUnavailableReason() {
      return SEED_UNAVAILABLE_REASON;
    }

    /**
     * FIPS 204 ML-DSA.Sign_internal.
     * @param level 2 (ML-DSA-44), 3 (ML-DSA-65) or 5 (ML-DSA-87).
     * @param expandedSk the expanded private key.
     * @param mPrime the formatted message M'.
     * @param rnd 32 random bytes.
     * @return the encoded signature.
     */
    static byte[] signInternal(int level, byte[] expandedSk, byte[] mPrime, byte[] rnd) {
      checkAvailable();
      try {
        Object mlDsa = NEW_ML_DSA.newInstance(level);
        Object sig = SIGN_INTERNAL.invoke(mlDsa, mPrime, rnd, expandedSk);
        return (byte[]) SIG_ENCODE.invoke(mlDsa, sig);
      } catch (InvocationTargetException e) {
        throw new ProviderException("ML-DSA signing failed", e.getCause());
      } catch (ReflectiveOperationException e) {
        throw new ProviderException("ML-DSA signing failed", e);
      }
    }

    /**
     * FIPS 204 ML-DSA.Verify_internal.
     * @param level 2 (ML-DSA-44), 3 (ML-DSA-65) or 5 (ML-DSA-87).
     * @param pk the encoded public key.
     * @param mPrime the formatted message M'.
     * @param sig the encoded signature.
     * @return whether the signature is valid.
     * @throws SignatureException if the signature is not correctly encoded.
     */
    static boolean verifyInternal(int level, byte[] pk, byte[] mPrime, byte[] sig)
        throws SignatureException {
      checkAvailable();
      try {
        Object mlDsa = NEW_ML_DSA.newInstance(level);
        return (Boolean) VERIFY_INTERNAL.invoke(mlDsa, pk, mPrime, sig);
      } catch (InvocationTargetException e) {
        if (e.getCause() instanceof SignatureException) {
          throw (SignatureException) e.getCause();
        }
        throw new ProviderException("ML-DSA verification failed", e.getCause());
      } catch (ReflectiveOperationException e) {
        throw new ProviderException("ML-DSA verification failed", e);
      }
    }

    /**
     * Computes the expanded private key from the seed.
     * @param paramSet ML-DSA-44, ML-DSA-65 or ML-DSA-87.
     * @param seed the 32-byte seed.
     * @return the expanded private key.
     */
    static byte[] seedToExpanded(String paramSet, byte[] seed) {
      if (SEED_UNAVAILABLE_REASON != null) {
        throw new ProviderException(SEED_UNAVAILABLE_REASON);
      }
      try {
        return (byte[]) SEED_TO_EXPANDED.invoke(null, paramSet, seed);
      } catch (InvocationTargetException e) {
        throw new ProviderException("could not expand ML-DSA seed", e.getCause());
      } catch (ReflectiveOperationException e) {
        throw new ProviderException("could not expand ML-DSA seed", e);
      }
    }

    private static void checkAvailable() {
      if (UNAVAILABLE_REASON != null) {
        throw new ProviderException(UNAVAILABLE_REASON);
      }
    }

  }

  /**
   * Access to the ML-KEM.KeyGen of the JDK (class com.sun.crypto.provider.ML_KEM_Impls), used to
   * compute the decapsulation key from the seed, which the public API of the JDK does not
   * support.
   * <p>
   * The package com.sun.crypto.provider is not exported, the JVM option
   * {@value #ADD_EXPORTS} is required.
   *
   * @author Lijun Liao (xipki)
   */
  static final class Mlkem {

    static final String ADD_EXPORTS = "--add-exports java.base/com.sun.crypto.provider=ALL-UNNAMED";

    private static final Method SEED_TO_EXPANDED;

    private static final String UNAVAILABLE_REASON;

    static {
      Method seedToExpanded = null;
      String reason = null;

      try {
        Class<?> impls = Class.forName("com.sun.crypto.provider.ML_KEM_Impls");
        seedToExpanded = impls.getMethod("seedToExpanded", String.class, byte[].class);
        // fails with IllegalAccessException if the package is not exported
        seedToExpanded.invoke(null, "ML-KEM-512", new byte[64]);
      } catch (InvocationTargetException e) {
        reason = "the ML-KEM implementation of the JDK is not usable: " + e.getCause();
      } catch (ReflectiveOperationException | RuntimeException e) {
        reason = (e instanceof IllegalAccessException)
            ? "the JVM option '" + ADD_EXPORTS + "' is required"
            : "the ML-KEM implementation of the JDK is not accessible: " + e;
      }

      SEED_TO_EXPANDED = (reason == null) ? seedToExpanded : null;
      UNAVAILABLE_REASON = reason;
    }

    private Mlkem() {
    }

    /**
     * Returns why the internals are not available.
     * @return the reason, or null if available.
     */
    static String unavailableReason() {
      return UNAVAILABLE_REASON;
    }

    /**
     * Computes the decapsulation key from the seed.
     * @param paramSet ML-KEM-512, ML-KEM-768 or ML-KEM-1024.
     * @param seed the 64-byte seed (d || z).
     * @return the decapsulation key.
     * @throws UnsupportedOperationException if the internals are not available.
     */
    static byte[] seedToExpanded(String paramSet, byte[] seed) {
      if (UNAVAILABLE_REASON != null) {
        throw new UnsupportedOperationException(UNAVAILABLE_REASON);
      }

      try {
        return (byte[]) SEED_TO_EXPANDED.invoke(null, paramSet, seed);
      } catch (InvocationTargetException e) {
        throw new ProviderException("could not expand ML-KEM seed", e.getCause());
      } catch (ReflectiveOperationException e) {
        throw new ProviderException("could not expand ML-KEM seed", e);
      }
    }

  }

}
