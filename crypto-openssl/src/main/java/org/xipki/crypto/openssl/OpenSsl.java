// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Bindings to libcrypto of OpenSSL 3.5+ via the Foreign Function &amp; Memory API (JDK 22+).
 * <p>
 * The library is the one of the system property {@value #PROP_LIB} (path or name), otherwise
 * the first found of the platform's default names of libcrypto 4.x and 3.x. Only 64-bit
 * platforms are supported ({@code size_t} is a {@code long}).
 * <p>
 * The JVM option {@code --enable-native-access=ALL-UNNAMED} (or the name of the module) avoids
 * the warning of the JDK about the native access.
 * <p>
 * All algorithms are fetched from the default library context with the default properties, so
 * the FIPS mode is configured in the openssl.cnf of the environment variable
 * {@code OPENSSL_CONF}: activate the providers fips and base (not default), and set
 * {@code default_properties = fips=yes}, see {@link #isFipsEnabled()}. The backend
 * crypto-be-openssl-fips requires the FIPS mode, crypto-be-openssl rejects it.
 * <p>
 * The downcalls of the frequent operations (digest, signature, cipher, MAC, random) are typed
 * and some are critical (the byte arrays of the heap are passed without copying); the others
 * go through {@link #call(MethodHandle, Object...)}.
 *
 * @author Lijun Liao (xipki)
 */
public final class OpenSsl {

  /** System property: path or name of libcrypto. */
  public static final String PROP_LIB = "xipki.openssl.lib";

  /** The minimal version 3.5.0, in the layout 0xMNN00PP0 of OPENSSL_VERSION_NUMBER. */
  public static final long MIN_VERSION = 0x30500000L;

  /** EVP_PKEY_PUBLIC_KEY of evp.h: the selection of the encoder for public keys. */
  static final int SELECT_PUBLIC_KEY = 0x86;

  /** EVP_PKEY_KEYPAIR of evp.h: the selection of the encoder for private keys. */
  static final int SELECT_KEYPAIR = 0x87;

  /** POINT_CONVERSION_COMPRESSED and POINT_CONVERSION_UNCOMPRESSED of ec.h. */
  static final int POINT_COMPRESSED = 2;

  static final int POINT_UNCOMPRESSED = 4;

  private static final Linker LINKER = Linker.nativeLinker();

  /** C {@code long}: 64-bit on Linux and macOS, 32-bit on Windows. */
  private static final ValueLayout C_LONG = (ValueLayout) LINKER.canonicalLayouts().get("long");

  private static final AddressLayout C_POINTER = ADDRESS;

  private static final Linker.Option CRITICAL = Linker.Option.critical(true);

  private static final String LOAD_ERROR;

  private static final Map<String, MemorySegment> MDS = new ConcurrentHashMap<>();

  private static final Map<String, MemorySegment> CIPHERS = new ConcurrentHashMap<>();

  static {
    String error = null;
    try {
      long version = versionNumber();
      if (Long.compareUnsigned(version, MIN_VERSION) < 0) {
        error = "OpenSSL 3.5.0 or later is required, found " + version()
            + " (" + H.LIB_NAME + ")";
      } else if (JAVA_LONG.byteSize() != LINKER.canonicalLayouts().get("size_t").byteSize()) {
        error = "only 64-bit platforms are supported";
      }
    } catch (ExceptionInInitializerError e) {
      error = (e.getCause() != null) ? e.getCause().getMessage() : e.getMessage();
    } catch (RuntimeException | LinkageError e) {
      error = e.getMessage();
    }
    LOAD_ERROR = error;
  }

  /**
   * The library and the handles of its functions. The handles are constants
   * ({@code static final}), so the JIT can inline the downcalls.
   */
  private static final class H {

    private static final String[] LOADED = new String[1];

    private static final SymbolLookup LIB = loadLibrary(LOADED);

    private static final String LIB_NAME = LOADED[0];

    private static final AddressLayout P = C_POINTER;

    private static final ValueLayout I = JAVA_INT;

    private static final ValueLayout L = JAVA_LONG;

    // ---------- typed: version, errors ----------
    static final MethodHandle VERSION_NUM = downcall("OpenSSL_version_num", fd(C_LONG));
    static final MethodHandle VERSION = downcall("OpenSSL_version", fd(P, I));
    static final MethodHandle ERR_GET_ERROR = downcall("ERR_get_error", fd(C_LONG));
    static final MethodHandle ERR_ERROR_STRING_N = downcall("ERR_error_string_n",
        FunctionDescriptor.ofVoid(C_LONG, P, L));

    // ---------- typed: EVP_MD ----------
    static final MethodHandle MD_CTX_NEW = downcall("EVP_MD_CTX_new", fd(P));
    static final MethodHandle MD_CTX_FREE = downcall("EVP_MD_CTX_free",
        FunctionDescriptor.ofVoid(P));
    static final MethodHandle MD_CTX_COPY_EX = downcall("EVP_MD_CTX_copy_ex", fd(I, P, P));
    static final MethodHandle MD_CTX_GET_PKEY_CTX =
        downcall("EVP_MD_CTX_get_pkey_ctx", fd(P, P));
    static final MethodHandle DIGEST_INIT_EX2 = downcall("EVP_DigestInit_ex2", fd(I, P, P, P));
    static final MethodHandle DIGEST_UPDATE =
        downcall("EVP_DigestUpdate", fd(I, P, P, L), CRITICAL);
    static final MethodHandle DIGEST_FINAL_EX =
        downcall("EVP_DigestFinal_ex", fd(I, P, P, P), CRITICAL);
    static final MethodHandle DIGEST_FINAL_XOF =
        downcall("EVP_DigestFinalXOF", fd(I, P, P, L), CRITICAL);

    // ---------- typed: signatures ----------
    static final MethodHandle DIGEST_SIGN_INIT_EX =
        downcall("EVP_DigestSignInit_ex", fd(I, P, P, P, P, P, P, P));
    static final MethodHandle DIGEST_VERIFY_INIT_EX =
        downcall("EVP_DigestVerifyInit_ex", fd(I, P, P, P, P, P, P, P));
    static final MethodHandle DIGEST_SIGN =
        downcall("EVP_DigestSign", fd(I, P, P, P, P, L), CRITICAL);
    static final MethodHandle DIGEST_VERIFY =
        downcall("EVP_DigestVerify", fd(I, P, P, L, P, L), CRITICAL);

    // ---------- typed: ciphers ----------
    static final MethodHandle CIPHER_UPDATE =
        downcall("EVP_CipherUpdate", fd(I, P, P, P, P, I), CRITICAL);
    static final MethodHandle CIPHER_FINAL_EX =
        downcall("EVP_CipherFinal_ex", fd(I, P, P, P), CRITICAL);

    // ---------- typed: MAC ----------
    static final MethodHandle MAC_UPDATE = downcall("EVP_MAC_update", fd(I, P, P, L), CRITICAL);
    static final MethodHandle MAC_FINAL = downcall("EVP_MAC_final", fd(I, P, P, P, L), CRITICAL);

    // ---------- typed: random ----------
    static final MethodHandle RAND_BYTES = downcall("RAND_bytes", fd(I, P, I), CRITICAL);
    static final MethodHandle RAND_PRIV_BYTES =
        downcall("RAND_priv_bytes", fd(I, P, I), CRITICAL);

    // ---------- untyped (via call): fetch ----------
    static final MethodHandle MD_FETCH = downcall("EVP_MD_fetch", fd(P, P, P, P));
    static final MethodHandle MD_GET_SIZE = downcall("EVP_MD_get_size", fd(I, P));
    static final MethodHandle CIPHER_FETCH = downcall("EVP_CIPHER_fetch", fd(P, P, P, P));
    static final MethodHandle CIPHER_GET_BLOCK_SIZE =
        downcall("EVP_CIPHER_get_block_size", fd(I, P));
    static final MethodHandle MAC_FETCH = downcall("EVP_MAC_fetch", fd(P, P, P, P));
    static final MethodHandle KDF_FETCH = downcall("EVP_KDF_fetch", fd(P, P, P, P));
    static final MethodHandle KDF_FREE = downcall("EVP_KDF_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle SIGNATURE_FETCH = downcall("EVP_SIGNATURE_fetch", fd(P, P, P, P));
    static final MethodHandle SIGNATURE_FREE =
        downcall("EVP_SIGNATURE_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle KEYMGMT_FETCH = downcall("EVP_KEYMGMT_fetch", fd(P, P, P, P));
    static final MethodHandle KEYMGMT_FREE =
        downcall("EVP_KEYMGMT_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle KEYEXCH_FETCH = downcall("EVP_KEYEXCH_fetch", fd(P, P, P, P));
    static final MethodHandle KEYEXCH_FREE =
        downcall("EVP_KEYEXCH_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle ASYM_CIPHER_FETCH =
        downcall("EVP_ASYM_CIPHER_fetch", fd(P, P, P, P));
    static final MethodHandle ASYM_CIPHER_FREE =
        downcall("EVP_ASYM_CIPHER_free", FunctionDescriptor.ofVoid(P));

    // ---------- untyped: FIPS mode ----------
    static final MethodHandle DEFAULT_PROPERTIES_IS_FIPS_ENABLED =
        downcall("EVP_default_properties_is_fips_enabled", fd(I, P));
    static final MethodHandle PROVIDER_AVAILABLE =
        downcall("OSSL_PROVIDER_available", fd(I, P, P));

    // ---------- untyped: EVP_CIPHER_CTX ----------
    static final MethodHandle CIPHER_CTX_NEW = downcall("EVP_CIPHER_CTX_new", fd(P));
    static final MethodHandle CIPHER_CTX_FREE =
        downcall("EVP_CIPHER_CTX_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle CIPHER_INIT_EX2 =
        downcall("EVP_CipherInit_ex2", fd(I, P, P, P, P, I, P));
    static final MethodHandle CIPHER_CTX_SET_PADDING =
        downcall("EVP_CIPHER_CTX_set_padding", fd(I, P, I));
    static final MethodHandle CIPHER_CTX_SET_PARAMS =
        downcall("EVP_CIPHER_CTX_set_params", fd(I, P, P));
    static final MethodHandle CIPHER_CTX_GET_PARAMS =
        downcall("EVP_CIPHER_CTX_get_params", fd(I, P, P));

    // ---------- untyped: EVP_MAC_CTX, EVP_KDF_CTX ----------
    static final MethodHandle MAC_FREE = downcall("EVP_MAC_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle MAC_CTX_NEW = downcall("EVP_MAC_CTX_new", fd(P, P));
    static final MethodHandle MAC_CTX_FREE =
        downcall("EVP_MAC_CTX_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle MAC_CTX_DUP = downcall("EVP_MAC_CTX_dup", fd(P, P));
    static final MethodHandle MAC_INIT = downcall("EVP_MAC_init", fd(I, P, P, L, P));
    static final MethodHandle MAC_CTX_GET_MAC_SIZE =
        downcall("EVP_MAC_CTX_get_mac_size", fd(L, P));
    static final MethodHandle KDF_CTX_NEW = downcall("EVP_KDF_CTX_new", fd(P, P));
    static final MethodHandle KDF_CTX_FREE =
        downcall("EVP_KDF_CTX_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle KDF_DERIVE = downcall("EVP_KDF_derive", fd(I, P, P, L, P));

    // ---------- untyped: EVP_PKEY ----------
    static final MethodHandle D2I_AUTO_PRIVATE_KEY_EX =
        downcall("d2i_AutoPrivateKey_ex", fd(P, P, P, C_LONG, P, P));
    static final MethodHandle D2I_PUBKEY_EX = downcall("d2i_PUBKEY_ex", fd(P, P, P, C_LONG, P, P));
    static final MethodHandle NEW_RAW_PRIVATE_KEY_EX =
        downcall("EVP_PKEY_new_raw_private_key_ex", fd(P, P, P, P, P, L));
    static final MethodHandle NEW_RAW_PUBLIC_KEY_EX =
        downcall("EVP_PKEY_new_raw_public_key_ex", fd(P, P, P, P, P, L));
    static final MethodHandle PKEY_FREE = downcall("EVP_PKEY_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle PKEY_IS_A = downcall("EVP_PKEY_is_a", fd(I, P, P));
    static final MethodHandle PKEY_GET0_TYPE_NAME = downcall("EVP_PKEY_get0_type_name", fd(P, P));
    static final MethodHandle PKEY_GET_SIZE = downcall("EVP_PKEY_get_size", fd(I, P));
    static final MethodHandle PKEY_GET_BITS = downcall("EVP_PKEY_get_bits", fd(I, P));
    static final MethodHandle PKEY_GET_OCTET_STRING_PARAM =
        downcall("EVP_PKEY_get_octet_string_param", fd(I, P, P, P, L, P));
    static final MethodHandle PKEY_GET_UTF8_STRING_PARAM =
        downcall("EVP_PKEY_get_utf8_string_param", fd(I, P, P, P, L, P));
    static final MethodHandle PKEY_GET_BN_PARAM = downcall("EVP_PKEY_get_bn_param", fd(I, P, P, P));
    static final MethodHandle PKEY_GET_RAW_PUBLIC_KEY =
        downcall("EVP_PKEY_get_raw_public_key", fd(I, P, P, P));
    static final MethodHandle PKEY_GET_RAW_PRIVATE_KEY =
        downcall("EVP_PKEY_get_raw_private_key", fd(I, P, P, P));
    static final MethodHandle ENCODER_CTX_NEW_FOR_PKEY =
        downcall("OSSL_ENCODER_CTX_new_for_pkey", fd(P, P, I, P, P, P));
    static final MethodHandle ENCODER_TO_DATA = downcall("OSSL_ENCODER_to_data", fd(I, P, P, P));
    static final MethodHandle ENCODER_CTX_FREE =
        downcall("OSSL_ENCODER_CTX_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle CRYPTO_FREE =
        downcall("CRYPTO_free", FunctionDescriptor.ofVoid(P, P, I));

    // ---------- untyped: EVP_PKEY_CTX ----------
    static final MethodHandle PKEY_CTX_NEW_FROM_NAME =
        downcall("EVP_PKEY_CTX_new_from_name", fd(P, P, P, P));
    static final MethodHandle PKEY_CTX_NEW_FROM_PKEY =
        downcall("EVP_PKEY_CTX_new_from_pkey", fd(P, P, P, P));
    static final MethodHandle PKEY_CTX_FREE =
        downcall("EVP_PKEY_CTX_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle PKEY_CTX_SET_PARAMS =
        downcall("EVP_PKEY_CTX_set_params", fd(I, P, P));
    static final MethodHandle PKEY_KEYGEN_INIT = downcall("EVP_PKEY_keygen_init", fd(I, P));
    static final MethodHandle PKEY_GENERATE = downcall("EVP_PKEY_generate", fd(I, P, P));
    static final MethodHandle PKEY_FROMDATA_INIT = downcall("EVP_PKEY_fromdata_init", fd(I, P));
    static final MethodHandle PKEY_FROMDATA = downcall("EVP_PKEY_fromdata", fd(I, P, P, I, P));
    static final MethodHandle PKEY_SIGN_INIT_EX = downcall("EVP_PKEY_sign_init_ex", fd(I, P, P));
    static final MethodHandle PKEY_SIGN = downcall("EVP_PKEY_sign", fd(I, P, P, P, P, L));
    static final MethodHandle PKEY_VERIFY_INIT_EX =
        downcall("EVP_PKEY_verify_init_ex", fd(I, P, P));
    static final MethodHandle PKEY_VERIFY = downcall("EVP_PKEY_verify", fd(I, P, P, L, P, L));
    static final MethodHandle PKEY_VERIFY_RECOVER_INIT_EX =
        downcall("EVP_PKEY_verify_recover_init_ex", fd(I, P, P));
    static final MethodHandle PKEY_VERIFY_RECOVER =
        downcall("EVP_PKEY_verify_recover", fd(I, P, P, P, P, L));
    static final MethodHandle PKEY_ENCRYPT_INIT_EX =
        downcall("EVP_PKEY_encrypt_init_ex", fd(I, P, P));
    static final MethodHandle PKEY_ENCRYPT = downcall("EVP_PKEY_encrypt", fd(I, P, P, P, P, L));
    static final MethodHandle PKEY_DECRYPT_INIT_EX =
        downcall("EVP_PKEY_decrypt_init_ex", fd(I, P, P));
    static final MethodHandle PKEY_DECRYPT = downcall("EVP_PKEY_decrypt", fd(I, P, P, P, P, L));
    static final MethodHandle PKEY_DERIVE_INIT_EX = downcall("EVP_PKEY_derive_init_ex",
        fd(I, P, P));
    static final MethodHandle PKEY_DERIVE_SET_PEER_EX =
        downcall("EVP_PKEY_derive_set_peer_ex", fd(I, P, P, I));
    static final MethodHandle PKEY_DERIVE = downcall("EVP_PKEY_derive", fd(I, P, P, P));
    static final MethodHandle PKEY_ENCAPSULATE_INIT =
        downcall("EVP_PKEY_encapsulate_init", fd(I, P, P));
    static final MethodHandle PKEY_ENCAPSULATE = downcall("EVP_PKEY_encapsulate",
        fd(I, P, P, P, P, P));
    static final MethodHandle PKEY_DECAPSULATE_INIT =
        downcall("EVP_PKEY_decapsulate_init", fd(I, P, P));
    static final MethodHandle PKEY_DECAPSULATE = downcall("EVP_PKEY_decapsulate",
        fd(I, P, P, P, P, L));

    // ---------- untyped: BIGNUM, EC_GROUP, EC_POINT ----------
    static final MethodHandle BN_BIN2BN = downcall("BN_bin2bn", fd(P, P, I, P));
    static final MethodHandle BN_BN2BINPAD = downcall("BN_bn2binpad", fd(I, P, P, I));
    static final MethodHandle BN_NUM_BITS = downcall("BN_num_bits", fd(I, P));
    static final MethodHandle BN_NEW = downcall("BN_new", fd(P));
    static final MethodHandle BN_CLEAR_FREE =
        downcall("BN_clear_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle OBJ_TXT2NID = downcall("OBJ_txt2nid", fd(I, P));
    static final MethodHandle EC_GROUP_NEW_BY_CURVE_NAME_EX =
        downcall("EC_GROUP_new_by_curve_name_ex", fd(P, P, P, I));
    static final MethodHandle EC_GROUP_GET_CURVE =
        downcall("EC_GROUP_get_curve", fd(I, P, P, P, P, P));
    static final MethodHandle EC_GROUP_GET0_GENERATOR =
        downcall("EC_GROUP_get0_generator", fd(P, P));
    static final MethodHandle EC_GROUP_GET0_ORDER = downcall("EC_GROUP_get0_order", fd(P, P));
    static final MethodHandle EC_GROUP_GET0_COFACTOR =
        downcall("EC_GROUP_get0_cofactor", fd(P, P));
    static final MethodHandle EC_GROUP_GET_DEGREE = downcall("EC_GROUP_get_degree", fd(I, P));
    static final MethodHandle EC_POINT_NEW = downcall("EC_POINT_new", fd(P, P));
    static final MethodHandle EC_POINT_CLEAR_FREE =
        downcall("EC_POINT_clear_free", FunctionDescriptor.ofVoid(P));
    static final MethodHandle EC_POINT_OCT2POINT =
        downcall("EC_POINT_oct2point", fd(I, P, P, P, L, P));
    static final MethodHandle EC_POINT_POINT2OCT =
        downcall("EC_POINT_point2oct", fd(L, P, P, I, P, L, P));
    static final MethodHandle EC_POINT_MUL = downcall("EC_POINT_mul", fd(I, P, P, P, P, P, P));
    static final MethodHandle EC_POINT_ADD = downcall("EC_POINT_add", fd(I, P, P, P, P, P));
    static final MethodHandle EC_POINT_IS_AT_INFINITY =
        downcall("EC_POINT_is_at_infinity", fd(I, P, P));

    private static FunctionDescriptor fd(MemoryLayout res, MemoryLayout... args) {
      return FunctionDescriptor.of(res, args);
    }

    /**
     * Returns the handle of the function. The C type {@code long} is a Java {@code long} in
     * the Java signature on all platforms.
     */
    private static MethodHandle downcall(String name, FunctionDescriptor desc,
                                         Linker.Option... options) {
      MemorySegment symbol = LIB.find(name)
          .orElseThrow(() -> new IllegalStateException("symbol " + name + " not found"));
      MethodHandle mh = LINKER.downcallHandle(symbol, desc, options);
      MethodType type = mh.type();
      for (int i = 0; i < type.parameterCount(); i++) {
        if (type.parameterType(i) == int.class
            && C_LONG.equals(desc.argumentLayouts().get(i))) {
          type = type.changeParameterType(i, long.class);
        }
      }
      if (type.returnType() == int.class && C_LONG.equals(desc.returnLayout().orElse(null))) {
        type = type.changeReturnType(long.class);
      }
      return MethodHandles.explicitCastArguments(mh, type);
    }

  }

  private OpenSsl() {
  }

  /**
   * Returns whether libcrypto of OpenSSL 3.5+ is available.
   * @return whether libcrypto of OpenSSL 3.5+ is available.
   */
  public static boolean isAvailable() {
    return LOAD_ERROR == null;
  }

  /**
   * Returns why libcrypto is not available.
   * @return the reason, or null if available.
   */
  public static String unavailableReason() {
    return LOAD_ERROR;
  }

  /**
   * Throws an exception if libcrypto of OpenSSL 3.5+ is not available.
   * @throws IllegalStateException if not available.
   */
  public static void ensureAvailable() {
    if (LOAD_ERROR != null) {
      throw new IllegalStateException("libcrypto of OpenSSL is not available: " + LOAD_ERROR
          + ", set the system property " + PROP_LIB + " to the path of libcrypto");
    }
  }

  /**
   * Returns the name or path of the loaded libcrypto.
   * @return the name or path of the loaded libcrypto.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available.
   */
  public static String libraryName() {
    ensureAvailable();
    return H.LIB_NAME;
  }

  /**
   * Returns whether OpenSSL is in the FIPS mode: the provider fips is available and the
   * default properties contain {@code fips=yes}.
   * @return whether OpenSSL is in the FIPS mode.
   * @throws IllegalStateException if libcrypto of OpenSSL 3.5+ is not available.
   */
  public static boolean isFipsEnabled() {
    ensureAvailable();
    try (Arena arena = Arena.ofConfined()) {
      return callInt(H.DEFAULT_PROPERTIES_IS_FIPS_ENABLED, MemorySegment.NULL) == 1
          && callInt(H.PROVIDER_AVAILABLE, MemorySegment.NULL, arena.allocateFrom("fips")) == 1;
    }
  }

  /**
   * Throws an exception if the FIPS mode of OpenSSL is not the one the backend requires.
   * @param fips whether OpenSSL must be in the FIPS mode (true) or must not be in it (false).
   * @param backend the name of the backend, for the message.
   * @throws IllegalStateException if the FIPS mode is not the required one, or if libcrypto of
   *         OpenSSL 3.5+ is not available.
   */
  static void ensureFipsMode(boolean fips, String backend) {
    boolean enabled = isFipsEnabled();
    if (fips && !enabled) {
      throw new IllegalStateException("the backend " + backend + " requires the FIPS mode, but "
          + version() + " is not in it: activate the provider fips and set"
          + " default_properties = fips=yes in the openssl.cnf of OPENSSL_CONF");
    } else if (!fips && enabled) {
      throw new IllegalStateException("the backend " + backend + " does not run in the FIPS"
          + " mode of " + version() + ": use the backend openssl-fips (crypto-be-openssl-fips)");
    }
  }

  /** The kinds of the algorithms of OpenSSL, see {@link #hasAlgorithm(Kind, String)}. */
  enum Kind {
    DIGEST, CIPHER, MAC, KDF, SIGNATURE, KEYMGMT, KEYEXCH, ASYM_CIPHER
  }

  /**
   * Returns whether the algorithm can be fetched with the default properties, e.g. not in the
   * FIPS mode for SM3.
   * @param kind the kind of the algorithm.
   * @param name the name of the algorithm in OpenSSL, e.g. "SM3".
   * @return whether the algorithm is available.
   */
  static boolean hasAlgorithm(Kind kind, String name) {
    return switch (kind) {
      case DIGEST -> !isNull(md(name));
      case CIPHER -> !isNull(cipher(name));
      case MAC -> fetchable(H.MAC_FETCH, H.MAC_FREE, name);
      case KDF -> fetchable(H.KDF_FETCH, H.KDF_FREE, name);
      case SIGNATURE -> fetchable(H.SIGNATURE_FETCH, H.SIGNATURE_FREE, name);
      case KEYMGMT -> fetchable(H.KEYMGMT_FETCH, H.KEYMGMT_FREE, name);
      case KEYEXCH -> fetchable(H.KEYEXCH_FETCH, H.KEYEXCH_FREE, name);
      case ASYM_CIPHER -> fetchable(H.ASYM_CIPHER_FETCH, H.ASYM_CIPHER_FREE, name);
    };
  }

  private static boolean fetchable(MethodHandle fetch, MethodHandle free, String name) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment alg = callPtr(fetch, MemorySegment.NULL, arena.allocateFrom(name),
          MemorySegment.NULL);
      if (isNull(alg)) {
        clearErrors();
        return false;
      }
      call(free, alg);
      return true;
    }
  }

  private static SymbolLookup loadLibrary(String[] loaded) {
    List<String> candidates = new ArrayList<>();
    String prop = System.getProperty(PROP_LIB);
    if (prop != null && !prop.isBlank()) {
      candidates.add(prop.trim());
    } else {
      String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
      // 4.x first, then 3.x
      if (os.contains("win")) {
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        String suffix = arch.contains("aarch64") ? "-arm64.dll" : "-x64.dll";
        candidates.add("libcrypto-4" + suffix);
        candidates.add("libcrypto-3" + suffix);
      } else if (os.contains("mac")) {
        // Homebrew: the kegs openssl@N are not in the search path of dlopen
        for (String v : new String[]{"4", "3"}) {
          candidates.add("libcrypto." + v + ".dylib");
          candidates.add("/opt/homebrew/opt/openssl@" + v + "/lib/libcrypto." + v + ".dylib");
          candidates.add("/usr/local/opt/openssl@" + v + "/lib/libcrypto." + v + ".dylib");
        }
      } else {
        candidates.add("libcrypto.so.4");
        candidates.add("libcrypto.so.3");
      }
    }

    IllegalArgumentException cause = null;
    for (String candidate : candidates) {
      try {
        SymbolLookup lookup = SymbolLookup.libraryLookup(candidate, Arena.global());
        loaded[0] = candidate;
        return lookup;
      } catch (IllegalArgumentException e) {
        if (cause == null) {
          cause = e;
        }
      }
    }
    throw new IllegalStateException("could not load libcrypto, tried " + candidates, cause);
  }

  // ---------- helpers ----------

  /** Returns the error as an unchecked exception, the checked ones cannot occur. */
  static RuntimeException rethrow(Throwable t) {
    if (t instanceof RuntimeException) {
      return (RuntimeException) t;
    } else if (t instanceof Error) {
      throw (Error) t;
    }
    return new IllegalStateException(t);
  }

  /**
   * Calls the function of a not frequent operation. The arguments are converted as by
   * {@link MethodHandle#invokeWithArguments(Object...)}.
   */
  private static Object call(MethodHandle mh, Object... args) {
    try {
      return mh.invokeWithArguments(args);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  private static int callInt(MethodHandle mh, Object... args) {
    return (int) call(mh, args);
  }

  private static MemorySegment callPtr(MethodHandle mh, Object... args) {
    return (MemorySegment) call(mh, args);
  }

  /** Returns a copy of the bytes in native memory of the arena. */
  static MemorySegment copyOf(Arena arena, byte[] bytes) {
    MemorySegment seg = arena.allocate(Math.max(1, bytes.length));
    MemorySegment.copy(bytes, 0, seg, JAVA_BYTE, 0, bytes.length);
    return seg;
  }

  static boolean isNull(MemorySegment p) {
    return p.address() == 0;
  }

  // ---------- version and errors ----------

  /**
   * Returns OpenSSL_version_num(), in the layout 0xMNN00PP0 of OPENSSL_VERSION_NUMBER.
   * @return the version number.
   */
  public static long versionNumber() {
    try {
      return (long) H.VERSION_NUM.invokeExact();
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * Returns OpenSSL_version(OPENSSL_VERSION), e.g. "OpenSSL 4.1.0 23 Oct 2026".
   * @return the version text.
   */
  public static String version() {
    try {
      MemorySegment s = (MemorySegment) H.VERSION.invokeExact(0);
      return s.reinterpret(256).getString(0);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * Returns the messages of the error queue of this thread, and clears the queue.
   * @return the messages, separated by "; ", or "unknown error".
   */
  static String errors() {
    StringBuilder sb = new StringBuilder();
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = arena.allocate(256);
      for (long e; (e = (long) H.ERR_GET_ERROR.invokeExact()) != 0; ) {
        H.ERR_ERROR_STRING_N.invokeExact(e, buf, buf.byteSize());
        if (!sb.isEmpty()) {
          sb.append("; ");
        }
        sb.append(buf.getString(0));
      }
    } catch (Throwable t) {
      throw rethrow(t);
    }
    return sb.isEmpty() ? "unknown error" : sb.toString();
  }

  /** Clears the error queue of this thread. */
  static void clearErrors() {
    try {
      while ((long) H.ERR_GET_ERROR.invokeExact() != 0) {
        // discard
      }
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  // ---------- random ----------

  /**
   * Fills the array with random bytes of the DRBG of OpenSSL.
   * @param secret whether the bytes are secret (RAND_priv_bytes), e.g. keys.
   */
  static void randomBytes(byte[] bytes, boolean secret) {
    try {
      int rc = secret
          ? (int) H.RAND_PRIV_BYTES.invokeExact(MemorySegment.ofArray(bytes), bytes.length)
          : (int) H.RAND_BYTES.invokeExact(MemorySegment.ofArray(bytes), bytes.length);
      if (rc != 1) {
        throw new IllegalStateException("RAND_bytes failed: " + errors());
      }
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  // ---------- EVP_MD ----------

  /**
   * Returns the fetched EVP_MD, cached for the lifetime of the JVM.
   * @param name the name of the digest in OpenSSL, e.g. "SM3".
   * @return the EVP_MD, or {@link MemorySegment#NULL} if unavailable.
   */
  static MemorySegment md(String name) {
    return fetch(MDS, H.MD_FETCH, name);
  }

  /**
   * Returns the fetched EVP_CIPHER, cached for the lifetime of the JVM.
   * @param name the name of the cipher in OpenSSL, e.g. "AES-128-GCM".
   * @return the EVP_CIPHER, or {@link MemorySegment#NULL} if unavailable.
   */
  static MemorySegment cipher(String name) {
    return fetch(CIPHERS, H.CIPHER_FETCH, name);
  }

  private static MemorySegment fetch(Map<String, MemorySegment> cache, MethodHandle fetch,
                                     String name) {
    MemorySegment cached = cache.get(name);
    if (cached != null) {
      return cached;
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment alg = callPtr(fetch, MemorySegment.NULL, arena.allocateFrom(name),
          MemorySegment.NULL);
      if (isNull(alg)) {
        clearErrors();
        return alg;
      }
      // a concurrently fetched one is not freed: the algorithms live as long as the JVM
      MemorySegment prev = cache.putIfAbsent(name, alg);
      return prev != null ? prev : alg;
    }
  }

  static int mdSize(MemorySegment md) {
    return callInt(H.MD_GET_SIZE, md);
  }

  static int cipherBlockSize(MemorySegment cipher) {
    return callInt(H.CIPHER_GET_BLOCK_SIZE, cipher);
  }

  static MemorySegment mdCtxNew() {
    try {
      MemorySegment ctx = (MemorySegment) H.MD_CTX_NEW.invokeExact();
      if (isNull(ctx)) {
        throw new OutOfMemoryError("EVP_MD_CTX_new failed");
      }
      return ctx;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static void mdCtxFree(MemorySegment ctx) {
    try {
      H.MD_CTX_FREE.invokeExact(ctx);
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static boolean mdCtxCopy(MemorySegment out, MemorySegment in) {
    try {
      return (int) H.MD_CTX_COPY_EX.invokeExact(out, in) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  static boolean digestInit(MemorySegment ctx, MemorySegment md) {
    try {
      return (int) H.DIGEST_INIT_EX2.invokeExact(ctx, md, MemorySegment.NULL) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /** EVP_DigestUpdate. The data may be a heap segment (the call is critical). */
  static boolean digestUpdate(MemorySegment ctx, MemorySegment data) {
    try {
      return (int) H.DIGEST_UPDATE.invokeExact(ctx, data, data.byteSize()) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /** EVP_DigestFinal_ex. The output may be a heap segment (the call is critical). */
  static boolean digestFinal(MemorySegment ctx, MemorySegment out) {
    try {
      return (int) H.DIGEST_FINAL_EX.invokeExact(ctx, out, MemorySegment.NULL) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /** EVP_DigestFinalXOF. The output may be a heap segment (the call is critical). */
  static boolean digestFinalXof(MemorySegment ctx, MemorySegment out) {
    try {
      return (int) H.DIGEST_FINAL_XOF.invokeExact(ctx, out, out.byteSize()) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * Returns the digest of the data.
   * @param md the EVP_MD.
   * @param outLen the length of the output: that of the digest, or any for the XOFs.
   * @param xof whether the digest is an XOF (EVP_DigestFinalXOF).
   */
  static byte[] digest(MemorySegment md, MemorySegment data, int outLen, boolean xof) {
    MemorySegment ctx = mdCtxNew();
    try {
      byte[] out = new byte[outLen];
      MemorySegment outSeg = MemorySegment.ofArray(out);
      if (!digestInit(ctx, md) || !digestUpdate(ctx, data)
          || !(xof ? digestFinalXof(ctx, outSeg) : digestFinal(ctx, outSeg))) {
        throw new IllegalStateException("digest failed: " + errors());
      }
      return out;
    } finally {
      mdCtxFree(ctx);
    }
  }

  // ---------- signatures (EVP_DigestSign) ----------

  /**
   * EVP_DigestSignInit_ex.
   * @param mdName the name of the digest, or {@link MemorySegment#NULL} for algorithms without
   *               digest, such as ML-DSA and EdDSA.
   */
  static boolean digestSignInit(MemorySegment ctx, MemorySegment mdName, MemorySegment pkey,
                                MemorySegment params) {
    try {
      return (int) H.DIGEST_SIGN_INIT_EX.invokeExact(ctx, MemorySegment.NULL, mdName,
          MemorySegment.NULL, MemorySegment.NULL, pkey, params) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * Sets the parameters of the signature operation initialized in the EVP_MD_CTX
   * (EVP_PKEY_CTX_set_params on EVP_MD_CTX_get_pkey_ctx).
   */
  static boolean digestSignVerifySetParams(MemorySegment ctx, MemorySegment params) {
    MemorySegment pctx = callPtr(H.MD_CTX_GET_PKEY_CTX, ctx);
    return !isNull(pctx) && callInt(H.PKEY_CTX_SET_PARAMS, pctx, params) == 1;
  }

  /**
   * EVP_DigestVerifyInit_ex.
   * @param mdName the name of the digest, or {@link MemorySegment#NULL} for algorithms without
   *               digest, such as ML-DSA and EdDSA.
   */
  static boolean digestVerifyInit(MemorySegment ctx, MemorySegment mdName, MemorySegment pkey,
                                  MemorySegment params) {
    try {
      return (int) H.DIGEST_VERIFY_INIT_EX.invokeExact(ctx, MemorySegment.NULL, mdName,
          MemorySegment.NULL, MemorySegment.NULL, pkey, params) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * EVP_DigestSign. The segments may be heap segments (the call is critical).
   * @return the signature, or null on error.
   */
  static byte[] digestSign(MemorySegment ctx, int maxSigLen, MemorySegment tbs) {
    byte[] sig = new byte[maxSigLen];
    long[] sigLen = {maxSigLen};
    try {
      int rc = (int) H.DIGEST_SIGN.invokeExact(ctx, MemorySegment.ofArray(sig),
          MemorySegment.ofArray(sigLen), tbs, tbs.byteSize());
      if (rc != 1) {
        return null;
      }
    } catch (Throwable t) {
      throw rethrow(t);
    }
    return sigLen[0] == maxSigLen ? sig : Arrays.copyOf(sig, (int) sigLen[0]);
  }

  /**
   * EVP_DigestVerify. The segments may be heap segments (the call is critical).
   * @return 1 if valid, 0 if invalid, other values on error.
   */
  static int digestVerify(MemorySegment ctx, MemorySegment sig, MemorySegment tbs) {
    try {
      return (int) H.DIGEST_VERIFY.invokeExact(ctx, sig, sig.byteSize(), tbs, tbs.byteSize());
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  // ---------- EVP_PKEY ----------

  /**
   * Decodes the private key (PKCS#8, or the traditional formats).
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment d2iPrivateKey(byte[] der) {
    return d2i(H.D2I_AUTO_PRIVATE_KEY_EX, der);
  }

  /**
   * Decodes the SubjectPublicKeyInfo.
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment d2iPublicKey(byte[] der) {
    return d2i(H.D2I_PUBKEY_EX, der);
  }

  private static MemorySegment d2i(MethodHandle d2i, byte[] der) {
    try (Arena arena = Arena.ofConfined()) {
      // the input pointer is advanced by d2i: it must be native memory
      MemorySegment buf = copyOf(arena, der);
      MemorySegment pp = arena.allocate(C_POINTER);
      pp.set(C_POINTER, 0, buf);
      try {
        return callPtr(d2i, MemorySegment.NULL, pp, (long) der.length,
            MemorySegment.NULL, MemorySegment.NULL);
      } finally {
        buf.fill((byte) 0);
      }
    }
  }

  /**
   * EVP_PKEY_new_raw_private_key_ex: e.g. X25519, Ed25519, or the expanded private key of
   * ML-KEM.
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment newRawPrivateKey(String keyType, byte[] key) {
    return newRawKey(H.NEW_RAW_PRIVATE_KEY_EX, keyType, key, true);
  }

  /**
   * EVP_PKEY_new_raw_public_key_ex: e.g. X25519, Ed25519, or the encapsulation key of ML-KEM.
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment newRawPublicKey(String keyType, byte[] key) {
    return newRawKey(H.NEW_RAW_PUBLIC_KEY_EX, keyType, key, false);
  }

  private static MemorySegment newRawKey(MethodHandle mh, String keyType, byte[] key,
                                         boolean secret) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = copyOf(arena, key);
      try {
        return callPtr(mh, MemorySegment.NULL, arena.allocateFrom(keyType),
            MemorySegment.NULL, buf, (long) key.length);
      } finally {
        if (secret) {
          buf.fill((byte) 0);
        }
      }
    }
  }

  static void pkeyFree(MemorySegment pkey) {
    call(H.PKEY_FREE, pkey);
  }

  static boolean pkeyIsA(MemorySegment pkey, String name) {
    try (Arena arena = Arena.ofConfined()) {
      return callInt(H.PKEY_IS_A, pkey, arena.allocateFrom(name)) == 1;
    }
  }

  /** Returns the type name of the key, e.g. "RSA", "EC", "SM2", "ED25519", "ML-DSA-65". */
  static String pkeyTypeName(MemorySegment pkey) {
    MemorySegment s = callPtr(H.PKEY_GET0_TYPE_NAME, pkey);
    return isNull(s) ? null : s.reinterpret(256).getString(0);
  }

  /** EVP_PKEY_get_size: the maximal size of a signature or ciphertext. */
  static int pkeySize(MemorySegment pkey) {
    return callInt(H.PKEY_GET_SIZE, pkey);
  }

  static int pkeyBits(MemorySegment pkey) {
    return callInt(H.PKEY_GET_BITS, pkey);
  }

  /**
   * EVP_PKEY_get_octet_string_param, e.g. "priv" for the expanded private key of ML-DSA.
   * @return the value, or null if not available.
   */
  static byte[] pkeyOctetStringParam(MemorySegment pkey, String name, int maxLen) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = arena.allocate(maxLen);
      MemorySegment outLen = arena.allocate(JAVA_LONG);
      int rc = callInt(H.PKEY_GET_OCTET_STRING_PARAM, pkey, arena.allocateFrom(name), buf,
          (long) maxLen, outLen);
      try {
        if (rc != 1) {
          clearErrors();
          return null;
        }
        return buf.asSlice(0, outLen.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
      } finally {
        buf.fill((byte) 0);
      }
    }
  }

  /**
   * EVP_PKEY_get_utf8_string_param, e.g. "group" for the curve of an EC key.
   * @return the value, or null if not available.
   */
  static String pkeyUtf8StringParam(MemorySegment pkey, String name) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = arena.allocate(256);
      int rc = callInt(H.PKEY_GET_UTF8_STRING_PARAM, pkey, arena.allocateFrom(name), buf,
          buf.byteSize(), MemorySegment.NULL);
      if (rc != 1) {
        clearErrors();
        return null;
      }
      return buf.getString(0);
    }
  }

  /**
   * EVP_PKEY_get_bn_param, e.g. "n" of an RSA key.
   * @return the value, or null if not available.
   */
  static BigInteger pkeyBigIntParam(MemorySegment pkey, String name) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment pbn = arena.allocate(C_POINTER);
      if (callInt(H.PKEY_GET_BN_PARAM, pkey, arena.allocateFrom(name), pbn) != 1) {
        clearErrors();
        return null;
      }
      MemorySegment bn = pbn.get(C_POINTER, 0);
      try {
        return toBigInteger(bn);
      } finally {
        call(H.BN_CLEAR_FREE, bn);
      }
    }
  }

  /**
   * EVP_PKEY_get_raw_public_key or EVP_PKEY_get_raw_private_key, e.g. of X25519 and Ed25519.
   * @return the raw key, or null if not available.
   */
  static byte[] pkeyRawKey(MemorySegment pkey, boolean privateKey) {
    MethodHandle mh = privateKey ? H.PKEY_GET_RAW_PRIVATE_KEY : H.PKEY_GET_RAW_PUBLIC_KEY;
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment len = arena.allocate(JAVA_LONG);
      if (callInt(mh, pkey, MemorySegment.NULL, len) != 1) {
        clearErrors();
        return null;
      }
      MemorySegment buf = arena.allocate(Math.max(1, len.get(JAVA_LONG, 0)));
      try {
        if (callInt(mh, pkey, buf, len) != 1) {
          clearErrors();
          return null;
        }
        return buf.asSlice(0, len.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
      } finally {
        buf.fill((byte) 0);
      }
    }
  }

  /**
   * Encodes the key as DER SubjectPublicKeyInfo or PrivateKeyInfo (PKCS#8).
   * @return the encoding, or null on error.
   */
  static byte[] encodeKey(MemorySegment pkey, boolean privateKey) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment ctx = callPtr(H.ENCODER_CTX_NEW_FOR_PKEY, pkey,
          privateKey ? SELECT_KEYPAIR : SELECT_PUBLIC_KEY, arena.allocateFrom("DER"),
          arena.allocateFrom(privateKey ? "PrivateKeyInfo" : "SubjectPublicKeyInfo"),
          MemorySegment.NULL);
      if (isNull(ctx)) {
        return null;
      }
      try {
        MemorySegment pdata = arena.allocate(C_POINTER);
        MemorySegment plen = arena.allocate(JAVA_LONG);
        if (callInt(H.ENCODER_TO_DATA, ctx, pdata, plen) != 1) {
          return null;
        }
        long len = plen.get(JAVA_LONG, 0);
        MemorySegment data = pdata.get(C_POINTER, 0).reinterpret(len);
        try {
          return data.toArray(JAVA_BYTE);
        } finally {
          if (privateKey) {
            data.fill((byte) 0);
          }
          call(H.CRYPTO_FREE, data, MemorySegment.NULL, 0);
        }
      } finally {
        call(H.ENCODER_CTX_FREE, ctx);
      }
    }
  }

  // ---------- EVP_PKEY_CTX ----------

  /** EVP_PKEY_CTX_new_from_name, the caller frees it. */
  static MemorySegment pkeyCtxNew(String keyType) {
    try (Arena arena = Arena.ofConfined()) {
      return callPtr(H.PKEY_CTX_NEW_FROM_NAME, MemorySegment.NULL, arena.allocateFrom(keyType),
          MemorySegment.NULL);
    }
  }

  /** EVP_PKEY_CTX_new_from_pkey, the caller frees it. */
  static MemorySegment pkeyCtxNew(MemorySegment pkey) {
    return callPtr(H.PKEY_CTX_NEW_FROM_PKEY, MemorySegment.NULL, pkey, MemorySegment.NULL);
  }

  static void pkeyCtxFree(MemorySegment ctx) {
    call(H.PKEY_CTX_FREE, ctx);
  }

  /**
   * Generates a key.
   * @param keyType the key type, e.g. "RSA", "EC", "ML-DSA-65".
   * @param params the parameters of the generation, e.g. "bits", "group" or "seed"; may be
   *               empty.
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment generateKey(String keyType, OsslParams params) {
    MemorySegment ctx = pkeyCtxNew(keyType);
    if (isNull(ctx)) {
      return MemorySegment.NULL;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment p = params.build(arena);
      try {
        MemorySegment ppkey = arena.allocate(C_POINTER);
        if (callInt(H.PKEY_KEYGEN_INIT, ctx) != 1
            || (!isNull(p) && callInt(H.PKEY_CTX_SET_PARAMS, ctx, p) != 1)
            || callInt(H.PKEY_GENERATE, ctx, ppkey) != 1) {
          return MemorySegment.NULL;
        }
        return ppkey.get(C_POINTER, 0);
      } finally {
        OsslParams.clear(p);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /**
   * Creates a key from its components (EVP_PKEY_fromdata).
   * @param keyType the key type, e.g. "RSA", "EC".
   * @param privateKey whether the components contain the private key.
   * @return the EVP_PKEY, or {@link MemorySegment#NULL} on error.
   */
  static MemorySegment keyFromData(String keyType, boolean privateKey, OsslParams params) {
    MemorySegment ctx = pkeyCtxNew(keyType);
    if (isNull(ctx)) {
      return MemorySegment.NULL;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment p = params.build(arena);
      try {
        MemorySegment ppkey = arena.allocate(C_POINTER);
        if (callInt(H.PKEY_FROMDATA_INIT, ctx) != 1
            || callInt(H.PKEY_FROMDATA, ctx, ppkey,
                privateKey ? SELECT_KEYPAIR : SELECT_PUBLIC_KEY, p) != 1) {
          return MemorySegment.NULL;
        }
        return ppkey.get(C_POINTER, 0);
      } finally {
        OsslParams.clear(p);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /** The asymmetric operations of {@link #pkeyOp}. */
  enum PkeyOp {
    SIGN(H.PKEY_SIGN_INIT_EX, H.PKEY_SIGN),
    VERIFY_RECOVER(H.PKEY_VERIFY_RECOVER_INIT_EX, H.PKEY_VERIFY_RECOVER),
    ENCRYPT(H.PKEY_ENCRYPT_INIT_EX, H.PKEY_ENCRYPT),
    DECRYPT(H.PKEY_DECRYPT_INIT_EX, H.PKEY_DECRYPT);

    private final MethodHandle init;

    private final MethodHandle op;

    PkeyOp(MethodHandle init, MethodHandle op) {
      this.init = init;
      this.op = op;
    }
  }

  /**
   * EVP_PKEY_sign, EVP_PKEY_verify_recover, EVP_PKEY_encrypt or EVP_PKEY_decrypt.
   * @param params the parameters, e.g. "pad-mode"; may be empty.
   * @return the output, or null on error.
   */
  static byte[] pkeyOp(PkeyOp op, MemorySegment pkey, OsslParams params, byte[] in) {
    MemorySegment ctx = pkeyCtxNew(pkey);
    if (isNull(ctx)) {
      return null;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment p = params.build(arena);
      MemorySegment inSeg = copyOf(arena, in);
      MemorySegment outLen = arena.allocate(JAVA_LONG);
      try {
        if (callInt(op.init, ctx, p) != 1
            || callInt(op.op, ctx, MemorySegment.NULL, outLen, inSeg, (long) in.length) != 1) {
          return null;
        }
        MemorySegment out = arena.allocate(Math.max(1, outLen.get(JAVA_LONG, 0)));
        try {
          if (callInt(op.op, ctx, out, outLen, inSeg, (long) in.length) != 1) {
            return null;
          }
          return out.asSlice(0, outLen.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
        } finally {
          out.fill((byte) 0);
        }
      } finally {
        inSeg.fill((byte) 0);
        OsslParams.clear(p);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /**
   * EVP_PKEY_verify, e.g. ECDSA of a hash.
   * @return 1 if valid, 0 if invalid, other values on error.
   */
  static int pkeyVerify(MemorySegment pkey, byte[] sig, byte[] tbs) {
    MemorySegment ctx = pkeyCtxNew(pkey);
    if (isNull(ctx)) {
      return -1;
    }

    try (Arena arena = Arena.ofConfined()) {
      if (callInt(H.PKEY_VERIFY_INIT_EX, ctx, MemorySegment.NULL) != 1) {
        return -1;
      }
      return callInt(H.PKEY_VERIFY, ctx, copyOf(arena, sig), (long) sig.length,
          copyOf(arena, tbs), (long) tbs.length);
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /**
   * Key agreement (EVP_PKEY_derive), e.g. ECDH and X25519.
   * @return the shared secret, or null on error.
   */
  static byte[] derive(MemorySegment pkey, MemorySegment peer) {
    MemorySegment ctx = pkeyCtxNew(pkey);
    if (isNull(ctx)) {
      return null;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment len = arena.allocate(JAVA_LONG);
      if (callInt(H.PKEY_DERIVE_INIT_EX, ctx, MemorySegment.NULL) != 1
          || callInt(H.PKEY_DERIVE_SET_PEER_EX, ctx, peer, 1) != 1
          || callInt(H.PKEY_DERIVE, ctx, MemorySegment.NULL, len) != 1) {
        return null;
      }
      MemorySegment out = arena.allocate(Math.max(1, len.get(JAVA_LONG, 0)));
      try {
        if (callInt(H.PKEY_DERIVE, ctx, out, len) != 1) {
          return null;
        }
        return out.asSlice(0, len.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
      } finally {
        out.fill((byte) 0);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /**
   * EVP_PKEY_encapsulate with the public key.
   * @return {wrapped key (ciphertext), shared secret}, or null on error.
   */
  static byte[][] encapsulate(MemorySegment pkey) {
    MemorySegment ctx = pkeyCtxNew(pkey);
    if (isNull(ctx)) {
      return null;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment wrappedLen = arena.allocate(JAVA_LONG);
      MemorySegment secretLen = arena.allocate(JAVA_LONG);
      if (callInt(H.PKEY_ENCAPSULATE_INIT, ctx, MemorySegment.NULL) != 1
          // the lengths
          || callInt(H.PKEY_ENCAPSULATE, ctx, MemorySegment.NULL, wrappedLen,
              MemorySegment.NULL, secretLen) != 1) {
        return null;
      }

      MemorySegment wrapped = arena.allocate(wrappedLen.get(JAVA_LONG, 0));
      MemorySegment secret = arena.allocate(secretLen.get(JAVA_LONG, 0));
      try {
        if (callInt(H.PKEY_ENCAPSULATE, ctx, wrapped, wrappedLen, secret, secretLen) != 1) {
          return null;
        }
        return new byte[][]{
            wrapped.asSlice(0, wrappedLen.get(JAVA_LONG, 0)).toArray(JAVA_BYTE),
            secret.asSlice(0, secretLen.get(JAVA_LONG, 0)).toArray(JAVA_BYTE)};
      } finally {
        secret.fill((byte) 0);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  /**
   * EVP_PKEY_decapsulate with the private key.
   * @return the shared secret, or null on error.
   */
  static byte[] decapsulate(MemorySegment pkey, byte[] wrappedKey) {
    MemorySegment ctx = pkeyCtxNew(pkey);
    if (isNull(ctx)) {
      return null;
    }

    try (Arena arena = Arena.ofConfined()) {
      MemorySegment wrapped = copyOf(arena, wrappedKey);
      MemorySegment secretLen = arena.allocate(JAVA_LONG);
      if (callInt(H.PKEY_DECAPSULATE_INIT, ctx, MemorySegment.NULL) != 1
          // the length
          || callInt(H.PKEY_DECAPSULATE, ctx, MemorySegment.NULL, secretLen,
              wrapped, (long) wrappedKey.length) != 1) {
        return null;
      }

      MemorySegment secret = arena.allocate(secretLen.get(JAVA_LONG, 0));
      try {
        if (callInt(H.PKEY_DECAPSULATE, ctx, secret, secretLen,
            wrapped, (long) wrappedKey.length) != 1) {
          return null;
        }
        return secret.asSlice(0, secretLen.get(JAVA_LONG, 0)).toArray(JAVA_BYTE);
      } finally {
        secret.fill((byte) 0);
      }
    } finally {
      pkeyCtxFree(ctx);
    }
  }

  // ---------- EVP_CIPHER_CTX ----------

  static MemorySegment cipherCtxNew() {
    MemorySegment ctx = callPtr(H.CIPHER_CTX_NEW);
    if (isNull(ctx)) {
      throw new OutOfMemoryError("EVP_CIPHER_CTX_new failed");
    }
    return ctx;
  }

  static void cipherCtxFree(MemorySegment ctx) {
    call(H.CIPHER_CTX_FREE, ctx);
  }

  /**
   * EVP_CipherInit_ex2.
   * @param cipher the EVP_CIPHER, or {@link MemorySegment#NULL} to keep the current one.
   * @param key the key, or null to keep the current one.
   * @param iv the IV, or null to keep the current one.
   * @param enc 1 to encrypt, 0 to decrypt, -1 to keep the current direction.
   */
  static boolean cipherInit(MemorySegment ctx, MemorySegment cipher, byte[] key, byte[] iv,
                            int enc, OsslParams params) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment keySeg = (key == null) ? MemorySegment.NULL : copyOf(arena, key);
      MemorySegment ivSeg = (iv == null) ? MemorySegment.NULL : copyOf(arena, iv);
      MemorySegment p = (params == null) ? MemorySegment.NULL : params.build(arena);
      try {
        return callInt(H.CIPHER_INIT_EX2, ctx, cipher, keySeg, ivSeg, enc, p) == 1;
      } finally {
        if (key != null) {
          keySeg.fill((byte) 0);
        }
      }
    }
  }

  static boolean cipherSetPadding(MemorySegment ctx, boolean padding) {
    return callInt(H.CIPHER_CTX_SET_PADDING, ctx, padding ? 1 : 0) == 1;
  }

  static boolean cipherSetParams(MemorySegment ctx, OsslParams params) {
    try (Arena arena = Arena.ofConfined()) {
      return callInt(H.CIPHER_CTX_SET_PARAMS, ctx, params.build(arena)) == 1;
    }
  }

  /**
   * Returns the octet string parameter of the cipher context, e.g. the "tag" of GCM.
   * @return the value, or null on error.
   */
  static byte[] cipherGetOctets(MemorySegment ctx, String name, int len) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment p = new OsslParams().octets(name, new byte[len]).build(arena);
      if (callInt(H.CIPHER_CTX_GET_PARAMS, ctx, p) != 1) {
        return null;
      }
      return p.get(C_POINTER, 16).reinterpret(len).toArray(JAVA_BYTE);
    }
  }

  /**
   * EVP_CipherUpdate. The segments may be heap segments (the call is critical).
   * @param out the output, or {@link MemorySegment#NULL} for the additional authenticated data
   *            of AEAD ciphers.
   * @return the length of the output, or -1 on error.
   */
  static int cipherUpdate(MemorySegment ctx, MemorySegment out, MemorySegment in) {
    int[] outLen = new int[1];
    try {
      int rc = (int) H.CIPHER_UPDATE.invokeExact(ctx, out, MemorySegment.ofArray(outLen),
          in, (int) in.byteSize());
      return (rc == 1) ? outLen[0] : -1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * EVP_CipherFinal_ex. The output may be a heap segment (the call is critical).
   * @return the length of the output, or -1 on error.
   */
  static int cipherFinal(MemorySegment ctx, MemorySegment out) {
    int[] outLen = new int[1];
    try {
      int rc = (int) H.CIPHER_FINAL_EX.invokeExact(ctx, out, MemorySegment.ofArray(outLen));
      return (rc == 1) ? outLen[0] : -1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  // ---------- EVP_MAC ----------

  /**
   * Returns a new EVP_MAC_CTX, the caller frees it.
   * @param name the MAC, e.g. "HMAC" or "GMAC".
   * @return the EVP_MAC_CTX, or {@link MemorySegment#NULL} if unavailable.
   */
  static MemorySegment macCtxNew(String name) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment mac = callPtr(H.MAC_FETCH, MemorySegment.NULL, arena.allocateFrom(name),
          MemorySegment.NULL);
      if (isNull(mac)) {
        clearErrors();
        return mac;
      }
      // the context holds its own reference to the EVP_MAC
      MemorySegment ctx = callPtr(H.MAC_CTX_NEW, mac);
      call(H.MAC_FREE, mac);
      return ctx;
    }
  }

  static void macCtxFree(MemorySegment ctx) {
    call(H.MAC_CTX_FREE, ctx);
  }

  static MemorySegment macCtxDup(MemorySegment ctx) {
    return callPtr(H.MAC_CTX_DUP, ctx);
  }

  /**
   * EVP_MAC_init.
   * @param key the key, or null to keep the current one.
   */
  static boolean macInit(MemorySegment ctx, byte[] key, OsslParams params) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment keySeg = (key == null) ? MemorySegment.NULL : copyOf(arena, key);
      MemorySegment p = (params == null) ? MemorySegment.NULL : params.build(arena);
      try {
        return callInt(H.MAC_INIT, ctx, keySeg, (long) (key == null ? 0 : key.length), p) == 1;
      } finally {
        if (key != null) {
          keySeg.fill((byte) 0);
        }
      }
    }
  }

  static int macSize(MemorySegment ctx) {
    return (int) (long) call(H.MAC_CTX_GET_MAC_SIZE, ctx);
  }

  /** EVP_MAC_update. The data may be a heap segment (the call is critical). */
  static boolean macUpdate(MemorySegment ctx, MemorySegment data) {
    try {
      return (int) H.MAC_UPDATE.invokeExact(ctx, data, data.byteSize()) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  /**
   * EVP_MAC_final. The output may be a heap segment (the call is critical).
   * @return whether successful.
   */
  static boolean macFinal(MemorySegment ctx, MemorySegment out) {
    long[] outLen = new long[1];
    try {
      return (int) H.MAC_FINAL.invokeExact(ctx, out, MemorySegment.ofArray(outLen),
          out.byteSize()) == 1;
    } catch (Throwable t) {
      throw rethrow(t);
    }
  }

  // ---------- EVP_KDF ----------

  /**
   * Derives a key with the KDF.
   * @param name the KDF, e.g. "PBKDF2" or "HKDF".
   * @return the derived key, or null on error.
   */
  static byte[] kdfDerive(String name, OsslParams params, int keyLen) {
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment kdf = callPtr(H.KDF_FETCH, MemorySegment.NULL, arena.allocateFrom(name),
          MemorySegment.NULL);
      if (isNull(kdf)) {
        return null;
      }
      MemorySegment ctx = callPtr(H.KDF_CTX_NEW, kdf);
      call(H.KDF_FREE, kdf);
      if (isNull(ctx)) {
        return null;
      }

      MemorySegment p = params.build(arena);
      MemorySegment out = arena.allocate(Math.max(1, keyLen));
      try {
        if (callInt(H.KDF_DERIVE, ctx, out, (long) keyLen, p) != 1) {
          return null;
        }
        return out.asSlice(0, keyLen).toArray(JAVA_BYTE);
      } finally {
        out.fill((byte) 0);
        OsslParams.clear(p);
        call(H.KDF_CTX_FREE, ctx);
      }
    }
  }

  // ---------- BIGNUM ----------

  /** Returns a new BIGNUM, the caller frees it with {@link #bnFree(MemorySegment)}. */
  static MemorySegment bn(BigInteger value) {
    if (value.signum() < 0) {
      throw new IllegalArgumentException("negative value");
    }
    byte[] be = value.toByteArray();
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = copyOf(arena, be);
      try {
        MemorySegment bn = callPtr(H.BN_BIN2BN, buf, be.length, MemorySegment.NULL);
        if (isNull(bn)) {
          throw new OutOfMemoryError("BN_bin2bn failed");
        }
        return bn;
      } finally {
        buf.fill((byte) 0);
        Arrays.fill(be, (byte) 0);
      }
    }
  }

  static MemorySegment bnNew() {
    MemorySegment bn = callPtr(H.BN_NEW);
    if (isNull(bn)) {
      throw new OutOfMemoryError("BN_new failed");
    }
    return bn;
  }

  static void bnFree(MemorySegment bn) {
    call(H.BN_CLEAR_FREE, bn);
  }

  static BigInteger toBigInteger(MemorySegment bn) {
    int len = (callInt(H.BN_NUM_BITS, bn) + 7) / 8;
    if (len == 0) {
      return BigInteger.ZERO;
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = arena.allocate(len);
      try {
        callInt(H.BN_BN2BINPAD, bn, buf, len);
        return new BigInteger(1, buf.toArray(JAVA_BYTE));
      } finally {
        buf.fill((byte) 0);
      }
    }
  }

  // ---------- EC_GROUP, EC_POINT ----------

  /**
   * Returns the EC_GROUP of the curve, never freed.
   * @param name the name or OID of the curve, e.g. "prime256v1".
   * @return the EC_GROUP, or {@link MemorySegment#NULL} if unknown.
   */
  static MemorySegment ecGroup(String name) {
    try (Arena arena = Arena.ofConfined()) {
      int nid = callInt(H.OBJ_TXT2NID, arena.allocateFrom(name));
      if (nid == 0) {
        clearErrors();
        return MemorySegment.NULL;
      }
      MemorySegment group = callPtr(H.EC_GROUP_NEW_BY_CURVE_NAME_EX, MemorySegment.NULL,
          MemorySegment.NULL, nid);
      if (isNull(group)) {
        clearErrors();
      }
      return group;
    }
  }

  /** Returns {p, a, b, order, cofactor} of the group. */
  static BigInteger[] ecGroupParams(MemorySegment group) {
    MemorySegment p = bnNew();
    MemorySegment a = bnNew();
    MemorySegment b = bnNew();
    try {
      if (callInt(H.EC_GROUP_GET_CURVE, group, p, a, b, MemorySegment.NULL) != 1) {
        throw new IllegalStateException("EC_GROUP_get_curve failed: " + errors());
      }
      return new BigInteger[]{toBigInteger(p), toBigInteger(a), toBigInteger(b),
          toBigInteger(callPtr(H.EC_GROUP_GET0_ORDER, group)),
          toBigInteger(callPtr(H.EC_GROUP_GET0_COFACTOR, group))};
    } finally {
      bnFree(p);
      bnFree(a);
      bnFree(b);
    }
  }

  static MemorySegment ecGenerator(MemorySegment group) {
    return callPtr(H.EC_GROUP_GET0_GENERATOR, group);
  }

  static int ecDegree(MemorySegment group) {
    return callInt(H.EC_GROUP_GET_DEGREE, group);
  }

  /** Returns a new EC_POINT, the caller frees it with {@link #ecPointFree(MemorySegment)}. */
  static MemorySegment ecPointNew(MemorySegment group) {
    MemorySegment p = callPtr(H.EC_POINT_NEW, group);
    if (isNull(p)) {
      throw new OutOfMemoryError("EC_POINT_new failed");
    }
    return p;
  }

  static void ecPointFree(MemorySegment point) {
    call(H.EC_POINT_CLEAR_FREE, point);
  }

  /**
   * Decodes the point (EC_POINT_oct2point), which checks that it is on the curve.
   * @return the new point, or {@link MemorySegment#NULL} if invalid.
   */
  static MemorySegment ecPointDecode(MemorySegment group, byte[] encoded) {
    MemorySegment point = ecPointNew(group);
    try (Arena arena = Arena.ofConfined()) {
      if (callInt(H.EC_POINT_OCT2POINT, group, point, copyOf(arena, encoded),
          (long) encoded.length, MemorySegment.NULL) != 1) {
        clearErrors();
        ecPointFree(point);
        return MemorySegment.NULL;
      }
      return point;
    }
  }

  /** Encodes the point (EC_POINT_point2oct); the infinity is encoded as {0x00}. */
  static byte[] ecPointEncode(MemorySegment group, MemorySegment point, boolean compressed) {
    int form = compressed ? POINT_COMPRESSED : POINT_UNCOMPRESSED;
    long len = (long) call(H.EC_POINT_POINT2OCT, group, point, form, MemorySegment.NULL, 0L,
        MemorySegment.NULL);
    if (len == 0) {
      // the infinity
      clearErrors();
      return new byte[1];
    }
    try (Arena arena = Arena.ofConfined()) {
      MemorySegment buf = arena.allocate(len);
      call(H.EC_POINT_POINT2OCT, group, point, form, buf, len, MemorySegment.NULL);
      return buf.toArray(JAVA_BYTE);
    }
  }

  static boolean ecPointIsInfinity(MemorySegment group, MemorySegment point) {
    return callInt(H.EC_POINT_IS_AT_INFINITY, group, point) == 1;
  }

  /**
   * Returns a new point n·G + m·Q (EC_POINT_mul), the caller frees it.
   * @param n the scalar of the generator, or null.
   * @param q the point, or {@link MemorySegment#NULL}.
   * @param m the scalar of q, or null.
   */
  static MemorySegment ecPointMul(MemorySegment group, BigInteger n, MemorySegment q,
                                  BigInteger m) {
    MemorySegment bnN = (n == null) ? MemorySegment.NULL : bn(n);
    MemorySegment bnM = (m == null) ? MemorySegment.NULL : bn(m);
    MemorySegment r = ecPointNew(group);
    try {
      if (callInt(H.EC_POINT_MUL, group, r, bnN, q, bnM, MemorySegment.NULL) != 1) {
        ecPointFree(r);
        throw new IllegalStateException("EC_POINT_mul failed: " + errors());
      }
      return r;
    } finally {
      if (n != null) {
        bnFree(bnN);
      }
      if (m != null) {
        bnFree(bnM);
      }
    }
  }

  /** Returns a new point a + b (EC_POINT_add), the caller frees it. */
  static MemorySegment ecPointAdd(MemorySegment group, MemorySegment a, MemorySegment b) {
    MemorySegment r = ecPointNew(group);
    if (callInt(H.EC_POINT_ADD, group, r, a, b, MemorySegment.NULL) != 1) {
      ecPointFree(r);
      throw new IllegalStateException("EC_POINT_add failed: " + errors());
    }
    return r;
  }

}
