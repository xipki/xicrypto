// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.crypto.extra.ec.SM2WITHSM3SignatureSpi;
import org.xipki.crypto.extra.ec.XiECDSASignatureSpi;
import org.xipki.crypto.extra.ec.XiECKeyFactorySpi;
import org.xipki.crypto.extra.ec.XiECKeyPairGeneratorSpi;
import org.xipki.crypto.extra.ec.XiECParametersSpi;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * JCA provider of XiPKI, used by the crypto backends (crypto-be-jdk, crypto-be-bcfips) for the
 * algorithms their providers do not support:
 * <ul>
 *   <li>MessageDigest SM3, Signature SM3withSM2 (not with the system property
 *       {@link EcCurve#PROP_DISABLE_SM} set to true),</li>
 *   <li>Signature SHAKE128/SHAKE256 with RSA-PSS (RFC 8702),</li>
 *   <li>Signature SHA3-*withRSA, RSASSA-PSS with MGF1 (also with SHA3), Mac HmacSHA3-*: for
 *       JDK 11 to 15, which have SHA3 only as MessageDigest,</li>
 *   <li>EC (KeyFactory, KeyPairGenerator, AlgorithmParameters) and ECDSA with SHA-1, SHA-2,
 *       SHA-3 and SHAKE (RFC 8692) on the curves of {@link EcCurve} (NIST P-256/384/521,
 *       brainpoolP256r1/P384r1/P512r1, SM2, FRP256v1),</li>
 *   <li>Mac AES-GMAC.</li>
 * </ul>
 * The provider is meant to be used as an instance of the backend, not registered in
 * {@link java.security.Security}. The primitives it does not implement itself (SHA-1/2/3, HMAC,
 * raw RSA, AES/GCM) come from the {@link Primitives} given to the constructor. A backend may
 * extend it to add or replace entries, see
 * {@link #service(String, String, Class, SpiFactory, String...)}.
 *
 * @author Lijun Liao (xipki)
 */
public class XiPKIProvider extends Provider {

  private static final long serialVersionUID = 1L;

  /**
   * The name of this provider: "{@value}".
   */
  public static final String PROVIDER_NAME = "XiPKI";

  private static final String PROVIDER_VERSION = "1.0";

  private static final String PROVIDER_INFO = "XiPKI JCA provider";

  private static final String EC_KEY_CLASSES = "java.security.interfaces.ECPublicKey"
      + "|java.security.interfaces.ECPrivateKey";

  private final transient Primitives primitives;

  /**
   * Constructor with the primitives of the default JCA lookup.
   */
  public XiPKIProvider() {
    this(new Primitives());
  }

  /**
   * Constructor.
   * @param primitives the source of the primitives (digests, HMACs, ciphers).
   */
  public XiPKIProvider(Primitives primitives) {
    this(PROVIDER_NAME, PROVIDER_INFO, primitives);
  }

  /**
   * Constructor for a subclass with its own name. The subclass adds or replaces entries with
   * {@link #service(String, String, Class, SpiFactory, String...)} and
   * {@link #ecdsa(String, Class, SpiFactory, Asn1Oid)}.
   * @param name the name of the provider.
   * @param info the description of the provider.
   * @param primitives the source of the primitives (digests, HMACs, ciphers).
   */
  protected XiPKIProvider(String name, String info, Primitives primitives) {
    super(name, PROVIDER_VERSION, info);
    this.primitives = (primitives == null) ? new Primitives() : primitives;

    boolean withSm = !EcCurve.isSmDisabled();
    if (withSm) {
      service("MessageDigest", "SM3", SM3Digest.class, p -> new SM3Digest(),
          AlgorithmOIDs.id_sm3.getId());
      service("Signature", "SM3WITHSM2", SM2WITHSM3SignatureSpi.class,
          p -> new SM2WITHSM3SignatureSpi(), "SM2WITHSM3", AlgorithmOIDs.sm2sign_with_sm3.getId());
    }

    service("Signature", "SHAKE128WITHRSAPSS", RSAPSSSignatureSpi.class,
        p -> new RSAPSSSignatureSpi(p, 128),
        "RSAPSSWITHSHAKE128", AlgorithmOIDs.id_RSASSA_PSS_SHAKE128.getId());
    service("Signature", "SHAKE256WITHRSAPSS", RSAPSSSignatureSpi.class,
        p -> new RSAPSSSignatureSpi(p, 256),
        "RSAPSSWITHSHAKE256", AlgorithmOIDs.id_RSASSA_PSS_SHAKE256.getId());

    // SHA3 with RSA (PKCS#1 v1.5), RSASSA-PSS (any hash, MGF1 with the same hash) and HMAC with
    // SHA3: the JDK has them since JDK 16, crypto-be-jdk uses these only on JDK 11 to 15.
    rsaPkcs1("SHA3-224", AlgorithmOIDs.id_sha3_224,
        AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_224);
    rsaPkcs1("SHA3-256", AlgorithmOIDs.id_sha3_256,
        AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_256);
    rsaPkcs1("SHA3-384", AlgorithmOIDs.id_sha3_384,
        AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_384);
    rsaPkcs1("SHA3-512", AlgorithmOIDs.id_sha3_512,
        AlgorithmOIDs.id_rsassa_pkcs1_v1_5_with_sha3_512);
    service("Signature", "RSASSA-PSS", RSAPSSSignatureSpi.class, RSAPSSSignatureSpi::new,
        AlgorithmOIDs.id_RSASSA_PSS.getId());

    hmacSha3(224, AlgorithmOIDs.id_hmacWithSHA3_224);
    hmacSha3(256, AlgorithmOIDs.id_hmacWithSHA3_256);
    hmacSha3(384, AlgorithmOIDs.id_hmacWithSHA3_384);
    hmacSha3(512, AlgorithmOIDs.id_hmacWithSHA3_512);

    String idEcPublicKey = AlgorithmOIDs.id_ecPublicKey.getId();
    service("KeyFactory", "EC", XiECKeyFactorySpi.class, p -> new XiECKeyFactorySpi(),
        "ECDSA", idEcPublicKey, CurveOIDs.sm2p256v1.getId());
    service("KeyPairGenerator", "EC", XiECKeyPairGeneratorSpi.class,
        p -> new XiECKeyPairGeneratorSpi(), "ECDSA", idEcPublicKey);
    service("AlgorithmParameters", "EC", XiECParametersSpi.class,
        p -> new XiECParametersSpi(), idEcPublicKey);

    ecdsa("SHA1WITHECDSA", "SHA-1", "HmacSHA1", AlgorithmOIDs.ecdsa_with_SHA1);
    ecdsa("SHA224WITHECDSA", "SHA-224", "HmacSHA224", AlgorithmOIDs.ecdsa_with_SHA224);
    ecdsa("SHA256WITHECDSA", "SHA-256", "HmacSHA256", AlgorithmOIDs.ecdsa_with_SHA256);
    ecdsa("SHA384WITHECDSA", "SHA-384", "HmacSHA384", AlgorithmOIDs.ecdsa_with_SHA384);
    ecdsa("SHA512WITHECDSA", "SHA-512", "HmacSHA512", AlgorithmOIDs.ecdsa_with_SHA512);
    ecdsa("SHA3-224WITHECDSA", "SHA3-224", "HmacSHA3-224", AlgorithmOIDs.id_ecdsa_with_sha3_224);
    ecdsa("SHA3-256WITHECDSA", "SHA3-256", "HmacSHA3-256", AlgorithmOIDs.id_ecdsa_with_sha3_256);
    ecdsa("SHA3-384WITHECDSA", "SHA3-384", "HmacSHA3-384", AlgorithmOIDs.id_ecdsa_with_sha3_384);
    ecdsa("SHA3-512WITHECDSA", "SHA3-512", "HmacSHA3-512", AlgorithmOIDs.id_ecdsa_with_sha3_512);
    // RFC 8692: SHAKE128 with 256 bits, SHAKE256 with 512 bits output; the nonce uses
    // HMAC-SHA256 or HMAC-SHA512, respectively
    ecdsa("SHAKE128WITHECDSA", XiECDSASignatureSpi.class,
        p -> new XiECDSASignatureSpi(p, new Shake(128, 32), "HmacSHA256"),
        AlgorithmOIDs.id_ecdsa_with_shake128);
    ecdsa("SHAKE256WITHECDSA", XiECDSASignatureSpi.class,
        p -> new XiECDSASignatureSpi(p, new Shake(256, 64), "HmacSHA512"),
        AlgorithmOIDs.id_ecdsa_with_shake256);

    service("Mac", "AES-GMAC", AesGmacSpi.class, AesGmacSpi::new, "AESGMAC",
        AlgorithmOIDs.AES128_GMAC.getId(), AlgorithmOIDs.AES192_GMAC.getId(),
        AlgorithmOIDs.AES256_GMAC.getId());
  }

  private void rsaPkcs1(String hash, Asn1Oid hashOid, Asn1Oid oid) {
    service("Signature", hash + "WITHRSA", RSAPKCS1SignatureSpi.class,
        p -> new RSAPKCS1SignatureSpi(p, hash, hashOid), oid.getId());
  }

  private void hmacSha3(int bits, Asn1Oid oid) {
    service("Mac", "HmacSHA3-" + bits, HmacSha3Spi.class, p -> new HmacSha3Spi(p, bits),
        oid.getId());
  }

  private void ecdsa(String name, String digest, String mac, Asn1Oid oid) {
    ecdsa(name, XiECDSASignatureSpi.class,
        p -> new XiECDSASignatureSpi(p, XiSignatureSpi.digest(p, digest), mac), oid);
  }

  /**
   * Creates the SPI of a service with the {@link Primitives} of the provider.
   */
  @FunctionalInterface
  protected interface SpiFactory {

    /**
     * Creates the SPI.
     * @param primitives the primitives of the provider.
     * @return the SPI.
     * @throws GeneralSecurityException if the SPI could not be created.
     */
    Object create(Primitives primitives) throws GeneralSecurityException;

  }

  /**
   * Registers an ECDSA signature, accepting the EC keys of any provider. An entry with the same
   * name replaces the existing one.
   * @param name the name of the algorithm.
   * @param clazz the class of the SPI.
   * @param factory the factory of the SPI.
   * @param oid the OID of the algorithm, registered as alias.
   */
  protected final void ecdsa(String name, Class<?> clazz, SpiFactory factory, Asn1Oid oid) {
    Map<String, String> attrs = new HashMap<>();
    attrs.put("SupportedKeyClasses", EC_KEY_CLASSES);
    putService(new XiService(this, "Signature", name, clazz, factory, attrs, oid.getId()));
  }

  /**
   * Registers an algorithm. An entry with the same type and name replaces the existing one.
   * @param type the type of the engine, e.g. "Signature".
   * @param name the name of the algorithm.
   * @param clazz the class of the SPI.
   * @param factory the factory of the SPI.
   * @param aliases the aliases of the algorithm.
   */
  protected final void service(String type, String name, Class<?> clazz, SpiFactory factory,
                               String... aliases) {
    putService(new XiService(this, type, name, clazz, factory, null, aliases));
  }

  /**
   * Service that creates the SPIs with its factory and the {@link Primitives} of the provider.
   */
  private static final class XiService extends Service {

    private final XiPKIProvider provider;

    private final SpiFactory factory;

    XiService(XiPKIProvider provider, String type, String name, Class<?> clazz,
              SpiFactory factory, Map<String, String> attributes, String... aliases) {
      super(provider, type, name, clazz.getName(), aliasList(aliases), attributes);
      this.provider = provider;
      this.factory = factory;
    }

    private static List<String> aliasList(String[] aliases) {
      return (aliases == null) ? null : new ArrayList<>(Arrays.asList(aliases));
    }

    @Override
    public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
      try {
        return factory.create(provider.primitives);
      } catch (GeneralSecurityException | RuntimeException e) {
        throw new NoSuchAlgorithmException("could not create " + getType() + " "
            + getAlgorithm() + ": " + e.getMessage(), e);
      }
    }

  }

}
