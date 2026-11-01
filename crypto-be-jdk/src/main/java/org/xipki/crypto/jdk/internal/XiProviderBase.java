// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.GmOIDs;
import org.xipki.crypto.jdk.internal.digest.HmacSM3Spi;
import org.xipki.crypto.jdk.internal.digest.SM3Digest;
import org.xipki.crypto.jdk.internal.ec.SM2WITHSM3SignatureSpi;
import org.xipki.crypto.jdk.internal.ec.math.EcCurve;
import org.xipki.crypto.jdk.internal.rsa.RSAPSSSignatureSpi;

import java.io.Serial;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Base of the JCA provider of the crypto backend crypto-be-jdk for the algorithms the providers
 * of the JDK do not support. It registers nothing itself: a backend registers
 * the algorithms it needs, the shared ones with {@link #addSm()} and {@link #addShakeRsaPss()},
 * the others with {@link #service(String, String, Class, SpiFactory, String...)} and
 * {@link #ecdsa(String, Class, SpiFactory, Asn1Oid)}.
 * <p>
 * The provider is meant to be used as an instance of the backend, not registered in
 * {@link java.security.Security}. The primitives it does not implement itself (SHA-1/2/3, HMAC,
 * raw RSA, AES/GCM) come from the {@link Primitives} given to the constructor.
 *
 * @author Lijun Liao (xipki)
 */
abstract class XiProviderBase extends Provider {

  @Serial
  private static final long serialVersionUID = 1L;

  private static final String PROVIDER_VERSION = "1.0";

  private static final String EC_KEY_CLASSES = "java.security.interfaces.ECPublicKey"
      + "|java.security.interfaces.ECPrivateKey";

  private final transient Primitives primitives;

  /**
   * Constructor.
   * @param name the name of the provider.
   * @param info the description of the provider.
   * @param primitives the source of the primitives (digests, HMACs, ciphers), or null for the
   *                   default JCA lookup.
   */
  XiProviderBase(String name, String info, Primitives primitives) {
    super(name, PROVIDER_VERSION, info);
    this.primitives = (primitives == null) ? new Primitives() : primitives;
  }

  /**
   * Registers MessageDigest SM3, Mac HmacSM3 and Signature SM3withSM2, not with the system property
   * {@link EcCurve#PROP_DISABLE_SM} set to true.
   */
  final void addSm() {
    if (EcCurve.isSmDisabled()) {
      return;
    }

    service("MessageDigest", "SM3", SM3Digest.class, p -> new SM3Digest(),
        AlgorithmOIDs.id_sm3.getId());
    service("Mac", "HmacSM3", HmacSM3Spi.class, p -> new HmacSM3Spi(),
        GmOIDs.hmac_sm3.getId());
    service("Signature", "SM3WITHSM2", SM2WITHSM3SignatureSpi.class,
        p -> new SM2WITHSM3SignatureSpi(), "SM2WITHSM3", AlgorithmOIDs.sm2sign_with_sm3.getId());
  }

  /**
   * Registers Signature SHAKE128WITHRSAPSS and SHAKE256WITHRSAPSS (RFC 8702).
   */
  final void addShakeRsaPss() {
    service("Signature", "SHAKE128WITHRSAPSS", RSAPSSSignatureSpi.class,
        p -> new RSAPSSSignatureSpi(p, 128),
        "RSAPSSWITHSHAKE128", AlgorithmOIDs.id_RSASSA_PSS_SHAKE128.getId());
    service("Signature", "SHAKE256WITHRSAPSS", RSAPSSSignatureSpi.class,
        p -> new RSAPSSSignatureSpi(p, 256),
        "RSAPSSWITHSHAKE256", AlgorithmOIDs.id_RSASSA_PSS_SHAKE256.getId());
  }

  /**
   * Creates the SPI of a service with the {@link Primitives} of the provider.
   */
  @FunctionalInterface
  interface SpiFactory {

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
  final void ecdsa(String name, Class<?> clazz, SpiFactory factory, Asn1Oid oid) {
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
  final void service(String type, String name, Class<?> clazz, SpiFactory factory,
                               String... aliases) {
    putService(new XiService(this, type, name, clazz, factory, null, aliases));
  }

  /**
   * Service that creates the SPIs with its factory and the {@link Primitives} of the provider.
   */
  private static final class XiService extends Service {

    private final XiProviderBase provider;

    private final SpiFactory factory;

    XiService(XiProviderBase provider, String type, String name, Class<?> clazz,
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
