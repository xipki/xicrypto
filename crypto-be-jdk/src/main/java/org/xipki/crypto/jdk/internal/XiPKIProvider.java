// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.jdk.internal;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CurveOIDs;
import org.xipki.crypto.jdk.internal.digest.AesGmacSpi;
import org.xipki.crypto.jdk.internal.digest.Shake;
import org.xipki.crypto.jdk.internal.ec.XiECDSASignatureSpi;
import org.xipki.crypto.jdk.internal.ec.XiECKeyFactorySpi;
import org.xipki.crypto.jdk.internal.ec.XiECKeyPairGeneratorSpi;
import org.xipki.crypto.jdk.internal.ec.XiECParametersSpi;

import java.io.Serial;

/**
 * JCA provider of XiPKI, used by crypto-be-jdk for the algorithms the JDK does not support:
 * <ul>
 *   <li>MessageDigest SM3, Mac HmacSM3, Signature SM3withSM2 (not with the system property
 *       org.xipki.crypto.jdk.internal.ec.math.EcCurve#PROP_DISABLE_SM set to true),</li>
 *   <li>Signature SHAKE128/SHAKE256 with RSA-PSS (RFC 8702),</li>
 *   <li>EC (KeyFactory, KeyPairGenerator, AlgorithmParameters) and ECDSA with SHA-1, SHA-2,
 *       SHA-3 and SHAKE (RFC 8692) on the curves of
 *       {@link org.xipki.crypto.jdk.internal.ec.math.EcCurve} (NIST P-256/384/521,
 *       brainpoolP256r1/P384r1/P512r1, SM2),</li>
 *   <li>Mac AES-GMAC.</li>
 * </ul>
 * The provider is meant to be used as an instance of the backend, not registered in
 * {@link java.security.Security}. The primitives it does not implement itself (SHA-1/2/3, HMAC,
 * raw RSA, AES/GCM) come from the {@link Primitives} given to the constructor. A subclass may
 * add or replace entries.
 *
 * @author Lijun Liao (xipki)
 */
public class XiPKIProvider extends XiProviderBase {

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * The name of this provider: "{@value}".
   */
  static final String PROVIDER_NAME = "XiPKI";

  private static final String PROVIDER_INFO = "XiPKI JCA provider";

  /**
   * Constructor with the primitives of the default JCA lookup.
   */
  XiPKIProvider() {
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
   * Constructor for a subclass with its own name.
   * @param name the name of the provider.
   * @param info the description of the provider.
   * @param primitives the source of the primitives (digests, HMACs, ciphers).
   */
  XiPKIProvider(String name, String info, Primitives primitives) {
    super(name, info, primitives);

    addSm();
    addShakeRsaPss();

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

  private void ecdsa(String name, String digest, String mac, Asn1Oid oid) {
    ecdsa(name, XiECDSASignatureSpi.class,
        p -> new XiECDSASignatureSpi(p, XiSignatureSpi.digest(p, digest), mac), oid);
  }

}
