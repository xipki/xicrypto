// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Locale;

/**
 * RSASSA-PSS (RFC 8017, section 8.1), either
 * <ul>
 *   <li>with SHAKE128 or SHAKE256 as hash and MGF (RFC 8702), the parameters are fixed; or</li>
 *   <li>with a hash of the {@link Primitives} and MGF1 with the same hash, set with a
 *       {@link PSSParameterSpec}: any salt length, trailer field 1. For the JDKs without
 *       RSASSA-PSS with SHA3 (JDK 11 to 15).</li>
 * </ul>
 *
 * @author Lijun Liao (xipki)
 */
public class RSAPSSSignatureSpi extends RsaSignatureSpi {

  private final Primitives primitives;

  private final boolean fixedParameters;

  private PssEncoder pss;

  /**
   * Constructor for RSASSA-PSS with MGF1, the parameters are set with a
   * {@link PSSParameterSpec}.
   * @param primitives the source of the digests and the raw RSA operation.
   */
  public RSAPSSSignatureSpi(Primitives primitives) {
    super(primitives, null);
    this.primitives = primitives;
    this.fixedParameters = false;
  }

  /**
   * Constructor for RSASSA-PSS with SHAKE128 or SHAKE256 (RFC 8702).
   * @param primitives the source of the raw RSA operation.
   * @param shakeStrength 128 (SHAKE128) or 256 (SHAKE256).
   */
  public RSAPSSSignatureSpi(Primitives primitives, int shakeStrength) {
    super(primitives, new Shake(shakeStrength, shakeStrength == 128 ? 32 : 64));
    this.primitives = primitives;
    this.fixedParameters = true;
    this.pss = PssEncoder.shake(shakeStrength);
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (fixedParameters) {
      super.engineSetParameter(params);
      return;
    }

    if (!(params instanceof PSSParameterSpec)) {
      throw new InvalidAlgorithmParameterException("PSSParameterSpec expected");
    }

    PSSParameterSpec spec = (PSSParameterSpec) params;
    String hashName = spec.getDigestAlgorithm();
    if (!"MGF1".equalsIgnoreCase(spec.getMGFAlgorithm())
        || !(spec.getMGFParameters() instanceof MGF1ParameterSpec)) {
      throw new InvalidAlgorithmParameterException("only MGF1 is supported");
    }
    String mgfHashName = ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm();
    if (!normalize(hashName).equals(normalize(mgfHashName))) {
      throw new InvalidAlgorithmParameterException("the hash of MGF1 (" + mgfHashName
          + ") differs from the hash of the message (" + hashName + ")");
    }
    if (spec.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
      throw new InvalidAlgorithmParameterException("only trailer field 1 is supported");
    }

    try {
      MessageDigest msgDigest = primitives.messageDigest(hashName);
      PssEncoder encoder = PssEncoder.mgf1(primitives.messageDigest(hashName),
          spec.getSaltLength());
      this.digest = msgDigest;
      this.pss = encoder;
    } catch (NoSuchAlgorithmException | IllegalArgumentException e) {
      throw new InvalidAlgorithmParameterException("unsupported PSS parameters: "
          + e.getMessage(), e);
    }
  }

  private static String normalize(String hashName) {
    return hashName.toUpperCase(Locale.ROOT).replace("-", "");
  }

  @Override
  byte[] encode(byte[] hash, int modBits) throws SignatureException {
    try {
      return pss.encode(hash, modBits, secureRandom());
    } catch (IllegalArgumentException e) {
      throw new SignatureException(e.getMessage(), e);
    }
  }

  @Override
  boolean matches(byte[] hash, byte[] m, int modBits) {
    // EM has emLen = ceil((modBits - 1) / 8) bytes, one byte less than m if modBits = 1 mod 8
    int emLen = (modBits - 1 + 7) / 8;
    int off = m.length - emLen;
    for (int i = 0; i < off; i++) {
      if (m[i] != 0) {
        return false;
      }
    }
    byte[] em = (off == 0) ? m : Arrays.copyOfRange(m, off, m.length);
    return pss.verify(hash, em, modBits);
  }

}
