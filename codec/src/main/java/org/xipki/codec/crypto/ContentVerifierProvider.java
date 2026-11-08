// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.crypto;

import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;

import java.time.Instant;

/**
 * General interface for providers of ContentVerifier objects.
 *
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public interface ContentVerifierProvider {

  /**
   * Return whether this verifier has a certificate associated with it.
   *
   * @return true if there is an associated certificate, false otherwise.
   */
  boolean hasAssociatedCertificate();

  /**
   * Return the associated certificate if there is one.
   *
   * @return whether the associated certificate is true. If no certificate is
   *         associated, false is returned.
   */
  boolean isAssociatedCertificateValidOn(Instant time);

  /**
   * Return a ContentVerifier that matches the passed in algorithm identifier,
   *
   * @param verifierAlgorithmIdentifier the algorithm and parameters required.
   * @return a matching ContentVerifier
   * @throws GenerationException if the required ContentVerifier cannot be created.
   */
  ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws GenerationException;
}
