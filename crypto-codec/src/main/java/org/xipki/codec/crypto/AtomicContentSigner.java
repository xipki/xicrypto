// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.codec.crypto;

import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.x509.AlgorithmIdentifier;

import java.security.SignatureException;

/**
 * General interface for an operator that is able to create a signature from
 * a stream of output.
 *
 * @author Lijun Liao (xipki)
 */
public interface AtomicContentSigner {

  /**
   * Return the algorithm identifier describing the signature
   * algorithm and parameters this signer generates.
   *
   * @return algorithm oid and parameters, never {@code null}.
   * @throws IllegalStateException if the algorithm identifier is not available.
   */
  AlgorithmIdentifier x509Algorithm();

  byte[] atomicX509Sign(byte[] dataToSign) throws SignatureException;

  /**
   * Return the C509 algorithm identifier describing the signature algorithm this signer
   * generates.
   *
   * @return the C509 algorithm identifier, never {@code null}.
   * @throws IllegalStateException if this signer is not C509 capable.
   */
  int c509Algorithm();

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToSign the data to be signed.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default SignatureValue atomicC509Sign(byte[] dataToSign) throws SignatureException {
    c509Algorithm();
    return new BytesSignatureValue(atomicX509Sign(dataToSign));
  }

}
