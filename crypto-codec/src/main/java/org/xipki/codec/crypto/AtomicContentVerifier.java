// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.crypto;

import org.xipki.codec.c509.SignatureValue;
import org.xipki.codec.x509.AlgorithmIdentifier;

import java.security.SignatureException;

/**
 * General interface for an operator that is able to verify a signature based
 * on data in a stream of output.
 *
 * @author Lijun Liao (xipki)
 */
public interface AtomicContentVerifier {

  /**
   * Return the algorithm identifier describing the signature
   * algorithm and parameters this verifier supports.
   *
   * @return algorithm oid and parameters.
   */
  AlgorithmIdentifier x509Algorithm();

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  boolean atomicX509Verify(byte[] dataToVerify, byte[] signature)
      throws SignatureException;

  /**
   * Return the C509 algorithm identifier describing the signature
   * algorithm and parameters this verifier supports.
   *
   * @return algorithm oid and parameters.
   */
  int c509Algorithm();

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  boolean atomicC509Verify(byte[] dataToVerify, SignatureValue signature)
      throws SignatureException;

}
