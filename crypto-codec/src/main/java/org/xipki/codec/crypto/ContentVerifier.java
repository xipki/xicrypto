// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.crypto;

import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.c509.SignatureValue;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * General interface for an operator that is able to verify a signature based
 * on data in a stream of output.
 *
 * @author Lijun Liao (xipki)
 */
public interface ContentVerifier extends AtomicContentVerifier {

  /**
   * Returns a stream that will accept data for the purpose of calculating
   * a signature for later verification.
   *
   * @return an OutputStream
   */
  OutputStream getOutputStream();

  /**
   * Return true if the signature value matches the data passed
   * into the stream.
   *
   * @param signature the signature to be verified.
   * @return true if the signature verifies, false otherwise
   */
  boolean x509Verify(byte[] signature) throws SignatureException;

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default boolean atomicX509Verify(byte[] dataToVerify, byte[] signature)
      throws SignatureException {
    OutputStream os = getOutputStream();
    try {
      os.write(dataToVerify);
      os.close();
    } catch (IOException e) {
      throw new SignatureException("error verifying", e);
    }
    return x509Verify(signature);
  }

  /**
   * Returns a C509 verifier stream that will accept data for the purpose of calculating
   * a signature for later verification.
   *
   * @return an OutputStream
   */
  default OutputStream getC509OutputStream() {
   c509Algorithm();
    return getOutputStream();
  }

  /**
   * Return true if the signature value matches the data passed
   * into the stream.
   *
   * @param signature the signature to be verified.
   * @return true if the signature verifies, false otherwise
   */
  default boolean c509Verify(SignatureValue signature) throws SignatureException {
    int algId = c509Algorithm();
    return x509Verify(toX509Signature(algId, signature));
  }

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  @Override
  default boolean atomicC509Verify(byte[] dataToVerify, SignatureValue signature)
      throws SignatureException {
    int algId = c509Algorithm();
    return atomicX509Verify(dataToVerify, toX509Signature(algId, signature));
  }

  /**
   * Converts the C509 signature value to the X.509 signature value: the plain ECDSA / SM2
   * signature (r || s) is converted to the X9.62 format.
   */
  private static byte[] toX509Signature(int c509AlgId, SignatureValue signature)
      throws SignatureException {
    if (!(signature instanceof BytesSignatureValue)) {
      throw new SignatureException("unsupported signature " + signature);
    }

    byte[] c509SigValue = ((BytesSignatureValue) signature).value();
    return ConstSignatureAlgorithm.isEcdsaSignature(c509AlgId)
        ? Asn1Util.dsaSigPlainToX962(c509SigValue) : c509SigValue;
  }

}
