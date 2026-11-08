// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.crypto;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * General interface for an operator that is able to create a signature from
 * a stream of output.
 *
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public interface ContentSigner {

  /**
   * Return the algorithm identifier describing the signature
   * algorithm and parameters this signer generates.
   *
   * @return algorithm oid and parameters.
   */
  AlgorithmIdentifier getAlgorithmIdentifier();

  /**
   * Returns a stream that will accept data for the purpose of calculating
   * a signature.
   *
   * @return an OutputStream
   */
  OutputStream getOutputStream();

  /**
   * Returns a signature based on the current data written to the stream, since the
   * start or the last call to getSignature().
   *
   * @return bytes representing the signature.
   */
  byte[] getSignature() throws SignatureException;

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToSign the data to be signed.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default byte[] atomicSign(byte[] dataToSign) throws SignatureException {
    OutputStream os = getOutputStream();
    try {
      os.write(dataToSign);
      os.close();
    } catch (IOException e) {
      throw new SignatureException("error signing", e);
    }
    return getSignature();
  }

  Integer getC509AlgorithmIdentifier();

  /**
   * Returns a stream that will accept data for the purpose of calculating
   * a signature.
   *
   * @return an OutputStream
   */
  default OutputStream getC509OutputStream() {
    Integer algId = getC509AlgorithmIdentifier();
    if (algId == null) {
      throw new IllegalStateException("This signer is not C509 capable");
    }

    return getOutputStream();
  }

  /**
   * Returns a signature based on the current data written to the stream, since the
   * start or the last call to getSignature().
   *
   * @return bytes representing the signature.
   */
  default byte[] getC509Signature() throws SignatureException {
    Integer algId = getC509AlgorithmIdentifier();
    if (algId == null) {
      throw new IllegalStateException("This signer is not C509 capable");
    }

    return getSignature();
  }

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToSign the data to be signed.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default byte[] atomicC509Sign(byte[] dataToSign) throws SignatureException {
    Integer algId = getC509AlgorithmIdentifier();
    if (algId == null) {
      throw new IllegalStateException("This signer is not C509 capable");
    }
    return atomicSign(dataToSign);
  }

}
