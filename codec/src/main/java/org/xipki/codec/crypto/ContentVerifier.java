// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.crypto;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/**
 * General interface for an operator that is able to verify a signature based
 * on data in a stream of output.
 *
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public interface ContentVerifier {

  /**
   * Return the algorithm identifier describing the signature
   * algorithm and parameters this verifier supports.
   *
   * @return algorithm oid and parameters.
   */
  AlgorithmIdentifier getAlgorithmIdentifier();

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
  boolean verify(byte[] signature) throws SignatureException;

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default boolean atomicVerify(byte[] dataToVerify, byte[] signature) throws SignatureException {
    OutputStream os = getOutputStream();
    if (os instanceof SignatureOutputStream) {
      Signature sig = ((SignatureOutputStream) os).getSig();
      sig.update(dataToVerify);
      return sig.verify(signature);
    } else {
      try {
        os.write(dataToVerify);
        os.close();
      } catch (IOException e) {
        throw new SignatureException("error verifying", e);
      }
      return verify(signature);
    }
  }

}
