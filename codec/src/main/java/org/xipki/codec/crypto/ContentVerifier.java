// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.crypto;

import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.c509.ConstSignatureAlgorithm;

import java.io.IOException;
import java.io.OutputStream;
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
    try {
      os.write(dataToVerify);
      os.close();
    } catch (IOException e) {
      throw new SignatureException("error verifying", e);
    }
    return verify(signature);
  }

  /**
   * Return the C509 algorithm identifier describing the signature
   * algorithm and parameters this verifier supports.
   *
   * @return algorithm oid and parameters.
   */
  Integer getC509AlgorithmIdentifier();

  /**
   * Returns a C509 verifier stream that will accept data for the purpose of calculating
   * a signature for later verification.
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
   * Return true if the signature value matches the data passed
   * into the stream.
   *
   * @param signature the signature to be verified.
   * @return true if the signature verifies, false otherwise
   */
  default boolean c509Verify(byte[] signature) throws SignatureException {
    Integer algId = getC509AlgorithmIdentifier();
    if (algId == null) {
      throw new IllegalStateException("This signer is not C509 capable");
    }
    return verify(signature);
  }

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToVerify the data to be verified.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  default boolean atomicC509Verify(byte[] dataToVerify, byte[] signature)
      throws SignatureException {
    Integer algId = getC509AlgorithmIdentifier();
    if (algId == null) {
      throw new IllegalStateException("This signer is not C509 capable");
    }

    byte[] x509SigValue;
    if (ConstSignatureAlgorithm.isEcdsaSignature(algId)) {
      x509SigValue = Asn1Util.dsaSigPlainToX962(signature);
    } else {
      x509SigValue = signature;
    }
    return atomicVerify(dataToVerify, x509SigValue);
  }

}
