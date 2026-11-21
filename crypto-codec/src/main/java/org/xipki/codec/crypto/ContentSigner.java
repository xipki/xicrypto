// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.codec.crypto;

import org.xipki.codec.c509.BytesSignatureValue;
import org.xipki.codec.c509.SignatureValue;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * General interface for an operator that is able to create a signature from
 * a stream of output.
 *
 * @author Lijun Liao (xipki)
 */
public interface ContentSigner extends AtomicContentSigner {

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
  byte[] getX509Signature() throws SignatureException;

  /**
   * Returns a signature based on the current data written to the stream, since the
   * start or the last call to getSignature().
   *
   * @return bytes representing the signature.
   */
  default SignatureValue getC509Signature() throws SignatureException {
    c509Algorithm();
    return new BytesSignatureValue(getX509Signature());
  }

  /**
   * Atomic operation to compute signature over the given data.
   * @param dataToSign the data to be signed.
   * @return the signature
   * @throws SignatureException when error occurred.
   */
  @Override
  default byte[] atomicX509Sign(byte[] dataToSign) throws SignatureException {
    OutputStream os = getOutputStream();
    try {
      os.write(dataToSign);
      os.close();
    } catch (IOException e) {
      throw new SignatureException("error signing", e);
    }
    return getX509Signature();
  }

  /**
   * Returns the given C509 algorithm identifier, or throws an exception if it is {@code null}.
   *
   * @param c509AlgId the C509 algorithm identifier, may be {@code null}.
   * @param algorithm the signature algorithm, used in the error message.
   * @return the non-null C509 algorithm identifier.
   * @throws IllegalStateException if c509AlgId is {@code null}.
   */
  static int checkC509AlgId(Integer c509AlgId, Object algorithm) {
    if (c509AlgId == null) {
      throw new IllegalStateException("signature algorithm " + algorithm
          + " is not C509 capable");
    }
    return c509AlgId;
  }

}
