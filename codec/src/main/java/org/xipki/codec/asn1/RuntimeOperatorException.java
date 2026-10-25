// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.codec.asn1;

/**
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public class RuntimeOperatorException extends RuntimeException {

  public RuntimeOperatorException(String msg) {
    super(msg);
  }

  public RuntimeOperatorException(String msg, Throwable cause) {
    super(msg, cause);
  }

}
