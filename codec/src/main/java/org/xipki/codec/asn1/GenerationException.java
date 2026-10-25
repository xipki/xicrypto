// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

/**
 * @author Lijun Liao (xipki)
 */
public class GenerationException extends OperatorException {

  public GenerationException(String message) {
    super(message);
  }

  public GenerationException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public GenerationException(String message, Throwable cause) {
    super(message, cause);
  }

}
