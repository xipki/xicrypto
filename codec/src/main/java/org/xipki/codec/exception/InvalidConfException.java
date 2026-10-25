// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.exception;

/**
 * Invalid Conf Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class InvalidConfException extends Exception {

  public InvalidConfException(String message) {
    super(message);
  }

  public InvalidConfException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public InvalidConfException(String message, Throwable cause) {
    super(message, cause);
  }

}
