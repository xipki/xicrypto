// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.exception;

/**
 * @author Lijun Liao (xipki)
 */
public class DuplicationException extends CodecException {

  public DuplicationException(String message) {
    super(message);
  }

  public DuplicationException(Throwable cause) {
    super(cause);
  }

  public DuplicationException(String message, Throwable cause) {
    super(message, cause);
  }
}
