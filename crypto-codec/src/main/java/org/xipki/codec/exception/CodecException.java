// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.codec.exception;

/**
 * Codec Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class CodecException extends Exception {

  public CodecException(String message) {
    super(message);
  }

  public CodecException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public CodecException(String message, Throwable cause) {
    super(message, cause);
  }

  public static CodecException seqWithUnexpectedElements() {
    return new CodecException("sequence contains unexpected elements");
  }

}
