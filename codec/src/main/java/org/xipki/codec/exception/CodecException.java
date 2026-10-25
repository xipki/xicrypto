// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.codec.exception;

import java.io.IOException;

/**
 * Codec Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class CodecException extends Exception {

  public static final CodecException SEQ_WITH_UNEXPECTED_ELEMENTS =
      new CodecException("sequence contains unexpected elements");

  public CodecException(String message) {
    super(message);
  }

  public CodecException(Throwable cause) {
    super(cause.getMessage(), cause);
  }

  public CodecException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Codec IOException type.
   */
  public static final class CodecIOException extends CodecException {

    public CodecIOException(String message) {
      super(message);
    }

    public CodecIOException(String message, IOException cause) {
      super(message, cause);
    }

    public CodecIOException(IOException cause) {
      super(cause);
    }
  }

  /**
   * Duplicated Key Exception type.
   */
  public static final class DuplicatedKeyException extends CodecException {

    /**
     * Duplicated key.
     */
    private final String key;

    /**
     * @param key duplicated key.
     */
    public DuplicatedKeyException(final String key) {
      super("Duplicated key: '".concat(key) + "'");
      this.key = key;
    }

    public String key() {
      return key;
    }
  }

  /**
   * Unexpected Char Exception type.
   */
  public static final class UnexpectedCharException extends CodecException {

    /**
     * @param position  position of unexpected character.
     * @param character unexpected character value (zero based).
     */
    public UnexpectedCharException(final int position, final char character) {
      super("Unexpected character '" + character + "' at position " + position + ".");
    }

  }
}
