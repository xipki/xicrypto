// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.io.IOException;

/**
 * Cbor Encodable interface.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class CborEncodable {

  public abstract void encode(CborEncoder encoder) throws CodecException;

  public abstract StringBuilder toString(StringBuilder buf, int indentLevel);

  public byte[] getEncoded() throws CodecException {
    try (ByteArrayCborEncoder encoder = new ByteArrayCborEncoder()){
      encode(encoder);
      return encoder.toByteArray();
    } catch (IOException e) {
      throw new CodecException("IO error: " + e.getMessage());
    }
  }

  protected String getTitle() {
    return getClass().getSimpleName();
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    return toStringWithLineSep(buf, 0, getTitle()).toString();
  }

  public StringBuilder toStringWithLineSep(StringBuilder buf, int indentLevel, String title) {
    return toStringWithLineSep(buf, indentLevel, title, false);
  }

  public StringBuilder toStringWithLineSep(
      StringBuilder buf, int indentLevel, String title, boolean withTrailingNewLine) {
    if (title == null || title.isEmpty()) {
      toString(buf, indentLevel);
    } else {
      ToStringUtil.appendIndent(buf, indentLevel, title + ":\n");
      toString(buf, indentLevel + 1);
    }

    if (withTrailingNewLine) {
      buf.append("\n");
    }
    return buf;
  }

  public StringBuilder toStringNoLineSep(StringBuilder buf, int indentLevel, String title) {
    return toStringNoLineSep(buf, indentLevel, title, false);
  }

  public StringBuilder toStringNoLineSep(
      StringBuilder buf, int indentLevel, String title, boolean withTrailingNewLine) {
    if (title == null || title.isEmpty()) {
      toString(buf, indentLevel);
    } else {
      ToStringUtil.appendIndent(buf, indentLevel, title + ": ");
      toString(buf, 0);
    }

    if (withTrailingNewLine) {
      buf.append("\n");
    }
    return buf;
  }

  protected static StringBuilder deleteLastNewLine(StringBuilder buf) {
    char c = buf.charAt(buf.length() - 1);
    if (c == '\n') {
      buf.deleteCharAt(buf.length() - 1);
    }
    return buf;
  }

}
