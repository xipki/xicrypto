// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * ASN.1 Encodable interface.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class Asn1Encodable {

  public abstract Asn1Primitive toAsn1Primitive();

  public boolean isChoice() {
    return false;
  }

  protected String getTitle() {
    return getClass().getSimpleName();
  }

  public void encodeTo(Asn1Encoder encoder) throws CodecException {
    encoder.encode(toAsn1Primitive());
  }

  public byte[] getEncoded() {
    return getEncoded(Asn1Encoding.DER);
  }

  public byte[] getEncoded(Asn1Encoding encoding) {
    Asn1Primitive prim = toAsn1Primitive();
    int len = prim.getEncodedLength(encoding);
    int size = Asn1Util.numBytesOfTag(prim.getTagNo()) + Asn1Util.numBytesOfLength(len) + len;
    byte[] buffer = new byte[size];
    Asn1Encoder.ByteArrayEncoder encoder = new Asn1Encoder.ByteArrayEncoder(encoding, buffer);
    try {
      prim.encodeTo(encoder);
    } catch (CodecException e) {
      throw new IllegalStateException("shall not happen, " +
          "error while encoding to ByteArrayAsn1Encoder", e);
    }
    return encoder.getWrittenBytes(false);
  }

  @Override
  public int hashCode() {
    return toAsn1Primitive().hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj == null || !getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }

    // Asn1Primitive overrides equals(), so this is never a primitive here and
    // toAsn1Primitive() returns another object: no recursion.
    Asn1Encodable b = (Asn1Encodable) obj;
    return toAsn1Primitive().equals(b.toAsn1Primitive());
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

  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return toAsn1Primitive().toString(buf, indentLevel);
  }

  protected static StringBuilder deleteLastNewLine(StringBuilder buf) {
    char c = buf.charAt(buf.length() - 1);
    if (c == '\n') {
      buf.deleteCharAt(buf.length() - 1);
    }
    return buf;
  }

}
