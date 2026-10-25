// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.util;

import org.xipki.codec.Hex;
import org.xipki.codec.util.BigIntegers;

import java.math.BigInteger;

/**
 * Shared formatting helpers for human-readable dumps of C509 structures.
 *
 * @author Lijun Liao (xipki)
 */
public class ToStringUtil {

  public static final String INDENT_UNIT = "  ";

  private static final int HEX_BYTES_PER_LINE = 16;

  private ToStringUtil() {
  }

  public static StringBuilder appendIndent(StringBuilder buf, int indentLevel, String text) {
    buf.append(INDENT_UNIT.repeat(Math.max(0, indentLevel))).append(text);
    return buf;
  }

  public static StringBuilder appendHexOneLine(
      String name, StringBuilder buf, int indentLevel, byte[] bytes) {
    return appendHexOneLine(name, buf, indentLevel, bytes, true);
  }

  public static StringBuilder appendHexOneLine(
      String name, StringBuilder buf, int indentLevel, byte[] bytes, boolean addNewLine) {
    appendIndent(buf, indentLevel, name).append(": ");
    Hex.append(buf, bytes, Integer.MAX_VALUE, "");
    if (addNewLine) {
      buf.append("\n");
    }
    return buf;
  }

  public static StringBuilder appendHex(StringBuilder buf, int indentLevel, byte[] bytes) {
    return appendHex(buf, false, indentLevel, bytes);
  }

  public static StringBuilder appendHex(
      StringBuilder buf, boolean uppdercase, int indentLevel, byte[] bytes) {
    Hex.append(uppdercase, buf, bytes, HEX_BYTES_PER_LINE,
        INDENT_UNIT + INDENT_UNIT.repeat(Math.max(0, indentLevel - 1)));
    return buf;
  }

  public static StringBuilder appendHexWithPrefix(
      StringBuilder buf, int indentLevel, byte[] bytes, String prefix) {
    return appendHexWithPrefix(buf, false, indentLevel, bytes, prefix);
  }

  public static StringBuilder appendHexWithPrefix(
      StringBuilder buf, boolean uppdercase, int indentLevel, byte[] bytes, String prefix) {
    if (bytes == null) {
      appendIndent(buf, indentLevel, prefix + ": null\n");
    } else {
      appendIndent(buf, indentLevel, prefix + "\n");
      appendHex(buf, uppdercase, indentLevel + 1, bytes);
    }
    return buf;
  }

  public static StringBuilder appendBigInt(StringBuilder buf, int indentLevel, BigInteger bn) {
    byte[] serialNumberBytes = BigIntegers.asUnsignedByteArray(bn);
    appendHex(buf, indentLevel, serialNumberBytes);
    return buf;
  }

  /**
   * Appends the name and, in the next lines, the unsigned big-endian bytes of the number in hex,
   * followed by a new line.
   * @param buf the buffer.
   * @param indentLevel the indent level of the name.
   * @param name the name.
   * @param bn the number.
   * @return the buffer.
   */
  public static StringBuilder appendBigInt(
      StringBuilder buf, int indentLevel, String name, BigInteger bn) {
    appendIndent(buf, indentLevel, name + ":\n");
    return appendBigInt(buf, indentLevel + 1, bn).append("\n");
  }

  /**
   * Appends the name and the length of a secret value, e.g. of the private key, without the
   * value itself, followed by a new line.
   * @param buf the buffer.
   * @param indentLevel the indent level.
   * @param name the name.
   * @param length the length of the secret value in bytes.
   * @return the buffer.
   */
  public static StringBuilder appendSecret(
      StringBuilder buf, int indentLevel, String name, int length) {
    return appendIndent(buf, indentLevel, name + ": <" + length + " bytes, not printed>\n");
  }

  public static StringBuilder toString(byte[] value, StringBuilder buf, int indentLevel) {
    if (value != null && value.length > 0) {
      return ToStringUtil.appendHex(buf, indentLevel, value);
    } else {
      return ToStringUtil.appendIndent(buf, indentLevel, "<empty>");
    }
  }

  public static StringBuilder toString(
      String name, byte[] value, StringBuilder buf, int indentLevel) {
    if (value != null && value.length > 0) {
      ToStringUtil.appendIndent(buf, indentLevel, name + "\n");
      return ToStringUtil.appendHex(buf, indentLevel + 1, value);
    } else {
      return ToStringUtil.appendIndent(buf, indentLevel, name + ": <empty>\n");
    }
  }

}
