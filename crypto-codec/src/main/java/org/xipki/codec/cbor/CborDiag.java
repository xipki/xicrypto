// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.codec.cbor.CborConstants.*;

/**
 * Cbor Diag.
 *
 * @author Lijun Liao (xipki)
 */
public class CborDiag {

  protected static final class LongWithType {

    private final CborType type;

    private final long value;

    public LongWithType(CborType type, long value) {
      this.type = type;
      this.value = value;
    }

    @Override
    public String toString() {
      return getIntegerTypeDesc(type) + "(" + value + ")";
    }

    public CborType type() {
      return type;
    }

    public long value() {
      return value;
    }

  }

  protected static final class IntWithType {

    private final CborType type;

    private final int value;

    public IntWithType(CborType type, int value) {
      this.type = type;
      this.value = value;
    }

    @Override
    public String toString() {
      return getIntegerTypeDesc(type) + "(" + value + ")";
    }

    public CborType type() {
      return type;
    }

    public int value() {
      return value;
    }

  }

  protected static final class IndentOutStream {

    private final byte[] prefix;
    private final OutputStream out;

    private boolean addPrefix = true;

    private int lineOffset = 0;

    public IndentOutStream(OutputStream out, String prefix) {
      this.prefix = (prefix == null || prefix.isEmpty())
          ? null : prefix.getBytes(StandardCharsets.UTF_8);
      this.out = out;
    }

    protected void writeText(String text) throws CodecException {
      try {
        if (addPrefix) {
          if (prefix != null) {
            out.write(prefix);
            lineOffset += prefix.length;
          }
          addPrefix = false;
        }

        out.write(text.getBytes(StandardCharsets.UTF_8));
        lineOffset += text.length();
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    protected void writeNewLine() throws CodecException {
      try {
        out.write('\n');
        lineOffset = 0;
        addPrefix = true;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    public int lineOffset() {
      return lineOffset;
    }
  }

  private static class MyBuffer {
    private byte[] buffer;

    private int count;

    private MyBuffer() {
      buffer = new byte[256];
    }

    private void ensureCap(int minCap) {
      int curCap = buffer.length;
      int minDiff = minCap - curCap;
      if (minDiff > 0) {
        buffer = Arrays.copyOf(buffer, curCap + Math.max(curCap, minDiff));
      }
    }

    private void write(int b) {
      ensureCap(count + 1);
      buffer[count++] = (byte) b;
    }

    private void write(byte[] buf, int off, int len) {
      ensureCap(count + len);
      System.arraycopy(buf, off, buffer, count, len);
      count += len;
    }

    private void reset() {
      count = 0;
    }

    private void unread() {
      if (count < 1) throw new IllegalStateException("could not unread");
      count--;
    }

    private byte[] toByteArray() {
      return Arrays.copyOf(buffer, count);
    }
  }

  /**
   * My Input Stream.
   */
  public static class MyInputStream {

    private final PushbackInputStream is;
    private final MyBuffer buffer;
    private final AtomicInteger offset;
    private final int totalSize;

    private MyInputStream(PushbackInputStream is) {
      this.is = is;
      int available;
      try {
        available = is.available();
      } catch (IOException e) {
        available = 9999;
      }
      totalSize = available;
      buffer = new MyBuffer();
      offset = new AtomicInteger();
    }

    private int read() throws CodecException {
      try {
        int i = is.read();
        if (i != -1) {
          buffer.write(i);
          offset.getAndIncrement();
        }
        return i;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private int read(byte[] buf, int off, int len) throws CodecException {
      try {
        int num = is.read(buf, off, len);
        if (num != -1) {
          buffer.write(buf, off, num);
          offset.getAndAdd(num);
        }
        return num;
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private void unread(int val) throws CodecException {
      try {
        is.unread(val);
        buffer.unread();
        offset.getAndDecrement();
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private void unread(byte[] bytes) throws CodecException {
      try {
        is.unread(bytes);
        for (int i = 0; i < bytes.length; i++) {
          buffer.unread();
          offset.getAndDecrement();
        }
      } catch (IOException e) {
        throw new CodecException(e);
      }
    }

    private void resetBuffer() {
      buffer.reset();
    }

    private int getOffset() {
      return offset.get();
    }

    private byte[] getBufferedBytes() {
      return buffer.toByteArray();
    }

  }

  private static final BigInteger _2power64 = new BigInteger("10000000000000000", 16);

  private int numBytesPerLine = 32;

  private int numTextBytesPerLine = 18;

  private int numSpacesBeforeComment = 22;

  private int maxCharsPerLine = 80;

  private final MyInputStream is;

  private final boolean printEofOffset;

  protected final int offsetLen;

  private IndentOutStream out;

  private final Decoder decoder = new Decoder();

  /**
   * Creates a new {@link CborDiag} instance.
   *
   * @param encoded the CBOR-encoded data form.
   */
  public CborDiag(byte[] encoded) {
    this(encoded, true);
  }

  public CborDiag(byte[] encoded, boolean printEofOffset) {
    this(new ByteArrayInputStream(encoded), printEofOffset);
  }

  /**
   * Creates a new {@link CborDiag} instance.
   *
   * @param is the actual input stream to read the CBOR-encoded data from,
   *          cannot be <code>null</code>.
   */
  public CborDiag(InputStream is) {
    this(is, true);
  }

  public CborDiag(InputStream is, boolean printEofOffset) {
    Args.notNull(is, "is");
    if (is instanceof PushbackInputStream) {
      this.is = new MyInputStream((PushbackInputStream) is);
    } else {
      this.is = new MyInputStream(new PushbackInputStream(is, 10));
    }
    this.printEofOffset = printEofOffset;
    int size = this.is.totalSize;
    this.offsetLen = size < 10 ? 1
        : size < 100 ? 2
        : size < 1000 ? 3
        : size < 10000 ? 4
        : size < 100000 ? 5 : 6;
  }

  public CborDiag(MyInputStream is, int offsetLen, boolean printEofOffset) {
    Args.notNull(is, "is");
    this.is = is;
    this.printEofOffset = printEofOffset;
    this.offsetLen = offsetLen;
  }

  public int numSpacesBeforeComment() {
    return numSpacesBeforeComment;
  }

  public void setNumSpacesBeforeComment(int numSpacesBeforeComment) {
    this.numSpacesBeforeComment = numSpacesBeforeComment;
  }

  public void setMaxCharsPerLine(int maxCharsPerLine) {
    this.maxCharsPerLine = maxCharsPerLine;
  }

  public void setNumTextBytesPerLine(int numTextBytesPerLine) {
    this.numTextBytesPerLine = numTextBytesPerLine;
  }

  protected MyInputStream inputStream() {
    return is;
  }

  protected IndentOutStream outputStream() {
    return out;
  }

  public void setNumBytesPerLine(int numBytesPerLine) {
    this.numBytesPerLine = numBytesPerLine;
  }

  public void print() throws CodecException {
    print(System.out, null);
  }

  public void print(int indentLevel) throws CodecException {
    print(System.out, "  ".repeat(indentLevel));
  }

  public void print(String indentPrefix) throws CodecException {
    print(System.out, indentPrefix);
  }

  public void print(OutputStream out) throws CodecException {
    print(out, null);
  }

  public void print(OutputStream out, int indentLevel) throws CodecException {
    print(out, "  ".repeat(indentLevel));
  }

  public void print(OutputStream out, String indentPrefix) throws CodecException {
    print(new IndentOutStream(Args.notNull(out, "out"), indentPrefix));
  }

  protected void print0(IndentOutStream out) throws CodecException {
    this.out = Args.notNull(out, "out");
    print0();
  }

  protected void print(IndentOutStream out) throws CodecException {
    print0(out);

    ByteArrayOutputStream bout = new ByteArrayOutputStream(32);
    int read;
    byte[] buffer = new byte[2048];
    while ((read = is.read(buffer, 0, buffer.length)) != -1) {
      bout.write(buffer, 0, read);
    }

    int size = bout.size();
    if (printEofOffset || size > 0) {
      writeOffset(getOffset());
      writeNewLine();
    }

    if (size > 0) {
      writeLine("## " + size + " unused bytes:");
      byte[] remainingBytes = bout.toByteArray();
      writeBytesBlock(0, remainingBytes);
    }
  }

  protected void print0() throws CodecException {
    output(0, "");
  }

  protected void output(int level, String prefix) throws CodecException {
    CborType ctype = peekType();
    int addInfo = ctype.additionalInfo();

    switch (ctype.majorType()) {
      case NULL:
        read1Byte();
        writeLine(level, readResetBuffer(), concat(prefix, "<null>"));
        break;
      case TYPE_NEGATIVE_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            int v = readInt8();
            writeLine(level, readResetBuffer(), concat(prefix, "nint8(" + v + ")"));
            break;
          }
          case TWO_BYTES: {
            int v = readInt16();
            writeLine(level, readResetBuffer(), concat(prefix, "nint16(" + v + ")"));
            break;
          }
          case FOUR_BYTES: {
            long v = readInt32();
            writeLine(level, readResetBuffer(), concat(prefix, "=nint32(" + v + ")"));
            break;
          }
          case EIGHT_BYTES: {
            long v = readInt64();
            String vText;
            // v = -1 - n as 64-bit value: v >= 0 if n >= 2^63, then v - 2^64 is the value
            if (v < 0) {
              vText = Long.toString(v);
            } else {
              vText = BigInteger.valueOf(v).subtract(_2power64).toString();
            }

            writeLine(level, readResetBuffer(), concat(prefix, "nint64(" + vText + ")"));
            break;
          }
          default: {
            read1Byte();
            int v = -1 * (addInfo + 1);
            writeLine(level, readResetBuffer(), concat(prefix, "simple-nint(" + v + ")"));
          }
        }
        break;
      }
      case TYPE_UNSIGNED_INTEGER: {
        switch (addInfo) {
          case ONE_BYTE: {
            read1Byte();
            int v = readUInt8();
            writeLine(level, readResetBuffer(), concat(prefix, "uint8(" + v + ")"));
            break;
          }
          case TWO_BYTES: {
            read1Byte();
            int v = readUInt16();
            writeLine(level, readResetBuffer(), concat(prefix, "uint16(" + v + ")"));
            break;
          }
          case FOUR_BYTES: {
            read1Byte();
            long v = readUInt32();
            writeLine(level, readResetBuffer(), concat(prefix, "uint32(" + v + ")"));
            break;
          }
          case EIGHT_BYTES: {
            read1Byte();
            long v = readUInt64();
            String vText;
            if (v > 0) {
              vText = Long.toString(v);
            } else {
              vText = _2power64.add(BigInteger.valueOf(v)).toString();
            }

            writeLine(level, readResetBuffer(), concat(prefix, "uint64(" + vText + ")"));
            break;
          }
          default: {
            if (addInfo >= 0 && addInfo <= 23) {
              read1Byte();
              writeLine(level, readResetBuffer(), concat(prefix, "simple-uint(" + addInfo + ")"));
            }
          }
        }
        break;
      }
      case TYPE_TAG: {
        long t = readTag();
        writeLine(level, readResetBuffer(), concat(prefix, "tag(" + t + ")"));
        output(level + 1, "");
        break;
      }
      case TYPE_BYTE_STRING: {
        boolean isInfinite = addInfo == BREAK;
        if (isInfinite) {
          read1Byte();
          int blockIdx = 0;
          writeLine(level, readResetBuffer(), concat(prefix, "byte[*]"));
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printByteString(level + 1, "[" + (blockIdx++) + "]");
          }
        } else {
          printByteString(level, prefix);
        }
        break;
      }
      case TYPE_TEXT_STRING: {
        boolean isInfinite = addInfo == BREAK;
        if (isInfinite) {
          read1Byte();
          int blockIdx = 0;
          writeLine(level, readResetBuffer(), concat(prefix, "char[*]"));
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }
            printTextString(level + 1, "[" + (blockIdx++) + "]");
          }
        } else {
          printTextString(level, prefix);
        }
        break;
      }
      case TYPE_FLOAT_SIMPLE: {
        if (addInfo >=0 && addInfo <= 23) {
          read1Byte();
          switch (addInfo) {
            case NULL:
              writeLine(level, readResetBuffer(), concat(prefix, "<null>"));
              break;
            case FALSE:
              writeLine(level, readResetBuffer(), concat(prefix, "false"));
              break;
            case TRUE:
              writeLine(level, readResetBuffer(), concat(prefix, "true"));
              break;
            case UNDEFINED:
              writeLine(level, readResetBuffer(), concat(prefix, "<undefined>"));
              break;
            default:
              writeLine(level, readResetBuffer(), concat(prefix, "float/simple(" + addInfo + ")"));
          }
        } else if (addInfo == HALF_PRECISION_FLOAT) {
          double d = readHalfPrecisionFloat();
          writeLine(level, readResetBuffer(), concat(prefix, "half precision float(" + d + ")"));
        } else if (addInfo == SINGLE_PRECISION_FLOAT) {
          double d = readFloat();
          writeLine(level, readResetBuffer(), concat(prefix, "float(" + d + ")"));
        } else if (addInfo == DOUBLE_PRECISION_FLOAT) {
          double d = readDouble();
          writeLine(level, readResetBuffer(), concat(prefix, "double(" + d + ")"));
        } else if (addInfo == BREAK) {
          writeLine(level, readResetBuffer(), concat(prefix, "<break>"));
        } else {
          byte b = readSimpleValue();
          writeLine(level, readResetBuffer(), concat(prefix, "float/simple(" + (b & 0xFF) + ")"));
        }
        break;
      }
      case TYPE_ARRAY: {
        int len = readArrayLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), concat(prefix, "array[*]"));
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx++) + "]");
          }
        } else {
          writeLine(level, readResetBuffer(), concat(prefix, "array[" + len + "]"));
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "]");
          }
        }
        break;
      }
      case TYPE_MAP: {
        int len = readMapLength();
        if (len == -1) {
          writeLine(level, readResetBuffer(), concat(prefix, "map{*}"));
          int idx = 0;
          while (true) {
            if (skipBreak()) {
              writeLine(level + 1, readResetBuffer(), "<break>");
              break;
            }

            output(level + 1, "[" + (idx) + "].key  ");
            output(level + 1, "[" + (idx) + "].value");
            idx++;
          }
        } else {
          writeLine(level, readResetBuffer(), concat(prefix, "map(" + len + ")"));
          for (int i = 0; i < len; i++) {
            output(level + 1, "[" + i + "].key  ");
            output(level + 1, "[" + i + "].value");
          }
        }
        break;
      }
      default:
        throw new CodecException("unsupported cbor type " + ctype);
    }
  }

  protected LongWithType readLongWithType() throws CodecException {
    CborType type = peekType();
    long value = readLong();
    return new LongWithType(type, value);
  }

  protected IntWithType readIntWithType() throws CodecException {
    CborType type = peekType();
    int value = readInt();
    return new IntWithType(type, value);
  }

  protected static String getIntegerTypeDesc(CborType ctype) {
    int addInfo = ctype.additionalInfo();
    int majorType = ctype.majorType();
    if (majorType == TYPE_NEGATIVE_INTEGER) {
      switch (addInfo) {
        case ONE_BYTE:
          return "nint8";
        case TWO_BYTES:
          return "nint16";
        case FOUR_BYTES:
          return "nint32";
        case EIGHT_BYTES:
          return "nint64";
        default:
          return "simple-nint";
      }
    } else if (majorType ==TYPE_UNSIGNED_INTEGER) {
      switch (addInfo) {
        case ONE_BYTE:
          return "uint8";
        case TWO_BYTES:
          return "uint16";
        case FOUR_BYTES:
          return "uint32";
        case EIGHT_BYTES:
          return "uint64";
        default:
          return "simple-uint";
      }
    } else {
      throw new IllegalArgumentException(ctype + " is not expected type");
    }
  }

  protected byte[] readResetBuffer() {
    byte[] bytes = is.getBufferedBytes();
    is.resetBuffer();
    return bytes;
  }

  protected void writeLine(String text) throws CodecException {
    writeText(text);
    writeNewLine();
  }

  protected byte[] printByteStringObj(int level, String prefix) throws CodecException {
    CborType type = peekType();
    if (type.isNull()) {
      printNull(level, prefix);
      return null;
    } else {
      return printByteString(level, prefix);
    }
  }

  protected byte[] printByteString(int level, String prefix) throws CodecException {
    int len = readByteStringLength();
    writeLine(level, readResetBuffer(), concat(prefix, "byte[" + len + "]"));
    byte[] bytes = readExactBytes(len);
    if (bytes.length > 0) {
      writeBytesBlock(level + 1, bytes);
    }
    return bytes;
  }

  protected void printTextStringObj(int level, String prefix) throws CodecException {
    CborType type = peekType();
    if (type.isNull()) {
      printNull(level, prefix);
    } else {
      printTextString(level, prefix);
    }
  }

  protected void printTextString(int level, String prefix) throws CodecException {
    int len = (int) readTextStringLength();
    writeLine(level, readResetBuffer(), concat(prefix, "char[" + len + "]"));
    if (len == 0) {
      return;
    }

    byte[] bytes = readExactBytes(len);
    String text = new String(bytes, StandardCharsets.UTF_8);
    boolean sameLen = (len == text.length());

    int offBase = getOffset() - bytes.length;
    is.resetBuffer();

    String ind = "  ".repeat(level + 1);

    int x = maxCharsPerLine - 4 // offset with 4 chars
        - 2 // ": "
        - ind.length() - 5;
    int numPerLine = Math.min(x, numTextBytesPerLine * 3) / 3;

    int n = (len + numPerLine - 1) / numPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numPerLine, len - off);
      writeText(Hex.encodeUpper(bytes, off, numBytesInLine));

      if (sameLen) {
        String textPart = text.substring(off, off + numBytesInLine);
        int commentOff = Math.max(numPerLine, 2 * Math.min(numPerLine, len) + 1);

        int numSpaces = commentOff - 2 * numBytesInLine;
        writeText(" ".repeat(numSpaces) + "# \"" + textPart + "\"");
      } else {
        // it is difficult to split the bytes, so we print
        // all text at the first line
        if (i == 0) {
          int numSpaces = Math.max(1, numSpacesBeforeComment - numBytesInLine * 2);
          writeText(" ".repeat(numSpaces) + "# \"" + text + "\"");
        }
      }

      writeNewLine();
    }
  }

  protected byte[] readExactBytes(int len) throws CodecException {
    byte[] out = new byte[len];
    int read;

    int off = 0;
    while (off < len && (read = is.read(out, off, len - off)) != -1) {
      off += read;
    }

    if (off < len) {
      throw new CodecException("in reaches end, but still expected " + (len - off) + " bytes");
    }
    return out;
  }

  protected void writeBytesBlock(int level, byte[] data) throws CodecException {
    int offBase = getOffset() - data.length;
    is.resetBuffer();

    int len = data.length;
    String ind = "  ".repeat(level);

    int numPerLine = Math.min(numBytesPerLine, (maxCharsPerLine - 6 - ind.length()) / 2);

    int n = (len + numPerLine - 1) / numPerLine;

    int off = 0;
    for (int i = 0; i < n; i++, off += numPerLine) {
      writeOffset(offBase + off);
      writeText(ind);

      int numBytesInLine = Math.min(numPerLine, len - off);
      writeText(Hex.encodeUpper(data, off, numBytesInLine));
      if (i != n - 1) {
        writeNewLine();
      }
    }

    writeNewLine();
  }

  protected void writeLine(int level, byte[] data, String text) throws CodecException {
    writeLine(level, data, true, text);
  }

  protected void writeLine(int level, byte[] data, boolean firstByteIsTag, String text)
    throws CodecException {
    writeOffset(getOffset() - data.length);
    writeText("  ".repeat(level));

    int numSpaces = numSpacesBeforeComment;
    int len = data.length;
    if (len <= 1) {
      writeText(Hex.encodeUpper(data));
    } else {
      if (firstByteIsTag) {
        writeText(Hex.encodeUpper(data[0]));
        writeText(" ");
        writeText(Hex.encodeUpper(Arrays.copyOfRange(data, 1, len)));
        numSpaces--;
      } else {
        writeText(Hex.encodeUpper(data));
      }
    }

    numSpaces = Math.max(1, numSpaces - 2 * data.length);

    writeText(" ".repeat(numSpaces));
    int textLen = text.length();
    int lineOffset = out.lineOffset;

    if (lineOffset + 2 + textLen < maxCharsPerLine) {
      writeText("# " + text);
    } else {
      // split the comment to multiple lines
      String leading = "";
      if (text.startsWith("[")) {
        int idx = text.indexOf("]: ", 1);
        if (idx == -1) {
          idx = text.indexOf("]. ", 1);
        }

        if (idx != -1) {
          leading = text.substring(0, idx + 3);
          text = text.substring(idx + 3);
        }
      }

      int numPerLine = maxCharsPerLine - lineOffset - 2 - leading.length();
      List<String> splitTexts = splitText(text, numPerLine);
      boolean firstLine = true;
      for (String line0 : splitTexts) {
        if (firstLine) {
          firstLine = false;
          writeText("# " + leading + line0);
        } else {
          writeNewLine();
          writeText(" ".repeat(lineOffset) + "# " + " ".repeat(leading.length()) + line0);
        }
      }
    }

    writeNewLine();
  }

  private static List<String> splitText(String text, int numPerLine) {
    List<String> lines = splitTextBySpaces(text, numPerLine);
    boolean ok = true;
    for (String line : lines) {
      if (line.length() > numPerLine) {
        ok = false;
        break;
      }
    }

    if (ok) {
      return lines;
    }

    // we need to split the long lines
    List<String> ret =  new ArrayList<>(lines.size() + 1);
    for (int i = 0; i < lines.size(); i++) {
      String line = lines.get(i);
      int len = line.length();
      if (len <= numPerLine) {
        // short line
        ret.add(line);
      } else {
        // long line
        int numBlocks = (len + numPerLine - 1) / numPerLine;
        int start = 0;
        for (int j = 0; j < numBlocks - 1; j++) {
          ret.add(line.substring(start, start + numPerLine));
          start += numPerLine;
        }

        String lastBlock = line.substring(start);
        if (i < lines.size() - 1) {
          // try to merge the last block with next line
          String nextLine = lines.get(i + 1);
          if (lastBlock.length() + 1 + nextLine.length() < numPerLine) {
            ret.add(lastBlock + " " + nextLine);
            i++;
          } else {
            ret.add(lastBlock);
          }
        } else {
          ret.add(lastBlock);
        }
      }
    }

    return ret;
  }

  private static List<String> splitTextBySpaces(String text, int numPerLine) {
    StringTokenizer tokenizer = new StringTokenizer(text, " ");
    List<String> tokens = new LinkedList<>();
    while (tokenizer.hasMoreTokens()) {
      tokens.add(tokenizer.nextToken());
    }

    List<String> lines = new ArrayList<>();

    String line = "";
    for (String token : tokens) {
      if (line.isEmpty()) {
        line += token;
      } else if (line.length() + 1 + token.length() <= numPerLine) {
        line += " " + token;
      } else {
        lines.add(line);
        line = token;
      }

      if (line.length() >= numPerLine) {
        lines.add(line);
        line = "";
      }
    }

    if (!line.isEmpty()) {
      lines.add(line);
    }

    return lines;
  }

  protected int getOffset() {
    return is.getOffset();
  }

  protected void writeText(String text) throws CodecException {
    out.writeText(text);
  }

  protected void writeNewLine() throws CodecException {
    out.writeNewLine();
  }

  protected void writeOffset(int offset) throws CodecException {
    String s = Integer.toString(offset);
    if (s.length() < offsetLen) {
      s = " ".repeat(offsetLen - s.length()) + s;
    }
    writeText(s + ": ");
  }

  protected static void fail(String msg, Object... args) throws CodecException {
    throw new CodecException(String.format(msg, args));
  }

  /**
   * The CBOR decoder reading from the recording input stream.
   */
  private final class Decoder extends CborDecoder {

    @Override
    public CborType peekType() throws CodecException {
      int p = is.read();
      if (p < 0) {
        // EOF, nothing to peek at...
        throw new CodecException("reached stream end");
      }
      is.unread(p);
      return CborType.valueOf(p);
    }

    @Override
    public CborType[] peekTypes(int num) throws CodecException {
      byte[] bytes = readExactBytes(num);
      is.unread(bytes);
      CborType[] ret = new CborType[num];
      for (int i = 0; i < num; i++) {
        ret[i] = CborType.valueOf(0xFF & bytes[i]);
      }
      return ret;
    }

    @Override
    public int read1Byte() throws CodecException {
      return is.read();
    }

    @Override
    public int streamOffset() {
      return is.getOffset();
    }

    @Override
    public String readTextString() throws CodecException {
      if (skipNull()) {
        return null;
      }

      long len = readTextStringLength();
      if (len < 0 || len > Integer.MAX_VALUE) {
        fail("unsupported text string length %d", len);
      }
      return new String(readExactBytes((int) len), StandardCharsets.UTF_8);
    }

    @Override
    protected int readUInt8() throws CodecException {
      return is.read() & 0xff;
    }

    @Override
    protected int readUInt16() throws CodecException {
      byte[] buf = readExactBytes(2);
      return (buf[0] & 0xFF) << 8 | (buf[1] & 0xFF);
    }

    @Override
    protected long readUInt32() throws CodecException {
      byte[] buf = readExactBytes(4);
      return ((buf[0] & 0xFFL) << 24 | (buf[1] & 0xFF) << 16 |
          (buf[2] & 0xFF) << 8 | (buf[3] & 0xFF)) & 0xffffffffL;
    }

    @Override
    protected long readUInt64() throws CodecException {
      byte[] buf = readExactBytes(8);
      return (buf[0] & 0xFFL) << 56 | (buf[1] & 0xFFL) << 48 |
          (buf[2] & 0xFFL) << 40 | (buf[3] & 0xFFL) << 32 |
          (buf[4] & 0xFFL) << 24 | (buf[5] & 0xFFL) << 16 |
          (buf[6] & 0xFFL) << 8  | (buf[7] & 0xFFL);
    }

    @Override
    protected byte[] readExactly(int len) throws CodecException {
      return readExactBytes(len);
    }

    @Override
    protected boolean allowFull64BitUInt() {
      // the diagnostic prints the full range of the 64-bit integers.
      return true;
    }

  } // class Decoder

  protected CborType peekType() throws CodecException {
    return decoder.peekType();
  }

  protected CborType[] peekTypes(int num) throws CodecException {
    return decoder.peekTypes(num);
  }

  protected int read1Byte() throws CodecException {
    return decoder.read1Byte();
  }

  protected int readArrayLength() throws CodecException {
    return decoder.readArrayLength();
  }

  protected void readBreak() throws CodecException {
    decoder.readBreak();
  }

  protected int readByteStringLength() throws CodecException {
    long v = decoder.readByteStringLength();
    if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
      throw new CodecException("value is out of range of int32");
    }
    return (int) v;
  }

  protected double readDouble() throws CodecException {
    return decoder.readDouble();
  }

  protected float readFloat() throws CodecException {
    return decoder.readFloat();
  }

  protected double readHalfPrecisionFloat() throws CodecException {
    return decoder.readHalfPrecisionFloat();
  }

  protected int readMapLength() throws CodecException {
    return decoder.readMapLength();
  }

  protected byte readSimpleValue() throws CodecException {
    return decoder.readSimpleValue();
  }

  protected long readTag() throws CodecException {
    return decoder.readTag();
  }

  protected long readTextStringLength() throws CodecException {
    return decoder.readTextStringLength();
  }

  protected int readMajorType(int majorType) throws CodecException {
    return decoder.readMajorType(majorType);
  }

  protected void readMajorTypeExact(int majorType, int subtype) throws CodecException {
    decoder.readMajorTypeExact(majorType, subtype);
  }

  protected long readMajorTypeWithSize(int majorType) throws CodecException {
    return decoder.readMajorTypeWithSize(majorType);
  }

  protected long readUInt(int length, boolean breakAllowed) throws CodecException {
    return decoder.readUInt(length, breakAllowed);
  }

  protected long readUInt(int length, boolean breakAllowed, boolean allow64Bit)
      throws CodecException {
    return decoder.readUInt(length, breakAllowed, allow64Bit);
  }

  protected int readUInt16() throws CodecException {
    return decoder.readUInt16();
  }

  protected long readUInt32() throws CodecException {
    return decoder.readUInt32();
  }

  protected long readUInt64() throws CodecException {
    return decoder.readUInt64();
  }

  public void readNull() throws CodecException {
    decoder.readNull();
  }

  public void readUndefined() throws CodecException {
    decoder.readUndefined();
  }

  public boolean readBoolean() throws CodecException {
    return decoder.readBoolean();
  }

  public int readInt() throws CodecException {
    return decoder.readInt();
  }

  public long readLong() throws CodecException {
    return decoder.readLong();
  }

  protected int readUInt8() throws CodecException {
    return decoder.readUInt8();
  }

  protected int readInt8() throws CodecException {
    return decoder.readInt8();
  }

  protected int readInt16() throws CodecException {
    return decoder.readInt16();
  }

  protected long readInt32() throws CodecException {
    return decoder.readInt32();
  }

  protected long readInt64() throws CodecException {
    return decoder.readInt64();
  }

  protected byte[] readFully(int size) throws CodecException {
    return readExactBytes(size);
  }

  protected byte[] readFully(byte[] buf) throws CodecException {
    byte[] bytes = readExactBytes(buf.length);
    System.arraycopy(bytes, 0, buf, 0, bytes.length);
    return buf;
  }

  protected boolean skipBreak() throws CodecException {
    return decoder.skipBreak();
  }

  protected long expectIntegerType(int ib) throws CodecException {
    return decoder.expectIntegerType(ib);
  }

  protected long readUIntExact(int expectedLength, int length) throws CodecException {
    return decoder.readUIntExact(expectedLength, length);
  }

  protected long printTag(int level, String prefix) throws CodecException {
    long tag = readTag();

    String prefix1 = prefix + ": tag=" + tag;
    // 121-127: alternatives 0..6, 1+1 encoding
    if (tag >= 121 && tag <= 127) {
      writeLine(level, readResetBuffer(), prefix1 + ": alternative " + (tag - 121));
      // 1280-1400: alternatives 7..127, 1+2 encoding
    } else if (tag >= 1280 && tag <= 1400) {
      writeLine(level, readResetBuffer(), prefix1 + ": alternative " + (tag - 1280 + 7));
    } else {
      writeLine(level, readResetBuffer(), prefix1);
    }
    return tag;
  }

  protected String concat(String prefix, String text) {
    if (prefix == null || prefix.isEmpty()) {
      return text;
    }

    char last = prefix.charAt(prefix.length() - 1);
    if (last == '=' || last == ' ') {
      return prefix + text;
    } else {
      return prefix + "=" + text;
    }
  }

  protected int printAndReadEntryLen(
      int level, String fielName, int numPerEntry, String entryName) throws CodecException {
    int len = readArrayLength();
    if (len < 0 || (len % numPerEntry) != 0) {
      throw new CodecException(
          "#array of field " + fielName + " is not multiple of " + numPerEntry + ": " + len);
    }

    int entryLen = len / numPerEntry;
    String desc = concat(fielName,  "array[" + len + "], " + entryLen + " " + entryName);
    if (entryLen > 1) {
      desc += "s";
    }

    writeLine(level, readResetBuffer(), desc);
    return entryLen;
  }

  protected int printAndReadArrayLen(int level, String prefix) throws CodecException {
    int arrayLen = readArrayLength();
    writeLine(level, readResetBuffer(), concat(prefix, "array[" + arrayLen + "]"));
    return arrayLen;
  }

  protected long printLong(int level, String prefix) throws CodecException {
    long v = readLong();
    writeLine(level, readResetBuffer(), concat(prefix, Long.toString(v)));
    return v;
  }

  protected Long printLongObj(int level, String prefix) throws CodecException {
    CborType cborType = peekType();
    if (cborType.isNull()) {
      printNull(level, prefix);
      return null;
    } else {
      return printLong(level, prefix);
    }
  }

  protected void printNull(int level, String prefix) throws CodecException {
    readNull();
    writeLine(level, readResetBuffer(), concat(prefix, "<null>"));
  }

  protected void printNoContentLine(int level, String text) throws CodecException {
    writeLine(" ".repeat(offsetLen + 2 // ": ".length() = 2
        + 2 * level + numSpacesBeforeComment()) + "#---" + text + "---");
  }

}
