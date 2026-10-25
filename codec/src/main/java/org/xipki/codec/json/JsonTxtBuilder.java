// THIRDPARTY. https://github.com/lbownik/primitive-json

//------------------------------------------------------------------------------
//Copyright 2014 Lukasz Bownik, Yidong Fang, Chris Nokleberg, Dave Hughes
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//------------------------------------------------------------------------------
package org.xipki.codec.json;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.io.IOException;

/**
 * Json Txt Builder: pretty JSON text, each element of a list in its own line, and lines
 * longer than maxCharsPerLine are wrapped.
 *
 * @author Lijun Liao (xipki)
 */
public class JsonTxtBuilder extends JsonBuilder {

  private static class MyAppendable implements Appendable {

    private final int maxCharsPerLine;

    private final StringBuilder sb = new StringBuilder();

    private String line = "";

    private int lineNo = 0;

    MyAppendable(int maxCharsPerLine) {
      this.maxCharsPerLine = maxCharsPerLine;
    }

    @Override
    public Appendable append(CharSequence csq) throws IOException {
      return append(csq, 0, csq.length());
    }

    @Override
    public Appendable append(CharSequence csq, int start, int end) throws IOException {
      for (int i = start; i < end; i++) {
        append(csq.charAt(i));
      }
      return this;
    }

    private boolean manualLineBreak = false;

    @Override
    public Appendable append(char c) {
      if (c == '\n') {
        if (!line.isEmpty()) {
          sb.append(line);
          line = "";
        }

        if (!manualLineBreak) {
          lineNo++;
          sb.append(c);
        } else {
          manualLineBreak = false;
        }
      } else {
        line += c;
        manualLineBreak = false;
        if (line.length() >= maxCharsPerLine) {
          sb.append(line);
          lineNo++;
          sb.append("\n");
          line = "";
          manualLineBreak = true;
        }
      }
      return this;
    }

    public String doFinal() {
      if (!line.isEmpty()) {
        sb.append(line);
      }
      return sb.toString();
    }
  }

  private final int maxCharsPerLine;

  public JsonTxtBuilder(int maxCharsPerLine) {
    this(null, maxCharsPerLine);
  }

  public JsonTxtBuilder(String indent, int maxCharsPerLine) {
    super(true, indent, true);
    this.maxCharsPerLine = Args.min(maxCharsPerLine, "maxCharsPerLine", 40);
  }

  @Override
  public String doToJson(JsonMap root) {
    MyAppendable builder = new MyAppendable(maxCharsPerLine);
    try {
      writeMap(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.doFinal();
  }

  @Override
  public String doToJson(JsonList root) {
    MyAppendable builder = new MyAppendable(maxCharsPerLine);
    try {
      writeList(root, builder, 0);
    } catch (CodecException e) {
      throw new RuntimeException(e);
    }
    return builder.doFinal();
  }

  /**
   * Encode an ArrayList into JSON text and write it to out.
   *
   * @param value list.
   * @param out appendable object.
   * @throws CodecException if output error occurs.
   * @throws NullPointerException if value or out == null.
   */
  @Override
  protected void writeList(JsonList value, Appendable out, int level) throws CodecException {
    final int size = value.size();

    append(out, '[');
    if (size > 0) {
      append(out, "\n");
      for (int i = 0; i < size; ++i) {
        Object v = value.getAt(i);
        appendIndent(out, level + 1);
        writeValue(v, out, level + 1);
        if (i != size - 1) {
          append(out, ",\n");
        }
      }
    }

    append(out, '\n');
    appendIndent(out, level);
    append(out, ']');
  }

}
