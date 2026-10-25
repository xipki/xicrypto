// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.pem;

import org.xipki.codec.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.LinkedList;
import java.util.List;

/**
 * A generic PEM reader, based on the format outlined in RFC 1421
 *
 * @author Lijun Liao (xipki)
 */
public class PemReader extends BufferedReader {

  private static final String BEGIN = "-----BEGIN ";
  private static final String END = "-----END ";

  public PemReader(Reader reader) {
    super(reader);
  }

  /**
   * Read the next PEM object as a blob of raw data with header information.
   *
   * @return the next object in the stream, null if no objects left.
   * @throws IOException in case of a parse error.
   */
  public PemObject readPemObject() throws IOException {
    String line = readLine();

    while (line != null && !line.startsWith(BEGIN)) {
      line = readLine();
    }

    if (line != null) {
      line = line.substring(BEGIN.length()).trim();
      int index = line.indexOf('-');

      if (index > 0 && line.endsWith("-----") && (line.length() - index) == 5) {
        String type = line.substring(0, index);
        return loadObject(type);
      }
    }

    return null;
  }

  private PemObject loadObject(String type) throws IOException {
    String line;
    String endMarker = END + type + "-----";
    StringBuilder buf = new StringBuilder();
    List<PemHeader> headers = new LinkedList<>();

    while ((line = readLine()) != null) {
      int index = line.indexOf(':');
      if (index >= 0) {
        String hdr = line.substring(0, index);
        String value = line.substring(index + 1).trim();
        headers.add(new PemHeader(hdr, value));
        continue;
      }

      if (line.indexOf(endMarker) == 0) {
        break;
      }

      buf.append(line.trim());
    }

    if (line == null) {
      throw new IOException(endMarker + " not found");
    }

    return new PemObject(type, headers, Base64.decode(buf.toString()));
  }

}
