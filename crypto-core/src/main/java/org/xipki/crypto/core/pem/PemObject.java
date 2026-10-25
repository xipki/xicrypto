// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.core.pem;

import org.xipki.codec.util.Args;

import java.util.Collections;
import java.util.List;

/**
 * A generic PEM object - type, header properties, and byte content.
 *
 * @author Lijun Liao (xipki)
 */
public class PemObject {

  private static final List<PemHeader> EMPTY_LIST = List.of();

  private final String type;
  private final List<PemHeader> headers;
  private final byte[] content;

  /**
   * Generic constructor for object without headers.
   *
   * @param type pem object type.
   * @param content the binary content of the object.
   */
  public PemObject(String type, byte[] content) {
    this(type, EMPTY_LIST, content);
  }

  /**
   * Generic constructor for object with headers.
   *
   * @param type pem object type.
   * @param headers a list of PemHeader objects.
   * @param content the binary content of the object.
   */
  public PemObject(String type, List<PemHeader> headers, byte[] content) {
    this.type = Args.notNull(type, "type");
    this.headers = Collections.unmodifiableList(headers);
    this.content = Args.notNull(content, "content");
  }

  public String getType() {
    return type;
  }

  public List<PemHeader> getHeaders() {
    return headers;
  }

  public byte[] getContent() {
    return content;
  }

}
