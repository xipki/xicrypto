// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.openssl;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Builder of an OSSL_PARAM array (core.h). The secret values (octet strings and unsigned
 * integers marked as secret) are zeroized by {@link #clear(MemorySegment)}.
 *
 * @author Lijun Liao (xipki)
 */
final class OsslParams {

  /** struct ossl_param_st {key, data_type, data, data_size, return_size} of core.h. */
  static final MemoryLayout OSSL_PARAM = MemoryLayout.structLayout(
      ADDRESS.withName("key"), JAVA_INT.withName("data_type"),
      MemoryLayout.paddingLayout(4), ADDRESS.withName("data"),
      JAVA_LONG.withName("data_size"), JAVA_LONG.withName("return_size"));

  private static final int INTEGER = 1;

  private static final int UNSIGNED_INTEGER = 2;

  private static final int UTF8_STRING = 4;

  private static final int OCTET_STRING = 5;

  /** OSSL_PARAM_UNMODIFIED of params.h. */
  private static final long UNMODIFIED = -1L;

  private record Entry(String key, int type, byte[] data, boolean secret) {
  }

  private final List<Entry> entries = new ArrayList<>(4);

  OsslParams utf8(String key, String value) {
    entries.add(new Entry(key, UTF8_STRING, value.getBytes(StandardCharsets.UTF_8), false));
    return this;
  }

  OsslParams octets(String key, byte[] value) {
    entries.add(new Entry(key, OCTET_STRING, value, false));
    return this;
  }

  /** An octet string zeroized by {@link #clear(MemorySegment)}, e.g. a key or a seed. */
  OsslParams secretOctets(String key, byte[] value) {
    entries.add(new Entry(key, OCTET_STRING, value, true));
    return this;
  }

  OsslParams integer(String key, int value) {
    byte[] data = new byte[4];
    MemorySegment.ofArray(data).set(ValueLayout.JAVA_INT_UNALIGNED, 0, value);
    entries.add(new Entry(key, INTEGER, data, false));
    return this;
  }

  /** An unsigned big integer (native byte order), e.g. a component of an RSA key. */
  OsslParams bigInt(String key, BigInteger value, boolean secret) {
    if (value.signum() < 0) {
      throw new IllegalArgumentException(key + " must not be negative");
    }
    byte[] be = value.toByteArray();
    int off = (be.length > 1 && be[0] == 0) ? 1 : 0;
    byte[] data = new byte[be.length - off];
    for (int i = 0; i < data.length; i++) {
      data[i] = (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN)
          ? be[be.length - 1 - i] : be[off + i];
    }
    if (secret) {
      Arrays.fill(be, (byte) 0);
    }
    entries.add(new Entry(key, UNSIGNED_INTEGER, data, secret));
    return this;
  }

  boolean isEmpty() {
    return entries.isEmpty();
  }

  /**
   * Returns the OSSL_PARAM array in the arena, or {@link MemorySegment#NULL} if empty. The
   * Java copies of the secret values are zeroized.
   */
  MemorySegment build(Arena arena) {
    if (entries.isEmpty()) {
      return MemorySegment.NULL;
    }

    MemorySegment params = arena.allocate(OSSL_PARAM, entries.size() + 1);
    long size = OSSL_PARAM.byteSize();
    for (int i = 0; i < entries.size(); i++) {
      Entry e = entries.get(i);
      MemorySegment data = arena.allocate(Math.max(1, e.data.length) + 1);
      MemorySegment.copy(e.data, 0, data, JAVA_BYTE, 0, e.data.length);
      if (e.secret) {
        Arrays.fill(e.data, (byte) 0);
      }
      long off = i * size;
      params.set(ADDRESS, off, arena.allocateFrom(e.key, StandardCharsets.US_ASCII));
      params.set(JAVA_INT, off + 8, e.type);
      params.set(ADDRESS, off + 16, data);
      params.set(JAVA_LONG, off + 24, e.data.length);
      params.set(JAVA_LONG, off + 32, UNMODIFIED);
    }
    // the last element (end marker) is zero-filled by allocate()
    return params;
  }

  /**
   * Zeroizes the values of the OSSL_PARAM array built by {@link #build(Arena)}.
   */
  static void clear(MemorySegment params) {
    if (params.address() == 0) {
      return;
    }
    long size = OSSL_PARAM.byteSize();
    MemorySegment all = params.reinterpret(Long.MAX_VALUE);
    for (long off = 0; all.get(ADDRESS, off).address() != 0; off += size) {
      long len = all.get(JAVA_LONG, off + 24);
      all.get(ADDRESS, off + 16).reinterpret(len).fill((byte) 0);
    }
  }

}
