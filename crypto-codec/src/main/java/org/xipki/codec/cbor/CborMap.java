// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.cbor;

import org.xipki.codec.Hex;
import org.xipki.codec.exception.CodecException;

import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.RandomAccess;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * An unmodifiable CBOR map whose keys are sorted in the deterministic order of RFC 8949,
 * Section 4.2.1: by the bytewise lexicographic order of their deterministic encodings.
 * Keys are compared by their encodings, so byte string keys are compared by content.
 * <p>
 * Values are kept as given; use {@link #deepSorted(Object)} to convert a generic value with all
 * its nested maps.
 *
 * @author Lijun Liao (xipki)
 */
public final class CborMap extends AbstractMap<Object, Object>
    implements SortedMap<Object, Object> {

  /** Compares keys by their deterministic CBOR encoding. */
  public static final Comparator<Object> KEY_ORDER =
      (a, b) -> Arrays.compareUnsigned(encodeKey(a), encodeKey(b));

  public static final CborMap EMPTY = new CborMap(new TreeMap<>(Arrays::compareUnsigned), true);

  /** Encoded key to entry. */
  private final TreeMap<byte[], Map.Entry<Object, Object>> entries;

  /** Whether all keys and values, also nested ones, are in the form of deepSorted(). */
  private final boolean deep;

  private final Set<Map.Entry<Object, Object>> entrySet = new AbstractSet<>() {

    @Override
    public Iterator<Map.Entry<Object, Object>> iterator() {
      Iterator<Map.Entry<Object, Object>> it = entries.values().iterator();
      return new Iterator<>() {
        @Override
        public boolean hasNext() {
          return it.hasNext();
        }

        @Override
        public Map.Entry<Object, Object> next() {
          return it.next();
        }
      };
    }

    @Override
    public int size() {
      return entries.size();
    }

  };

  private CborMap(TreeMap<byte[], Map.Entry<Object, Object>> entries, boolean deep) {
    this.entries = entries;
    this.deep = deep;
  }

  /**
   * An unmodifiable list whose elements, also nested ones, are in the form of deepSorted().
   */
  private static final class DeepList extends AbstractList<Object> implements RandomAccess {

    private final Object[] items;

    private DeepList(Object[] items) {
      this.items = items;
    }

    @Override
    public Object get(int index) {
      return items[index];
    }

    @Override
    public int size() {
      return items.length;
    }

  }

  /**
   * Collects the entries of a CBOR map in the deterministic order. Duplicate keys, i.e. keys
   * with the same encoding, are rejected.
   */
  public static final class Builder {

    private TreeMap<byte[], Map.Entry<Object, Object>> entries =
        new TreeMap<>(Arrays::compareUnsigned);

    /**
     * @throws CodecException if the key cannot be encoded, or is already present.
     */
    public Builder put(Object key, Object value) throws CodecException {
      byte[] encodedKey = encode(key);
      if (entries.putIfAbsent(encodedKey, new SimpleImmutableEntry<>(key, value)) != null) {
        throw new CodecException("duplicate map key " + toDiagnostic(key));
      }
      return this;
    }

    public CborMap build() {
      return build(false);
    }

    /**
     * For keys and values that are all in the form of deepSorted(), as those returned by
     * {@link CborDecoder#readNext()}.
     */
    CborMap buildDeep() {
      return build(true);
    }

    private CborMap build(boolean deep) {
      CborMap map = entries.isEmpty() ? EMPTY : new CborMap(entries, deep);
      entries = new TreeMap<>(Arrays::compareUnsigned);
      return map;
    }

  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Copies a map. Nested values are kept as given, see {@link #deepSorted(Object)}.
   *
   * @throws CodecException if a key cannot be encoded, or two keys have the same encoding.
   */
  public static CborMap of(Map<?, ?> map) throws CodecException {
    if (map instanceof CborMap) {
      return (CborMap) map;
    }
    Builder b = builder();
    for (Map.Entry<?, ?> e : map.entrySet()) {
      b.put(e.getKey(), e.getValue());
    }
    return b.build();
  }

  /**
   * Returns a copy of a generic CBOR value, as returned by {@link CborDecoder#readNext()}, in
   * which every map, also nested ones and those in keys or tagged values, is a {@link CborMap},
   * and every list or array is an unmodifiable list. Other values are returned as they are.
   *
   * @throws CodecException if a map key cannot be encoded, or two keys of a map have the same
   *         encoding.
   */
  public static Object deepSorted(Object value) throws CodecException {
    if ((value instanceof CborMap && ((CborMap) value).deep) || value instanceof DeepList) {
      return value;
    } else if (value instanceof Map) {
      Builder b = builder();
      for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
        b.put(deepSorted(e.getKey()), deepSorted(e.getValue()));
      }
      return b.buildDeep();
    } else if (value instanceof Collection || value instanceof Object[]) {
      Collection<?> c = (value instanceof Object[])
          ? Arrays.asList((Object[]) value) : (Collection<?>) value;
      List<Object> list = new ArrayList<>(c.size());
      for (Object m : c) {
        list.add(deepSorted(m));
      }
      return new DeepList(list.toArray());
    } else if (value instanceof CborTaggedObject) {
      CborTaggedObject t = (CborTaggedObject) value;
      Object v = deepSorted(t.value());
      return (v == t.value()) ? t : new CborTaggedObject(t.tag(), v);
    } else {
      return value;
    }
  }

  /**
   * Returns a one-line text form of a generic CBOR value in the style of the diagnostic
   * notation of RFC 8949, Section 8: e.g. {@code {1: h'0a0b', "x": [true, null]}}.
   */
  public static String toDiagnostic(Object value) {
    StringBuilder sb = new StringBuilder();
    appendDiagnostic(sb, value);
    return sb.toString();
  }

  private static void appendDiagnostic(StringBuilder sb, Object value) {
    if (value == null) {
      sb.append("null");
    } else if (value instanceof byte[]) {
      sb.append("h'").append(Hex.encode((byte[]) value)).append('\'');
    } else if (value instanceof String) {
      sb.append('"').append(((String) value).replace("\\", "\\\\").replace("\"", "\\\""))
          .append('"');
    } else if (value instanceof Map) {
      sb.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
        sb.append(first ? "" : ", ");
        first = false;
        appendDiagnostic(sb, e.getKey());
        sb.append(": ");
        appendDiagnostic(sb, e.getValue());
      }
      sb.append('}');
    } else if (value instanceof Collection || value instanceof Object[]) {
      Collection<?> c = (value instanceof Object[])
          ? Arrays.asList((Object[]) value) : (Collection<?>) value;
      sb.append('[');
      boolean first = true;
      for (Object m : c) {
        sb.append(first ? "" : ", ");
        first = false;
        appendDiagnostic(sb, m);
      }
      sb.append(']');
    } else if (value instanceof CborTaggedObject) {
      CborTaggedObject t = (CborTaggedObject) value;
      sb.append(t.tag()).append('(');
      appendDiagnostic(sb, t.value());
      sb.append(')');
    } else {
      sb.append(value);
    }
  }

  private static byte[] encode(Object key) throws CodecException {
    ByteArrayCborEncoder enc = new ByteArrayCborEncoder();
    enc.writeAnyObject(deepSorted(key));
    return enc.toByteArray();
  }

  private static byte[] encodeKey(Object key) {
    try {
      return encode(key);
    } catch (CodecException e) {
      throw new ClassCastException("not a CBOR map key: " + e.getMessage());
    }
  }

  /** The encoded key, or null if the object cannot be a CBOR map key. */
  private static byte[] encodeOrNull(Object key) {
    try {
      return encode(key);
    } catch (CodecException | RuntimeException e) {
      return null;
    }
  }

  /**
   * For elements that are all in the form of deepSorted(), as those returned by
   * {@link CborDecoder#readNext()}.
   */
  static List<Object> deepList(List<Object> elements) {
    return new DeepList(elements.toArray());
  }

  private CborMap sub(SortedMap<byte[], Map.Entry<Object, Object>> part) {
    return part.isEmpty() ? EMPTY : new CborMap(new TreeMap<>(part), deep);
  }

  @Override
  public Set<Map.Entry<Object, Object>> entrySet() {
    return entrySet;
  }

  @Override
  public int size() {
    return entries.size();
  }

  @Override
  public boolean containsKey(Object key) {
    byte[] encoded = encodeOrNull(key);
    return encoded != null && entries.containsKey(encoded);
  }

  @Override
  public Object get(Object key) {
    byte[] encoded = encodeOrNull(key);
    Map.Entry<Object, Object> e = (encoded == null) ? null : entries.get(encoded);
    return (e == null) ? null : e.getValue();
  }

  /**
   * Always throws: this map is immutable. Overridden because {@link AbstractMap#remove(Object)}
   * matches keys with {@code equals} and silently returns {@code null} if the key class differs
   * (e.g. {@code Integer} vs. {@code Long}) instead of throwing.
   */
  @Override
  public Object remove(Object key) {
    throw new UnsupportedOperationException("CborMap is immutable");
  }

  @Override
  public Comparator<? super Object> comparator() {
    return KEY_ORDER;
  }

  @Override
  public SortedMap<Object, Object> subMap(Object fromKey, Object toKey) {
    return sub(entries.subMap(encodeKey(fromKey), encodeKey(toKey)));
  }

  @Override
  public SortedMap<Object, Object> headMap(Object toKey) {
    return sub(entries.headMap(encodeKey(toKey)));
  }

  @Override
  public SortedMap<Object, Object> tailMap(Object fromKey) {
    return sub(entries.tailMap(encodeKey(fromKey)));
  }

  @Override
  public Object firstKey() {
    if (entries.isEmpty()) {
      throw new NoSuchElementException();
    }
    return entries.firstEntry().getValue().getKey();
  }

  @Override
  public Object lastKey() {
    if (entries.isEmpty()) {
      throw new NoSuchElementException();
    }
    return entries.lastEntry().getValue().getKey();
  }

  @Override
  public String toString() {
    return toDiagnostic(this);
  }

}
