// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.util;

import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 * Map whose {@link #entrySet()}, {@link #keySet()} and {@link #values()} return the
 * elements in the order of addition. Re-putting an existing key does not change its
 * position. Removing a key costs O(n). Null keys are not allowed.
 *
 * @author Lijun Liao (xipki)
 */
public class InsertionOrderedMap<K, V> extends AbstractMap<K, V> {

  private final Map<K, V> map = new HashMap<>();

  private final List<K> keys = new ArrayList<>();

  private final Set<Map.Entry<K, V>> entrySet = new EntrySet();

  public InsertionOrderedMap() {
  }

  public InsertionOrderedMap(Map<? extends K, ? extends V> m) {
    putAll(m);
  }

  @Override
  public int size() {
    return map.size();
  }

  @Override
  public boolean containsKey(Object key) {
    return map.containsKey(key);
  }

  @Override
  public boolean containsValue(Object value) {
    return map.containsValue(value);
  }

  @Override
  public V get(Object key) {
    return map.get(key);
  }

  @Override
  public V put(K key, V value) {
    Args.notNull(key, "key");
    if (!map.containsKey(key)) {
      keys.add(key);
    }
    return map.put(key, value);
  }

  @Override
  public V remove(Object key) {
    if (!map.containsKey(key)) {
      return null;
    }
    keys.remove(key);
    return map.remove(key);
  }

  @Override
  public void clear() {
    map.clear();
    keys.clear();
  }

  @Override
  public Set<Map.Entry<K, V>> entrySet() {
    return entrySet;
  }

  private final class EntrySet extends AbstractSet<Map.Entry<K, V>> {

    @Override
    public int size() {
      return map.size();
    }

    @Override
    public void clear() {
      InsertionOrderedMap.this.clear();
    }

    @Override
    public Iterator<Map.Entry<K, V>> iterator() {
      return new Iterator<>() {

        private int next;

        private boolean canRemove;

        @Override
        public boolean hasNext() {
          return next < keys.size();
        }

        @Override
        public Map.Entry<K, V> next() {
          if (!hasNext()) {
            throw new NoSuchElementException();
          }
          canRemove = true;
          return new Node(keys.get(next++));
        }

        @Override
        public void remove() {
          if (!canRemove) {
            throw new IllegalStateException();
          }
          canRemove = false;
          map.remove(keys.remove(--next));
        }
      };
    }
  }

  private final class Node extends SimpleEntry<K, V> {

    Node(K key) {
      super(key, map.get(key));
    }

    @Override
    public V setValue(V value) {
      map.put(getKey(), value);
      return super.setValue(value);
    }
  }

}
