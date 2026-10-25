// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * <pre>
 * xxx ::= SEQUENCE / SET SIZE(min..max) OF T
 * </pre>
 * @author Lijun Liao (xipki)
 */
public abstract class AbstractCollection<T extends Asn1Encodable>
    extends Asn1Encodable implements Iterable<T> {

  private class MyIterator implements Iterator<T> {

    private final AtomicInteger position;

    public MyIterator() {
      this.position = new AtomicInteger(0);
    }

    @Override
    public boolean hasNext() {
      return position.get() < size;
    }

    @Override
    public T next() {
      int i = position.getAndIncrement();
      return i < size ? entries.get(i) : null;
    }
  }

  protected final List<T> entries;

  private final int size;

  protected final boolean isSet;

  @SafeVarargs
  protected AbstractCollection(boolean isSet, int min, int max, T... entries) {
    this.isSet = isSet;
    this.size = entries == null ? 0 : entries.length;
    Args.range(size, "entries.length", min, max);
    this.entries = Args.noNullElements2(entries, "entries");
  }

  protected AbstractCollection(boolean isSet, int min, int max, List<T> entries) {
    this.isSet = isSet;
    this.size = entries == null ? 0 : entries.size();
    Args.range(size, "entries.length", min, max);
    Args.noNullElements(entries, "entries");
    this.entries = entries == null ? new ArrayList<>() : new ArrayList<>(entries);
  }

  protected AbstractCollection(boolean isSet, int min, int max, AbstractAsn1Collection coll)
      throws CodecException {
    Args.notNull(coll, "coll");
    this.isSet = isSet;
    this.size = coll.size();
    Args.range(size, "coll.size", min, max);

    this.entries = new ArrayList<>(size);
    for (int i = 0; i != size; i++) {
      entries.add(newType(coll, i));
    }
  }

  protected abstract T newType(AbstractAsn1Collection seq, int index) throws CodecException;

  public List<T> getEntries() {
    return entries;
  }

  public int size() {
    return entries.size();
  }

  public boolean isEmpty() {
    return entries.isEmpty();
  }

  public T get(int index) {
    return entries.get(index);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return isSet ? new Asn1Set(entries) : new Asn1Sequence(entries);
  }

  @Override
  public Iterator<T> iterator() {
    return new MyIterator();
  }

  @Override
  public int hashCode() {
    return entries.hashCode() * 31 + (isSet ? 1: 0);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj == null || !getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }

    AbstractCollection b = (AbstractCollection) obj;
    return entries.equals(b.entries);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    return toString(buf, indentLevel, true);
  }

  @Override
  public StringBuilder toStringWithLineSep(StringBuilder buf, int indentLevel, String title) {
    return toStringWithLineSep(buf, indentLevel, title, false);
  }

  @Override
  public StringBuilder toStringWithLineSep(
      StringBuilder buf, int indentLevel, String title, boolean withTrailingNewLine) {
    if (title == null || title.isEmpty()) {
      toString(buf, indentLevel, false);
    } else {
      ToStringUtil.appendIndent(buf, indentLevel, title + ":\n");
      toString(buf, indentLevel + 1, false);
    }

    if (withTrailingNewLine) {
      buf.append("\n");
    }
    return buf;
  }

  public StringBuilder toString(StringBuilder buf, int indentLevel, boolean withBrackets) {
    int level = indentLevel;
    if (withBrackets) {
      ToStringUtil.appendIndent(buf, indentLevel, "[").append("\n");
      level++;
    }

    for (int i = 0; i < entries.size(); i++) {
      T m = entries.get(i);
      if (m instanceof AbstractCollection) {
        ((AbstractCollection<?>) m).toString(buf, level, false);
      } else {
        m.toString(buf, level);
      }

      if (i != entries.size() - 1) {
        buf.append(",\n");
      }
    }

    if (withBrackets) {
      buf.append("\n");
      ToStringUtil.appendIndent(buf, indentLevel, "]");
    }
    return buf;
  }

}
