// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.util.List;

/**
 * <pre>
 * xxx ::= SEQUENCE SIZE(min..MAX) OF INTEGER
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class IntegerSeq extends AbstractSeq<Asn1Integer> {

  public IntegerSeq(int min, int... entries) {
    super(min, Integer.MAX_VALUE, toIntegers(entries));
  }

  public IntegerSeq(int min, long... entries) {
    super(min, Integer.MAX_VALUE, toIntegers(entries));
  }

  public IntegerSeq(int min, BigInteger... entries) {
    super(min, Integer.MAX_VALUE, toIntegers(entries));
  }

  public IntegerSeq(int min, Asn1Integer... entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public IntegerSeq(int min, List<Asn1Integer> entries) {
    super(min, Integer.MAX_VALUE, entries);
  }

  public IntegerSeq(int min, Asn1Sequence seq) throws CodecException {
    super(min, Integer.MAX_VALUE, seq);
  }

  public static IntegerSeq ofBigIntegers(int min, List<BigInteger> numbers) {
    Args.noNullElements(numbers, "numbers");
    Asn1Integer[] values = new Asn1Integer[numbers.size()];
    for (int i = 0; i < values.length; i++) {
      values[i] = new Asn1Integer(numbers.get(i));
    }
    return new IntegerSeq(min, values);
  }

  @Override
  protected Asn1Integer newType(AbstractAsn1Collection coll, int index) throws CodecException {
    return coll.getIntegerAt(index);
  }

  public static IntegerSeq fromAsn1(int min, Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeMin(seq, "seq", min);
    return new IntegerSeq(min, toIntegers(seq));
  }

  protected static Asn1Integer[] toIntegersI(List<Integer> entries) {
    if (entries == null) {
      return null;
    }

    Asn1Integer[] r = new Asn1Integer[entries.size()];
    for (int i = 0; i < entries.size(); i++) {
      r[i] = new Asn1Integer(entries.get(i));
    }

    return r;
  }

  protected static Asn1Integer[] toIntegers(int... entries) {
    if (entries == null) {
      return null;
    }

    Asn1Integer[] r = new Asn1Integer[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1Integer(entries[i]);
    }

    return r;
  }

  protected static Asn1Integer[] toIntegersL(List<Long> entries) {
    if (entries == null) {
      return null;
    }

    Asn1Integer[] r = new Asn1Integer[entries.size()];
    for (int i = 0; i < entries.size(); i++) {
      r[i] = new Asn1Integer(entries.get(i));
    }

    return r;
  }

  protected static Asn1Integer[] toIntegers(long... entries) {
    if (entries == null) {
      return null;
    }

    Asn1Integer[] r = new Asn1Integer[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1Integer(entries[i]);
    }

    return r;
  }

  protected static Asn1Integer[] toIntegers(List<BigInteger> entries) {
    if (entries == null) {
      return null;
    }

    Asn1Integer[] r = new Asn1Integer[entries.size()];
    for (int i = 0; i < entries.size(); i++) {
      r[i] = new Asn1Integer(entries.get(i));
    }

    return r;
  }

  protected static Asn1Integer[] toIntegers(BigInteger... entries) {
    if (entries == null) {
      return null;
    }

    Args.noNullElements(entries, "entries");
    Asn1Integer[] r = new Asn1Integer[entries.length];
    for (int i = 0; i < entries.length; i++) {
      r[i] = new Asn1Integer(entries[i]);
    }

    return r;
  }

  static Asn1Integer[] toIntegers(AbstractAsn1Collection seq) throws CodecException {
    int size = seq.size();
    Asn1Integer[] r = new Asn1Integer[size];
    for (int i = 0; i < size; i++) {
      r[i] = seq.getIntegerAt(i);
    }
    return r;
  }

}
