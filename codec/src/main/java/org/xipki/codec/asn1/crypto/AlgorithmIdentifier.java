// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.*;
import org.xipki.codec.asn1.*;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * <pre>
 *  AlgorithmIdentifier ::= SEQUENCE {
 *      algorithm   OBJECT IDENTIFIER,
 *      parameters  ANY DEFINED BY algorithm OPTIONAL }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class AlgorithmIdentifier extends Asn1Encodable {

  public static class Seq1 extends AbstractSeq1<AlgorithmIdentifier> {

    public Seq1(AlgorithmIdentifier... entries) {
      super(entries);
    }

    public Seq1(List<AlgorithmIdentifier> entries) {
      super(entries);
    }

    protected Seq1(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq1 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq1(seq);
    }

    @Override
    protected AlgorithmIdentifier newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AlgorithmIdentifier.fromAsn1(coll.getSequenceAt(index));
    }
  }

  public static class Seq0 extends AbstractSeq0<AlgorithmIdentifier> {

    public Seq0(AlgorithmIdentifier... entries) {
      super(entries);
    }

    public Seq0(List<AlgorithmIdentifier> entries) {
      super(entries);
    }

    protected Seq0(Asn1Sequence seq) throws CodecException {
      super(seq);
    }

    public static Seq0 fromAsn1(Asn1Sequence seq) throws CodecException {
      return new Seq0(seq);
    }

    @Override
    protected AlgorithmIdentifier newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AlgorithmIdentifier.fromAsn1(coll.getSequenceAt(index));
    }
  }

  public static class Set1 extends AbstractSet<AlgorithmIdentifier> {

    public Set1(AlgorithmIdentifier... entries) {
      super(0, Integer.MAX_VALUE, entries);
    }

    public Set1(List<AlgorithmIdentifier> entries) {
      super(0, Integer.MAX_VALUE, entries);
    }

    protected Set1(Asn1Set set) throws CodecException {
      super(0, Integer.MAX_VALUE, set);
    }

    public static Set1 fromAsn1(Asn1Set set) throws CodecException {
      return new Set1(set);
    }

    @Override
    protected AlgorithmIdentifier newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AlgorithmIdentifier.fromAsn1(coll.getSequenceAt(index));
    }
  }

  public static class Set0 extends AbstractSet<AlgorithmIdentifier> {

    public Set0(AlgorithmIdentifier... entries) {
      super(0, Integer.MAX_VALUE, entries);
    }

    public Set0(Collection<AlgorithmIdentifier> entries) {
      super(0, Integer.MAX_VALUE, entries.toArray(new AlgorithmIdentifier[0]));
    }

    protected Set0(Asn1Set set) throws CodecException {
      super(0, Integer.MAX_VALUE, set);
    }

    public static Set0 fromAsn1(Asn1Set set) throws CodecException {
      return new Set0(set);
    }

    @Override
    protected AlgorithmIdentifier newType(AbstractAsn1Collection coll, int index)
        throws CodecException {
      return AlgorithmIdentifier.fromAsn1(coll.getSequenceAt(index));
    }
  }

  private final Asn1Oid algorithm;
  private final Asn1Primitive parameters;

  public static AlgorithmIdentifier fromSequenceElement(Asn1Sequence seq, int index)
      throws CodecException {
    return AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(index));
  }

  public AlgorithmIdentifier(Asn1Oid algorithm) {
    this(algorithm, null);
  }

  public AlgorithmIdentifier(Asn1Oid algorithm, Asn1Primitive parameters) {
    this.algorithm = Args.notNull(algorithm, "algorithm");
    this.parameters = parameters;
  }

  public static AlgorithmIdentifier build(Asn1Oid algorithm) {
    return new AlgorithmIdentifier(algorithm, null);
  }

  public static AlgorithmIdentifier ofNullParams(Asn1Oid algorithm) {
    return new AlgorithmIdentifier(algorithm, Asn1Null.INSTANCE);
  }

  public static AlgorithmIdentifier build(Asn1Oid algorithm, Asn1Encodable parameters) {
    return new AlgorithmIdentifier(algorithm,
        (parameters == null) ? null : parameters.toAsn1Primitive());
  }

  public static AlgorithmIdentifier fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static AlgorithmIdentifier fromAsn1(Asn1Sequence seq) throws CodecException {
    int size = Args.sequenceSizeRange(seq, "seq", 1, 2);
    Asn1Oid algorithm = seq.getOidAt(0);
    Asn1Primitive parameters = (size == 2) ? seq.getObjectAt(1) : null;
    return new AlgorithmIdentifier(algorithm, parameters);
  }

  public Asn1Oid getAlgorithm()
  {
      return algorithm;
  }

  public Asn1Primitive getParameters()
  {
      return parameters;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return Asn1Sequence.buildIgnoreNull(algorithm, parameters);
  }

  @Override
  public int hashCode() {
    return (parameters == null) ? algorithm.hashCode()
        : parameters.hashCode() * 31 + algorithm.hashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof AlgorithmIdentifier)) {
      return false;
    }

    AlgorithmIdentifier b = (AlgorithmIdentifier) obj;
    return algorithm.equals(b.algorithm) && Objects.equals(parameters, b.parameters);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    algorithm.toStringNoLineSep(buf, indentLevel, "algorithm", true);
    if (parameters != null) {
      parameters.toStringWithLineSep(buf, indentLevel, "parameters", true);
    }
    return deleteLastNewLine(buf);
  }

  public boolean isEquivalent(AlgorithmIdentifier other) {
    if (other == null) {
      return false;
    }

    if (!algorithm.equals(other.algorithm)) {
      return false;
    }

    Asn1Primitive aParams = Asn1Null.INSTANCE.equals(parameters) ? null : parameters;
    Asn1Primitive bParams = Asn1Null.INSTANCE.equals(other.parameters) ? null : other.parameters;
    return Objects.equals(aParams, bParams);
  }

}
