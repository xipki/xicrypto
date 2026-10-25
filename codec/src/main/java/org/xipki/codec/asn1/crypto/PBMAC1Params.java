// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * RFC 8018
 *
 * <pre>
 * PBMAC1-params ::= SEQUENCE {
 *     keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
 *     messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class PBMAC1Params extends Asn1Encodable {

  private final AlgorithmIdentifier func;
  private final AlgorithmIdentifier scheme;

  public PBMAC1Params(AlgorithmIdentifier keyDevFunc, AlgorithmIdentifier encScheme) {
    this.func = Args.notNull(keyDevFunc, "keyDevFunc");
    this.scheme = Args.notNull(encScheme, "encScheme");
  }

  public static PBMAC1Params fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    AlgorithmIdentifier func = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(0));
    AlgorithmIdentifier scheme = AlgorithmIdentifier.fromAsn1(seq.getSequenceAt(1));
    return new PBMAC1Params(func, scheme);
  }

  public AlgorithmIdentifier getKeyDerivationFunc() {
    return func;
  }

  public AlgorithmIdentifier getMessageAuthScheme() {
    return scheme;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(func, scheme);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    func.toStringWithLineSep(buf, indentLevel, "func", true);
    scheme.toStringWithLineSep(buf, indentLevel, "scheme", true);

    return deleteLastNewLine(buf);
  }

}
