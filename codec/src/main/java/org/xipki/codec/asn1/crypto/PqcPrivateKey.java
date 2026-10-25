// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1.crypto;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.Asn1TaggedObject;
import org.xipki.codec.asn1.Asn1Util;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

/**
 * RFC 9881:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::= BEGIN
 *
 * ML-DSA-44-PrivateKey ::= CHOICE {
 *   seed [0] OCTET STRING (SIZE (32)),
 *   expandedKey OCTET STRING (SIZE (2560)),
 *   both SEQUENCE {
 *       seed OCTET STRING (SIZE (32)),
 *       expandedKey OCTET STRING (SIZE (2560))
 *       }
 *   }
 *
 * ML-DSA-65-PrivateKey ::= CHOICE {
 *   seed [0] OCTET STRING (SIZE (32)),
 *   expandedKey OCTET STRING (SIZE (4032)),
 *   both SEQUENCE {
 *       seed OCTET STRING (SIZE (32)),
 *       expandedKey OCTET STRING (SIZE (4032))
 *       }
 *   }
 *
 * ML-DSA-87-PrivateKey ::= CHOICE {
 *   seed [0] OCTET STRING (SIZE (32)),
 *   expandedKey OCTET STRING (SIZE (4896)),
 *   both SEQUENCE {
 *       seed OCTET STRING (SIZE (32)),
 *       expandedKey OCTET STRING (SIZE (4896))
 *       }
 *   }
 * </pre>
 *
 * RFC 9935:
 * <pre>
 * DEFINITIONS IMPLICIT TAGS ::= BEGIN
 *
 *       ML-KEM-512-PrivateKey ::= CHOICE {
 *        seed [0] OCTET STRING (SIZE (64)),
 *        expandedKey OCTET STRING (SIZE (1632)),
 *        both SEQUENCE {
 *          seed OCTET STRING (SIZE (64)),
 *          expandedKey OCTET STRING (SIZE (1632))
 *          }
 *        }
 *
 *      ML-KEM-768-PrivateKey ::= CHOICE {
 *        seed [0] OCTET STRING (SIZE (64)),
 *        expandedKey OCTET STRING (SIZE (2400)),
 *        both SEQUENCE {
 *          seed OCTET STRING (SIZE (64)),
 *          expandedKey OCTET STRING (SIZE (2400))
 *          }
 *        }
 *
 *      ML-KEM-1024-PrivateKey ::= CHOICE {
 *        seed [0] OCTET STRING (SIZE (64)),
 *        expandedKey OCTET STRING (SIZE (3168)),
 *        both SEQUENCE {
 *          seed OCTET STRING (SIZE (64)),
 *          expandedKey OCTET STRING (SIZE (3168))
 *          }
 *        }
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class PqcPrivateKey extends Asn1Encodable {

  private final Asn1OctetString seed;

  private final Asn1OctetString expandedKey;

  protected boolean isSeedLengthValid(int seedLength) {
    return true;
  }

  protected boolean isExpandedKeyLengthValid(int expandedKeyLength) {
    return true;
  }

  protected PqcPrivateKey(byte[] seed, byte[] expandedKey) {
    this(Asn1Util.toOctetString(seed), Asn1Util.toOctetString(expandedKey));
  }

  protected PqcPrivateKey(
      Asn1OctetString seed, Asn1OctetString expandedKey) {
    if (seed == null && expandedKey == null) {
      throw new IllegalArgumentException("at least one of seed and expandedKey must be non-null");
    }

    this.seed = seed;
    this.expandedKey = expandedKey;

    checkFields();
  }

  private void checkFields() {
    if (seed != null) {
      int len = seed.getOctetsLength();
      if (!isSeedLengthValid(len)) {
        throw new IllegalArgumentException("invalid seed length " + len);
      }
    }

    if (expandedKey != null) {
      int len = expandedKey.getOctetsLength();
      if (!isExpandedKeyLengthValid(len)) {
        throw new IllegalArgumentException("invalid expandedKey length " + len);
      }
    }
  }

  public static PqcPrivateKey fromEncoded(byte[] encoded) throws CodecException {
    return fromAsn1(Asn1Util.readAsn1Object(encoded));
  }

  public static PqcPrivateKey fromAsn1(Asn1Primitive asn1) throws CodecException {
    return new PqcPrivateKey(asn1);
  }

  protected PqcPrivateKey(Asn1Primitive asn1) throws CodecException {
    Args.notNull(asn1, "asn1");
    if (asn1 instanceof Asn1TaggedObject) {
      if (asn1.getTagNo() != 0) {
        throw new CodecException("unknown tag " + asn1.getTagNo());
      }

      this.seed = ((Asn1TaggedObject) asn1).getImplicitOctetStringBase();
      this.expandedKey = null;
    } else if (asn1 instanceof Asn1OctetString) {
      this.seed = null;
      this.expandedKey = (Asn1OctetString) asn1;
    } else if (asn1 instanceof Asn1Sequence) {
      Asn1Sequence seq = (Asn1Sequence) asn1;
      Args.sequenceSizeEquals(seq, "asn1", 2);
      this.seed = seq.getOctetStringAt(0);
      this.expandedKey = seq.getOctetStringAt(1);
    } else {
      throw new CodecException("unknown ASN.1 class " + asn1.getClass().getName());
    }

    checkFields();
  }

  @Override
  public boolean isChoice() {
    return true;
  }

  public Asn1OctetString getSeed() {
    return seed;
  }

  public Asn1OctetString getExpandedKey() {
    return expandedKey;
  }

  public byte[] seed() {
    return Asn1Util.fromAsn1(seed);
  }

  public byte[] expandedKey() {
    return Asn1Util.fromAsn1(expandedKey);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    if (seed != null) {
      if (expandedKey != null) {
        return new Asn1Sequence(seed, expandedKey);
      } else {
        return Asn1TaggedObject.newImplicit(0, seed);
      }
    } else {
      return expandedKey;
    }
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    // the private key material is not printed.
    if (seed != null) {
      ToStringUtil.appendSecret(buf, indentLevel, "seed", seed.getOctetsLength());
    }

    if (expandedKey != null) {
      ToStringUtil.appendSecret(buf, indentLevel, "expandedKey", expandedKey.getOctetsLength());
    }

    return deleteLastNewLine(buf);
  }
}
