// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.util.Arrays;

/**
 * BIT STRING
 * @author Lijun Liao (xipki)
 */
public class Asn1BitString extends Asn1Primitive {

  private final int unusedBits;

  private final byte[] octets;

  public static Asn1BitString fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1BitString) Asn1Util.readAsn1Object(Asn1Tags.BIT_STRING, encoded);
  }

  public Asn1BitString(byte[] octets) {
    this.octets = Args.notNull(octets, "octets");
    this.unusedBits = 0;
  }

  public Asn1BitString(byte[] octets, int unusedBits) {
    this.octets = Args.notNull(octets, "octets");
    this.unusedBits = Args.range(unusedBits, "unusedBits", 0, 7);
  }

  /**
   * @param flagBits - the flag bits.
   */
  public Asn1BitString(int[] flagBits) {
    int maxInt = -1;
    for (int flagBit : flagBits) {
      maxInt = Math.max(maxInt, flagBit);
    }

    if (maxInt == -1) {
      this.octets = new byte[0];
      this.unusedBits = 0;
    } else {
      this.unusedBits = 7 - maxInt % 8;
      int numBytes = 1 + maxInt / 8;
      this.octets = new byte[numBytes];
      for (int flagBit : flagBits) {
        int byteIndex = flagBit / 8;
        int bitIndex  = flagBit % 8;
        int v = 0xFF & octets[byteIndex];
        v |= (1 << (7 - bitIndex));
        octets[byteIndex] = (byte) v;
      }
    }
  }

  public int getNumOfBits() {
    return 8 * octets.length - unusedBits;
  }

  int getOctetsLength() {
    return octets.length;
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.BIT_STRING;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.BIT_STRING;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return 1 + octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }

  public byte[] getAlignedOctets() {
    if (unusedBits != 0) {
      throw new IllegalStateException("unusedBits != 0: " + unusedBits);
    }
    return octets;
  }

  public int getUnusedBits() {
    return unusedBits;
  }

  /**
   * Convert the bit string to booleans.
   * @return the corresponding booleans, with true if the bit is set, false otherwise.
   */
  public boolean[] toBooleans() {
    int num = getNumOfBits();
    boolean[] r = new boolean[num];
    for (int i = 0; i < num; i++) {
      r[i] = isBitSet(i);
    }

    return r;
  }

  // TODO: check the correctness
  public boolean isBitSet(int bitIndex) {
    int maxBitIndex = 8 * octets.length - unusedBits - 1;
    if (bitIndex > maxBitIndex) {
      return false;
    }

    int byteIndex = bitIndex / 8;
    int bitIndex0 = bitIndex % 8;
    int v = octets[byteIndex];
    int mask = 1 << (7 - bitIndex0);
    return (v & mask) == mask;
  }

  /**
   *  Returns whether all valid bit indexes in b is set in this bit string.
   * @param b the target bit flags
   * @return true if all valid bit indexes of b is also set in this bit string,
   *         false otherwise.
   */
  public boolean containsAllSetBits(Asn1BitString b) {
    int bNumBits = b.getNumOfBits();
    for (int i = bNumBits - 1; i >= 0; i--) {
      if (b.isBitSet(i)) {
        if (!isBitSet(i)) {
          return false;
        }
      }
    }
    return true;
  }

  @Override
  public int hashCode() {
    return unusedBits * 31 + Arrays.hashCode(octets);
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1BitString)) {
      return false;
    }

    Asn1BitString b = (Asn1BitString) obj;
    return unusedBits == b.unusedBits && Arrays.equals(octets, b.octets);
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder();
    toString(buf, 0);
    return buf.toString();
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    if (unusedBits == 0) {
      ToStringUtil.toString(octets, buf, indentLevel);
    } else {
      ToStringUtil.appendIndent(buf, indentLevel,
          "unusedBits=" + unusedBits + "\n");
      ToStringUtil.toString("octets", octets, buf, indentLevel);
    }
    return buf;
  }

}
