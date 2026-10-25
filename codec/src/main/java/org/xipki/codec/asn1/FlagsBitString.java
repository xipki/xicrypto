// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.util.ToStringUtil;

import java.util.LinkedList;
import java.util.List;

/**
 * <pre>
 * * ::= BIT STRING {
 *   ...
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public abstract class FlagsBitString extends Asn1Encodable {

  protected final Asn1BitString flags;

  protected FlagsBitString(int... indexes) {
    this.flags = indexes == null ? new Asn1BitString(new int[0]) : new Asn1BitString(indexes);
  }

  protected FlagsBitString(List<? extends FlagsBitString> flags) {
    this((flags == null) ? null : flags.toArray(new FlagsBitString[0]));
  }

  protected FlagsBitString(FlagsBitString... flags) {
    if (flags == null || flags.length == 0) {
      this.flags = new Asn1BitString(new int[0]);
      return;
    }

    List<Integer> indexes = new LinkedList<>();
    for (FlagsBitString flagStr : flags) {
      int numBits = flagStr.flags.getNumOfBits();
      for (int i = 0; i < numBits; i++) {
        if (flagStr.flags.isBitSet(i)) {
          indexes.add(i);
        }
      }
    }

    int[] ints = new int[indexes.size()];
    for (int i = 0; i < ints.length; i++) {
      ints[i] = indexes.get(i);
    }

    this.flags = new Asn1BitString(ints);
  }

  protected FlagsBitString(Asn1BitString flags) {
    this.flags = flags;
  }

  public Asn1BitString getFlags() {
    return flags;
  }

  public boolean hasFlag(FlagsBitString flag) {
    return flags.containsAllSetBits(flag.flags);
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return flags;
  }

  public String getFlagName(int flagIndex) {
    List<String> names = getFlagNames();
    if (flagIndex < 0 || flagIndex >= names.size()) {
      return "flagIndex " + flagIndex;
    } else {
      return names.get(flagIndex);
    }
  }

  /**
   * Convert the bit string to booleans.
   * @return the corresponding booleans, with true if the bit is set, false otherwise.
   */
  public boolean[] toBooleans() {
    return flags.toBooleans();
  }

  protected abstract List<String> getFlagNames();

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    boolean[] bits = toBooleans();
    List<String> l = new LinkedList<>();
    for (int i = 0; i < bits.length; i++) {
      if (bits[i]) {
        l.add(getFlagName(i));
      }
    }

    return ToStringUtil.appendIndent(buf, indentLevel, l.toString());
  }
}
