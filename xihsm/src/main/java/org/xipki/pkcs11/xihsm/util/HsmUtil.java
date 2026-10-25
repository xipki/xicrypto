// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.util;

import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.type.CkVersion;
import org.xipki.pkcs11.xihsm.crypt.XiMechanism;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * Hsm Util.
 *
 * @author Lijun Liao (xipki)
 */
public class HsmUtil {

  private static final SecureRandom rnd = new SecureRandom();

  public static long[] listToLongs(List<Long> list) {
    long[] ret = new long[list.size()];
    int i = 0;
    for (long l : list) {
      ret[i++] = l;
    }
    return ret;
  }

  public static byte[] randomBytes(int size) {
    byte[] bytes = new byte[size];
    rnd.nextBytes(bytes);
    return bytes;
  }

  public static CkVersion buildVersion(int major, int minor) {
    return new CkVersion((byte) major, (byte) minor);
  }

  public static long[] concatenate(long[] list, long... newElements) {
    long[] newList = Arrays.copyOf(list, list.length + newElements.length);
    System.arraycopy(newElements, 0, newList, list.length, newElements.length);
    return newList;
  }

  public static void assertNullParameter(XiMechanism mechanism) throws HsmException {
    if (mechanism.getParameter() != null) {
      throw new HsmException(PKCS11T.CKR_MECHANISM_PARAM_INVALID,
          "Mechanism.parameters is not NULL");
    }
  }

  public static byte[] getOctetStringValue(String name, byte[] derOctetString) throws HsmException {
    try {
      return Asn1OctetString.fromEncoded(derOctetString).getOctets();
    } catch (CodecException e) {
      throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
          name + " is not a DER-encoded OCTET STRING: " + Hex.encode(derOctetString));
    }
  }

  public static boolean contains(long[] array, long value) {
    for (long v : array) {
      if (v == value) {
        return true;
      }
    }
    return false;
  }

}
