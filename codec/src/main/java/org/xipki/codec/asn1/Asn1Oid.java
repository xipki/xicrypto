// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.asn1;

import org.xipki.codec.asn1.oid.OIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.ToStringUtil;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * OBJECT IDENTIFIER
 *
 * @author Lijun Liao (xipki)
 */
public class Asn1Oid extends Asn1Primitive {

  public interface OidNameResolver {

    /**
     * Resolve the name for the OID.
     * @param oid the OID.
     * @return the name for the OID. Null is allowed.
     */
    String engineGetName(Asn1Oid oid);

    /**
     * Resolve the name for the OID. Null or blank result is not allowed.
     * @param oid the OID.
     * @return the name for the OID. If no name can be resolved,
     *         returns the dotted-representation of this OID.
     */
    default String getNonBlankName(Asn1Oid oid) {
      String name = engineGetName(oid);
      return name == null || name.isEmpty() ? oid.getId() : name;
    }
  }

  /**
   * Maximal length of the encoded OID (content octets). It protects against the CPU and memory
   * exhaustion caused by huge OIDs in the malicious input, see CVE-2025-8885 for BouncyCastle.
   */
  public static final int MAX_ENCODED_LENGTH = 4096;

  /**
   * Maximal length of the OID in dotted representation.
   */
  public static final int MAX_STRING_LENGTH = 16385;

  private static OidNameResolver oidNameResolver = OIDs.OID_NAME_RESOLVER;

  private final byte[] octets;

  private final String id;

  public static void setOidNameResolver(OidNameResolver oidNameResolver) {
    Asn1Oid.oidNameResolver = oidNameResolver != null ? oidNameResolver : OIDs.OID_NAME_RESOLVER;
  }

  public static Asn1Oid fromEncoded(byte[] encoded) throws CodecException {
    return (Asn1Oid) Asn1Util.readAsn1Object(Asn1Tags.OBJECT_IDENTIFIER, encoded);
  }

  public Asn1Oid(String oid) {
    this.id = checkStringLength(Args.notBlank(oid, "oid"));
    this.octets = checkEncodedLength(encodeRawOid(oid));
  }

  public Asn1Oid(byte[] octets) {
    this.octets = checkEncodedLength(Args.notEmpty(octets, "octets"));
    this.id = decodeRawOid(octets, 0);
  }

  public Asn1Oid branch(String branch) {
    return new Asn1Oid(branch.startsWith(".") ? id + branch : id + "." + branch);
  }

  public boolean on(Asn1Oid parentOid) {
    return id.length() > parentOid.id.length() && id.startsWith(parentOid.id + ".");
  }

  @Override
  public PrimitiveType type() {
    return PrimitiveType.OID;
  }

  @Override
  public boolean isConstructed() {
    return false;
  }

  @Override
  public int getTagNo() {
    return Asn1Tags.OBJECT_IDENTIFIER;
  }

  @Override
  public int getEncodedLength(Asn1Encoding encoding) {
    return octets.length;
  }

  public byte[] getOctets() {
    return octets;
  }

  public String getId() {
    return id;
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(octets);
  }

  @Override
  protected boolean doEquals(Asn1Primitive obj) {
    if (!(obj instanceof Asn1Oid)) {
      return false;
    }

    return Arrays.equals(octets, ((Asn1Oid) obj).octets);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    String name = oidNameResolver.getNonBlankName(this);
    return ToStringUtil.appendIndent(buf,indentLevel, name);
  }

  static String checkStringLength(String oid) {
    if (oid.length() > MAX_STRING_LENGTH) {
      throw new IllegalArgumentException("OID string too long: " + oid.length() + " > "
          + MAX_STRING_LENGTH);
    }
    return oid;
  }

  static byte[] checkEncodedLength(byte[] octets) {
    if (octets.length > MAX_ENCODED_LENGTH) {
      throw new IllegalArgumentException("encoded OID too long: " + octets.length + " > "
          + MAX_ENCODED_LENGTH);
    }
    return octets;
  }

  private static byte[] encodeRawOid( String oid) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(10);
    String[] nodes = oid.split("\\.");

    if (nodes.length < 2) {
      throw new IllegalArgumentException("invalid oid " + oid);
    }

    // first two nodes
    int node0 = Integer.parseInt(nodes[0]);
    BigInteger node1 = parseNode(oid, nodes[1]);
    boolean valid = ((node0 == 0 || node0 == 1) && node1.compareTo(BigInteger.valueOf(40)) < 0)
        || node0 == 2;
    if (!valid) {
      throw new IllegalArgumentException("invalid oid " + oid);
    }

    encodeOidNode(out, BigInteger.valueOf(node0 * 40L).add(node1));

    for (int i = 2; i < nodes.length; i++) {
      encodeOidNode(out, parseNode(oid, nodes[i]));
    }

    return out.toByteArray();
  }

  private static BigInteger parseNode(String oid, String node) {
    // the arcs are unbounded, e.g. the UUID-based OIDs 2.25.{UUID as integer} (RFC 4122)
    if (node.isEmpty() || node.length() > 1 && node.charAt(0) == '0') {
      throw new IllegalArgumentException("invalid oid " + oid);
    }

    for (int i = 0; i < node.length(); i++) {
      char c = node.charAt(i);
      if (c < '0' || c > '9') {
        throw new IllegalArgumentException("invalid oid " + oid);
      }
    }
    return new BigInteger(node);
  }

  private static void encodeOidNode(ByteArrayOutputStream out, BigInteger nodeValue) {
    if (nodeValue.bitLength() < 31) {
      encodeOidNode(out, nodeValue.intValue());
      return;
    }

    int numBytes = (nodeValue.bitLength() + 6) / 7;
    for (int j = numBytes - 1; j >= 0; j--) {
      int k = 0x7F & nodeValue.shiftRight(7 * j).intValue();
      if (j != 0) {
        k |= 0x80;
      }
      out.write(k);
    }
  }

  static void encodeOidNode(ByteArrayOutputStream out, int nodeValue) {
    if (nodeValue < 128) {
      out.write(nodeValue);
    } else {
      int bitLen = BigInteger.valueOf(nodeValue).bitLength();
      // bitLen=8, numBytes=2, shiftBits = 1
      int numBytes = (bitLen + 6) / 7;
      int shiftBits = bitLen - (numBytes - 1) * 7;
      for (int j = 0; j < numBytes; j++) {
        int k = 0x7F & (nodeValue >> (bitLen - shiftBits - 7 * j));
        if (j != numBytes - 1) {
          k |= 0x80;
        }
        out.write(k);
      }
    }
  }

  private static String decodeRawOid(byte[] encoded, int offset) {
    final int len = encoded.length;
    if ((encoded[len - 1] & 0x80) != 0) {
      throw new IllegalArgumentException("invalid OID");
    }

    StringBuilder sb = new StringBuilder(len + 5);

    boolean start = true;
    while (offset < len) {
      if (!start) {
        sb.append(".");
      }
      offset = readNode(sb, encoded, offset, start);
      start = false;
    }

    if (offset != len) {
      throw new IllegalArgumentException("encoded too long");
    }

    return sb.toString();
  }

  /*
   * returns the new offset.
   */
  static int readNode(StringBuilder sb, byte[] values, int off, boolean start) {
    // use long, and BigInteger if the value does not fit in long.
    long nodeValue = 0;
    BigInteger bigNodeValue = null;
    while (true) {
      if (off >= values.length) {
        throw new IllegalArgumentException("invalid OID: truncated");
      }

      int v = 0xff & values[off++];
      boolean hasFurther = (v & 0x80) != 0;
      if (bigNodeValue == null && nodeValue > (Long.MAX_VALUE >> 7)) {
        bigNodeValue = BigInteger.valueOf(nodeValue);
      }

      if (bigNodeValue == null) {
        nodeValue = (nodeValue << 7) + (v & 0x7F);
      } else {
        bigNodeValue = bigNodeValue.shiftLeft(7).add(BigInteger.valueOf(v & 0x7F));
      }

      if (!hasFurther) {
        break;
      }
    }

    if (start) {
      if (bigNodeValue != null) {
        sb.append("2.").append(bigNodeValue.subtract(BigInteger.valueOf(80)));
      } else if (nodeValue < 40) {
        sb.append("0.").append(nodeValue);
      } else if (nodeValue < 80) {
        sb.append("1.").append(nodeValue - 40);
      } else {
        sb.append("2.").append(nodeValue - 80);
      }
    } else {
      sb.append(bigNodeValue != null ? bigNodeValue.toString() : Long.toString(nodeValue));
    }

    return off;
  }

}
