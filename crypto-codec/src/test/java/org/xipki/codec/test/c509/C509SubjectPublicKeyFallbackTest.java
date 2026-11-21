// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.c509;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.c509.C509BytesSubjectPublicKey;
import org.xipki.codec.c509.C509RawSubjectPublicKey;
import org.xipki.codec.c509.C509SubjectPublicKey;
import org.xipki.codec.c509.C509SubjectPublicKeyInfo;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.exception.CodecException;

import java.security.spec.InvalidKeySpecException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Public keys of unregistered algorithms: a byte string value gives a
 * C509BytesSubjectPublicKey, any other value a C509RawSubjectPublicKey.
 *
 * @author Lijun Liao (xipki)
 */
public class C509SubjectPublicKeyFallbackTest {

  /** 1000 is not registered. */
  private static final int UNREGISTERED = 1000;

  @Test
  public void unregisteredByteString() throws Exception {
    // 1000, h'0102'
    C509SubjectPublicKey key = C509SubjectPublicKey.parse(Hex.decode("1903e8420102"));
    Assert.assertTrue(key instanceof C509BytesSubjectPublicKey);
    Assert.assertEquals(UNREGISTERED, key.algorithm());
    Assert.assertFalse(key.toString().isEmpty());
  }

  @Test
  public void unregisteredMap() throws Exception {
    // 1000, {2: "b", 1: h'01'}: keys not sorted
    C509SubjectPublicKey key = C509SubjectPublicKey.parse(Hex.decode("1903e8a2026162014101"));
    Assert.assertTrue(key instanceof C509RawSubjectPublicKey);
    Assert.assertEquals(UNREGISTERED, key.algorithm());
    CborEncodedItem value = ((C509RawSubjectPublicKey) key).value();
    Assert.assertTrue(value.type().isMap());
    // original encoding kept
    Assert.assertEquals("a2026162014101", Hex.encode(value.getEncoded()));
    Assert.assertEquals("1903e8a2026162014101", Hex.encode(key.getEncoded()));
    Assert.assertTrue(key.toString().contains("{1: h'01', 2: \"b\"}"));

    // built from generic data: encoded deterministically
    Map<Object, Object> map = new LinkedHashMap<>();
    map.put(2, "b");
    map.put(1, new byte[] {1});
    C509RawSubjectPublicKey built = new C509RawSubjectPublicKey(UNREGISTERED, map);
    Assert.assertEquals("1903e8a2014101026162", Hex.encode(built.getEncoded()));
    Assert.assertNotEquals(key, built);

    C509SubjectPublicKey sorted = C509SubjectPublicKey.parse(Hex.decode("1903e8a2014101026162"));
    Assert.assertEquals(sorted, built);
    Assert.assertEquals(sorted.hashCode(), built.hashCode());
  }

  @Test
  public void unregisteredOtherTypes() throws Exception {
    for (Object value : new Object[] {List.of(1, "a"), 5, "text", true}) {
      C509RawSubjectPublicKey key = new C509RawSubjectPublicKey(UNREGISTERED, value);
      C509SubjectPublicKey copy = C509SubjectPublicKey.parse(key.getEncoded());
      Assert.assertEquals(key, copy);
    }
  }

  @Test
  public void inSubjectPublicKeyInfo() throws Exception {
    C509SubjectPublicKeyInfo info = new C509SubjectPublicKeyInfo(
        new C509RawSubjectPublicKey(UNREGISTERED, List.of(1, 2)));
    Assert.assertEquals(info, C509SubjectPublicKeyInfo.parse(info.getEncoded()));
  }

  @Test
  public void noX509OrJcaKey() {
    C509RawSubjectPublicKey key = new C509RawSubjectPublicKey(UNREGISTERED, List.of(1));
    Assert.assertThrows(UnsupportedOperationException.class, key::toX509SubjectPublicKey);
    Assert.assertThrows(InvalidKeySpecException.class, key::publicKey);
  }

  @Test
  public void registeredAlgorithmNeedsByteString() {
    // ed25519 (12), [1]: the value of a registered algorithm is not taken as raw data
    Assert.assertThrows(CodecException.class,
        () -> C509SubjectPublicKey.parse(Hex.decode("0c8101")));
    Assert.assertThrows(IllegalArgumentException.class,
        () -> new C509RawSubjectPublicKey(ConstPublicKeyAlgorithm.ed25519, List.of(1)));
  }

  @Test
  public void byteStringValueRejected() {
    Assert.assertThrows(IllegalArgumentException.class,
        () -> new C509RawSubjectPublicKey(UNREGISTERED, new byte[] {1}));
  }

}
