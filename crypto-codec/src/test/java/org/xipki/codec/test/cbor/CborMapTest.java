// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.cbor;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.ByteArrayCborDecoder;
import org.xipki.codec.cbor.ByteArrayCborEncoder;
import org.xipki.codec.cbor.CborMap;
import org.xipki.codec.cbor.CborTaggedObject;
import org.xipki.codec.exception.CodecException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CborMap: deterministic key order, duplicate keys, immutability and text form.
 *
 * @author Lijun Liao (xipki)
 */
public class CborMapTest {

  private static byte[] encode(Object value) throws CodecException {
    ByteArrayCborEncoder enc = new ByteArrayCborEncoder();
    enc.writeAnyObject(value);
    return enc.toByteArray();
  }

  private static Object decode(String hex) throws CodecException {
    try (ByteArrayCborDecoder in = new ByteArrayCborDecoder(Hex.decode(hex))) {
      return in.readNext();
    }
  }

  @Test
  public void keyOrder() throws Exception {
    // RFC 8949, Section 4.2.1: 10, 100, -1, "z", "aa", [100], [-1], false
    Map<Object, Object> map = new LinkedHashMap<>();
    map.put(false, 8);
    map.put(List.of(-1), 7);
    map.put(List.of(100), 6);
    map.put("aa", 5);
    map.put("z", 4);
    map.put(-1, 3);
    map.put(100, 2);
    map.put(10, 1);

    CborMap sorted = (CborMap) CborMap.deepSorted(map);
    Assert.assertEquals(List.of(10, 100, -1, "z", "aa", List.of(100), List.of(-1), false),
        new ArrayList<>(sorted.keySet()));
    Assert.assertEquals(10, sorted.firstKey());
    Assert.assertEquals(false, sorted.lastKey());
    Assert.assertEquals(2, sorted.headMap(-1).size());
  }

  @Test
  public void encodingIndependentOfInsertionOrder() throws Exception {
    Map<Object, Object> a = new LinkedHashMap<>();
    a.put("b", Map.of(2, "x", 1, "y"));
    a.put(1, new byte[] {1});
    Map<Object, Object> b = new LinkedHashMap<>();
    b.put(1, new byte[] {1});
    b.put("b", Map.of(1, "y", 2, "x"));

    byte[] encoded = encode(CborMap.deepSorted(a));
    Assert.assertArrayEquals(encoded, encode(CborMap.deepSorted(b)));
    // {1: h'01', "b": {1: "y", 2: "x"}}
    Assert.assertEquals("a20141016162a2016179026178", Hex.encode(encoded));
  }

  @Test
  public void decodeSortsAndReencodes() throws Exception {
    // {2: 1, 1: [{"b": 1, "a": 2}]}: neither map is sorted
    Object v = decode("a202010181a2616201616102");
    Assert.assertTrue(v instanceof CborMap);
    Assert.assertEquals("{1: [{\"a\": 2, \"b\": 1}], 2: 1}", v.toString());
    Assert.assertEquals("a20181a26161026162010201", Hex.encode(encode(v)));
    Assert.assertSame(v, CborMap.deepSorted(v));
  }

  @Test
  public void byteStringKeys() throws Exception {
    CborMap map = CborMap.of(Map.of(new byte[] {1, 2}, "v"));
    Assert.assertEquals("v", map.get(new byte[] {1, 2}));
    Assert.assertTrue(map.containsKey(new byte[] {1, 2}));
    Assert.assertNull(map.get(new byte[] {1}));
    Assert.assertNull(map.get(new Object()));
  }

  @Test
  public void duplicateKeys() {
    // {1: 1, 1: 2}
    Assert.assertThrows(CodecException.class, () -> decode("a201010102"));
    // Integer 1 and Long 1 have the same encoding
    Map<Object, Object> map = new HashMap<>();
    map.put(1, "a");
    map.put(1L, "b");
    Assert.assertThrows(CodecException.class, () -> CborMap.of(map));
  }

  @Test
  public void unmodifiable() throws Exception {
    Object v = decode("a10182 0102".replace(" ", ""));
    CborMap map = (CborMap) v;
    Assert.assertThrows(UnsupportedOperationException.class, () -> map.put(2, 2));
    Assert.assertThrows(UnsupportedOperationException.class, () -> map.remove(1));
    @SuppressWarnings("unchecked")
    List<Object> list = (List<Object>) map.get(1);
    Assert.assertThrows(UnsupportedOperationException.class, () -> list.add(3));
  }

  @Test
  public void taggedValue() throws Exception {
    Object v = CborMap.deepSorted(new CborTaggedObject(24, Map.of("z", 1, "aa", 2)));
    Assert.assertTrue(((CborTaggedObject) v).value() instanceof CborMap);
    Assert.assertEquals("24({\"z\": 1, \"aa\": 2})", CborMap.toDiagnostic(v));
  }

}
