// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test.c509;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.c509.id.ConstHashAlgorithm;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Locale;
import java.util.function.Function;

/**
 * The names of the C509 algorithm registries: every constant is found by its name in the forms
 * x_y, xy and x-y, in any case, as well as by its registered name and its decimal code.
 *
 * @author Lijun Liao (xipki)
 */
public class ConstAlgorithmNamesTest {

  @Test
  public void publicKeyAlgorithm() throws Exception {
    assertAllConstants(ConstPublicKeyAlgorithm.class, ConstPublicKeyAlgorithm::code);
    int code = ConstPublicKeyAlgorithm.ec_secp256r1;
    for (String name : new String[] {"ec_secp256r1", "ecsecp256r1", "ec-secp256r1",
        "EC_SECP256R1", "1", "EC public key on curve secp256r1"}) {
      Assert.assertEquals(name, Integer.valueOf(code), ConstPublicKeyAlgorithm.code(name));
    }
    Assert.assertNull(ConstPublicKeyAlgorithm.code("no_such_algorithm"));
  }

  @Test
  public void signatureAlgorithm() throws Exception {
    assertAllConstants(ConstSignatureAlgorithm.class, ConstSignatureAlgorithm::code);
    int code = ConstSignatureAlgorithm.ecdsa_with_SHA256;
    for (String name : new String[] {"ecdsa_with_SHA256", "ecdsawithsha256",
        "ecdsa-with-sha256"}) {
      Assert.assertEquals(name, Integer.valueOf(code), ConstSignatureAlgorithm.code(name));
    }
  }

  @Test
  public void hashAlgorithm() throws Exception {
    assertAllConstants(ConstHashAlgorithm.class, ConstHashAlgorithm::code);
    Assert.assertEquals(Integer.valueOf(ConstHashAlgorithm.SHA256),
        ConstHashAlgorithm.code("sha-256"));
  }

  private static void assertAllConstants(Class<?> clazz, Function<String, Integer> codeOf)
      throws Exception {
    int n = 0;
    for (Field field : clazz.getFields()) {
      int mod = field.getModifiers();
      if (field.getType() != int.class || !Modifier.isStatic(mod) || !Modifier.isFinal(mod)) {
        continue;
      }
      n++;
      Integer expected = field.getInt(null);
      for (String name : variants(field.getName())) {
        Assert.assertEquals(clazz.getSimpleName() + ": " + name, expected, codeOf.apply(name));
      }
    }
    Assert.assertTrue(clazz.getSimpleName() + " has constants", n > 0);
  }

  /** The name with the separators '_', '' and '-', in the original and in lower case. */
  static String[] variants(String name) {
    String noSep = name.replace("_", "").replace("-", "");
    String dash = name.replace('_', '-');
    String underscore = name.replace('-', '_');
    return new String[] {underscore, noSep, dash, underscore.toLowerCase(Locale.ROOT),
        noSep.toUpperCase(Locale.ROOT)};
  }

}
