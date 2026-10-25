// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.codec.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.util.Args;

/**
 * Args test.
 *
 * @author Lijun Liao (xipki)
 */
public class ArgsTest {

  @Test
  public void testBlank() {
    Assert.assertTrue(Args.isBlank(null));
    Assert.assertTrue(Args.isBlank(""));
    Assert.assertFalse(Args.isBlank("a"));

    Assert.assertFalse(Args.isNotBlank(null));
    Assert.assertFalse(Args.isNotBlank(""));
    Assert.assertTrue(Args.isNotBlank("a"));
  }

}
