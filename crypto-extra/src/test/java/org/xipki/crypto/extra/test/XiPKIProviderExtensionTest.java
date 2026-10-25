// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.test;

import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.crypto.extra.Primitives;
import org.xipki.crypto.extra.XiPKIProvider;
import org.xipki.crypto.extra.ec.XiECDSASignatureSpi;

import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureSpi;

/**
 * Tests that a subclass of {@link XiPKIProvider} can replace and add entries.
 *
 * @author Lijun Liao (xipki)
 */
public class XiPKIProviderExtensionTest {

  private static final String OID_SHA256_ECDSA = AlgorithmOIDs.ecdsa_with_SHA256.getId();

  @Test
  public void testDefaultEntry() {
    Provider.Service s = new XiPKIProvider().getService("Signature", "SHA256WITHECDSA");
    Assert.assertNotNull(s);
    Assert.assertEquals(XiECDSASignatureSpi.class.getName(), s.getClassName());
  }

  @Test
  public void testReplaceEntry() throws Exception {
    Provider p = new ExtProvider(new Primitives());
    Assert.assertEquals("XiPKI-TEST", p.getName());

    Provider.Service s = p.getService("Signature", "SHA256WITHECDSA");
    Assert.assertEquals(DummySignatureSpi.class.getName(), s.getClassName());
    // the attributes of an ECDSA entry
    Assert.assertNotNull(s.getAttribute("SupportedKeyClasses"));

    // by name and by the OID alias
    for (String name : new String[] {"SHA256WITHECDSA", OID_SHA256_ECDSA}) {
      Signature sig = Signature.getInstance(name, p);
      sig.initVerify((PublicKey) null);
      Assert.assertTrue(name, sig.verify(new byte[0]));
    }

    // the other entries are kept
    Assert.assertEquals(XiECDSASignatureSpi.class.getName(),
        p.getService("Signature", "SHA384WITHECDSA").getClassName());
  }

  @Test
  public void testAddEntry() throws Exception {
    Primitives primitives = new Primitives();
    Provider p = new ExtProvider(primitives);
    MessageDigest md = MessageDigest.getInstance("TEST-DIGEST", p);
    // created with the primitives of the provider
    Assert.assertArrayEquals(new byte[] {1}, md.digest());
    Assert.assertSame(primitives, DummyDigestSpi.lastPrimitives);
  }

  private static final class ExtProvider extends XiPKIProvider {

    private static final long serialVersionUID = 1L;

    ExtProvider(Primitives primitives) {
      super("XiPKI-TEST", "test", primitives);
      ecdsa("SHA256WITHECDSA", DummySignatureSpi.class, p -> new DummySignatureSpi(),
          AlgorithmOIDs.ecdsa_with_SHA256);
      service("MessageDigest", "TEST-DIGEST", DummyDigestSpi.class, DummyDigestSpi::new);
    }

  }

  /**
   * Signature that verifies everything.
   */
  public static final class DummySignatureSpi extends SignatureSpi {

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
    }

    @Override
    protected void engineUpdate(byte b) {
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
    }

    @Override
    protected byte[] engineSign() {
      return new byte[0];
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
      return true;
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
      throw new InvalidParameterException();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      throw new InvalidParameterException();
    }

  }

  /**
   * Digest with the constant output {1}.
   */
  public static final class DummyDigestSpi extends MessageDigestSpi {

    static volatile Primitives lastPrimitives;

    public DummyDigestSpi(Primitives primitives) {
      lastPrimitives = primitives;
    }

    @Override
    protected void engineUpdate(byte input) {
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
    }

    @Override
    protected byte[] engineDigest() {
      return new byte[] {1};
    }

    @Override
    protected void engineReset() {
    }

  }

}
