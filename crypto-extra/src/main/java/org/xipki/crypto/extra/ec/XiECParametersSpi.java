// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.crypto.extra.ec;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.extra.ec.math.EcCurve;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * AlgorithmParameters "EC" for the named curves of {@link EcCurve}: converts between the
 * curve OID ({@link ECGenParameterSpec}, DER-encoded OID) and {@link ECParameterSpec}.
 *
 * @author Lijun Liao (xipki)
 */
public class XiECParametersSpi extends AlgorithmParametersSpi {

  private EcCurve curve;

  @Override
  protected void engineInit(AlgorithmParameterSpec paramSpec)
      throws InvalidParameterSpecException {
    EcCurve c = EcKeys.curveOf(paramSpec);
    if (c == null) {
      throw new InvalidParameterSpecException("unsupported curve or AlgorithmParameterSpec");
    }
    this.curve = c;
  }

  @Override
  protected void engineInit(byte[] params) throws IOException {
    Asn1Oid oid;
    try {
      oid = Asn1Oid.fromEncoded(params);
    } catch (CodecException | RuntimeException e) {
      throw new IOException("only named curves are supported", e);
    }

    EcCurve c = EcCurve.ofOid(oid);
    if (c == null) {
      throw new IOException("unsupported curve " + oid.getId());
    }
    this.curve = c;
  }

  @Override
  protected void engineInit(byte[] params, String format) throws IOException {
    if (format != null && !"ASN.1".equalsIgnoreCase(format)) {
      throw new IOException("unsupported format " + format);
    }
    engineInit(params);
  }

  @Override
  protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
      throws InvalidParameterSpecException {
    assertInitialized();
    if (paramSpec.isAssignableFrom(ECParameterSpec.class)) {
      return paramSpec.cast(curve.parameterSpec());
    } else if (paramSpec.isAssignableFrom(ECGenParameterSpec.class)) {
      return paramSpec.cast(new ECGenParameterSpec(curve.oid().getId()));
    }
    throw new InvalidParameterSpecException("unsupported AlgorithmParameterSpec "
        + paramSpec.getName());
  }

  @Override
  protected byte[] engineGetEncoded() {
    assertInitialized();
    return curve.oid().getEncoded();
  }

  @Override
  protected byte[] engineGetEncoded(String format) throws IOException {
    if (format != null && !"ASN.1".equalsIgnoreCase(format)) {
      throw new IOException("unsupported format " + format);
    }
    return engineGetEncoded();
  }

  @Override
  protected String engineToString() {
    return curve == null ? "uninitialized" : curve.oid().getId();
  }

  private void assertInitialized() {
    if (curve == null) {
      throw new IllegalStateException("not initialized");
    }
  }

}
