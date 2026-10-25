# crypto-extra

The algorithms the JDK lacks, and the JCA provider of XiPKI
(`org.xipki.crypto.extra.XiPKIProvider`, name `XiPKI`) that offers them. The crypto backends use
it for the algorithms their providers do not support, so that the application code does not
handle these algorithms explicitly:

- `crypto-be-jdk` uses all algorithms of this module.
- `crypto-be-bcfips` uses SM3, SM3withSM2 and SHAKE128/256withRSAPSS. BC-FIPS provides the others
  itself, and `crypto-be-bcfips` replaces SHAKE128/256withECDSA with its own implementation on
  BC-FIPS primitives (see `crypto-be-bcfips/README.md`).

Dependencies: `codec` only. No BouncyCastle, and no `crypto-api` (the provider is
used by the backends, it must not call back into `CryptoApiFactory`).

## Algorithms

| Type | Algorithms |
|---|---|
| MessageDigest | SM3 |
| Signature | SM3withSM2; SHAKE128/256withRSAPSS (RFC 8702); SHA3-224/256/384/512withRSA (PKCS#1 v1.5); RSASSA-PSS (MGF1 with the same hash, e.g. SHA3); SHA1/224/256/384/512withECDSA, SHA3-224/256/384/512withECDSA, SHAKE128/256withECDSA (RFC 8692) |
| KeyFactory, KeyPairGenerator, AlgorithmParameters | EC on the curves P-256, P-384, P-521, brainpoolP256r1/P384r1/P512r1, SM2 (sm2p256v1), FRP256v1 |
| Mac | AES-GMAC; HmacSHA3-224/256/384/512 |

SHA3 with RSA, RSASSA-PSS and HmacSHA3 are for JDK 11 to 15, which have SHA3 only as
`MessageDigest`. `Primitives.mac` falls back to the HmacSHA3 of crypto-extra if none of its providers
has it, so that the deterministic nonce (RFC 6979) of ECDSA with SHA3 works there too.

Also public: `Shake` (SHAKE128/256 as XOF) and the curve arithmetic in
`org.xipki.crypto.extra.ec.math` (`EcCurve`, `WeierstrassCurve`, `WeierstrassPoint`).

With the system property `xipki.crypto.disableSm=true`, the SM algorithms (SM3, SM3withSM2, the
curve sm2p256v1) are not offered.

## Usage

The provider is meant to be used as an instance, not registered in `java.security.Security`:

```java
Provider xipki = new XiPKIProvider(new Primitives(primitiveProviders));
Signature sig = Signature.getInstance("SHA256WITHECDSA", xipki);
```

`Primitives` is the source of the algorithms the provider uses but does not implement itself
(SHA-1/2/3, HMAC, `RSA/ECB/NoPadding`, `AES/GCM/NoPadding`): the backend passes its own
providers. Without providers, the default JCA lookup is used.

A backend can extend the provider. A subclass may use its own name
(`XiPKIProvider(String name, String info, Primitives)`), and add or replace entries with
`service(...)` and `ecdsa(...)`. An entry with the same type and algorithm replaces the existing
one. The SPI is created with its `(Primitives)` constructor if it has one, otherwise with its
no-arg constructor.

## Implementation notes

- Curve arithmetic: constant-time prime-field arithmetic, complete addition formulas (Renes,
  Costello, Batina 2016) and a Montgomery ladder for scalars that are secret. The ladder reads
  the scalar bits from fixed-length limbs with shifts. Points and x coordinates are encoded
  directly from the limbs (`getEncoded`, `getXCoordBytes`), without `BigInteger`. A
  variable-time interleaved wNAF (`VarTimeMultiplier`) is used for u1·G + u2·Q in the
  verification only.
- Secret scalars (nonce, private key) are handled with `ModN`, the constant-time arithmetic
  modulo the order n (Montgomery form, inversion by Fermat), and as fixed-length byte arrays.
  `BigInteger` is used for secrets only at the JCA boundary (`ECPrivateKey.getS()`).
- ECDSA: nonce as in RFC 6979, hedged with fresh random bytes if a `SecureRandom` is passed to
  `initSign`; the nonce never becomes a `BigInteger`, the modular arithmetic is additionally
  blinded; only DER encoded signatures are accepted.
- SM2: GB/T 32918.2 with the default user ID "1234567812345678"; arithmetic like ECDSA.
- The JVM gives no constant-time guarantee; the code is branch-free in the source, and
  `ConstantTimeTest` (see below) checks it statistically.
- RSA-PSS with SHAKE: the raw RSA operation is the `RSA/ECB/NoPadding` cipher of the primitives
  (blinded in the JDK and in BC-FIPS).

## Tests

```
mvn -f xicrypto/pom.xml -pl crypto-extra test
```

The execution `sm-disabled` runs `SmDisabledTest` with the SM algorithms disabled; the execution
`no-bc` runs the Wycheproof and arithmetic tests without BouncyCastle on the classpath. The
Wycheproof vectors are in `src/test/resources/wycheproof`.

The statistical timing test (dudect: Welch's t-test of a fixed versus random inputs) of the
ladder and of the inversion mod n, with a sensitivity check on the variable-time multiplier, is
opt-in (about a minute):

```
mvn -f xicrypto/pom.xml -pl crypto-extra test -Dtest=ConstantTimeTest -Dxipki.timingTest=true
```
