# crypto-be-jdk

Implementation of `org.xipki.crypto.api.CryptoApi` using the providers of the JDK (SunJCE,
SunEC, SunRsaSign, SUN), and its own implementations for the algorithms the JDK does not
support. It is an alternative to `crypto-be-bc` (BouncyCastle) and `crypto-be-bc-fips` (BouncyCastle
FIPS), offered as library only.

## Requirements

- JDK 25 or later, at build time (`release 25`) and at run time. On an older JDK the backend
  is not loaded: `CryptoApiFactory` skips it, and choosing it fails with "CryptoApi backend 'jdk'
  could not be loaded: it requires Java 25 or later". The other modules of xicrypto run on
  JDK 11+; use `crypto-be-bc` or `crypto-be-bc-fips` there.
- Seed expansion of ML-DSA and ML-KEM, and the import of private keys containing the seed,
  need a JDK newer than 25 GA (see Limitations).
- Runtime dependencies: `crypto-api` (and transitively `codec`).
  No BouncyCastle.

## Usage

Put `crypto-be-jdk` instead of `crypto-be-bc` on the classpath. If more than one
backend is on the classpath, select it with the system property:

```
-Dxipki.crypto.backend=jdk
```

Only the providers of the JDK and an own instance of the XiPKI provider are used, even if other
providers such as BouncyCastle are registered. The XiPKI provider instance is not registered in
`java.security.Security`, so the JCA lookup of other code in the JVM is not affected.

## Algorithms not supported by the JDK

They are provided by the XiPKI provider of this module (`XiPKIProvider`, name `XiPKI`), with the
primitives (SHA-1/2/3, HMAC, raw RSA, AES/GCM) of the JDK providers (`Primitives`).

Packages:
- `org.xipki.crypto.jdk`: the backend on the JDK providers (`CryptoJdk`, the only public class,
  `EcRouting`, `JdkInternals`, `MldsaSignature`).
- `org.xipki.crypto.jdk.internal`: the XiPKI provider and its algorithms. Not an API: classes
  and members are public only if `CryptoJdk` or another subpackage uses them.
  - `internal`: `XiPKIProvider`, `XiProviderBase`, `Primitives`, `XiSignatureSpi`
  - `internal.rsa`: `RsaSignatureSpi`, `RsaRaw`, `RSAPSSSignatureSpi`, `PssEncoder`
  - `internal.digest`: `SM3Digest`, `HmacSM3Spi`, `Shake`, `AesGmacSpi`
  - `internal.ec`: `EcKeys`, `XiECPublicKey`, `XiECPrivateKey`, `XiECKeyFactorySpi`,
    `XiECKeyPairGeneratorSpi`, `XiECParametersSpi`, `XiECDSASignatureSpi`,
    `SM2WITHSM3SignatureSpi`, `XiEcParameters`
  - `internal.ec.math`: `EcCurve`, `WeierstrassCurve`, `WeierstrassPoint`, `PrimeField`, `ModN`,
    `VarTimeMultiplier`

| Algorithm | Note |
|---|---|
| SM3, HmacSM3, SM3withSM2 | `xipki.crypto.disableSm=true` disables them |
| SHAKE128/256withRSAPSS (RFC 8702) | |
| SHAKE128/256withECDSA (RFC 8692) | all curves |
| EC keys and ECDSA on brainpoolP256r1/P384r1/P512r1, SM2 | see below |
| AES-GMAC | |
| `xof` (SHAKE128, SHAKE256) | |
| `getByOID` (EC arithmetic of the 7 curves) | `sumOfTwoMultiplies` is the fast variable-time variant |

### EC curves

SunEC supports only the NIST curves P-256, P-384 and P-521. `CryptoJdk` chooses per curve:

- `newKeyFactory("EC")`, `newKeyPairGenerator("EC")`, `getPublicKey`, `getPrivateKey` and the
  ECDSA signatures use SunEC if it can generate keys on the curve, otherwise the XiPKI provider. The
  decision is made per curve, not per key class: SunEC still knows the brainpool curves in its
  curve table and parses brainpool keys, but fails when signing or verifying.
- The returned `KeyFactory`, `KeyPairGenerator` and `Signature` objects choose their delegate
  at initialization; their `getProvider()` returns null.
- If a future JDK supports one of these curves, it is used automatically.

### Implementation

| Algorithm | Classes |
|---|---|
| MessageDigest SM3 | `SM3Digest` |
| Mac HmacSM3 | `HmacSM3Spi` |
| Signature SM3withSM2 | `SM2WITHSM3SignatureSpi` |
| Signature SHAKE128/256withRSAPSS (RFC 8702) | `RSAPSSSignatureSpi`, `PssEncoder` |
| SHAKE128/256 as XOF | `Shake` |
| ECDSA (RFC 6979) | `XiECDSASignatureSpi` |
| EC keys and curve arithmetic (P-256, P-384, P-521, brainpoolP256r1/P384r1/P512r1, sm2p256v1) | `EcKeys`, `XiECPublicKey`, `XiECPrivateKey`, `EcCurve`, `WeierstrassCurve`, `WeierstrassPoint`, `ModN`, ... |

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
- RSA-PSS with SHAKE: the raw RSA operation is the `RSA/ECB/NoPadding` cipher of the JDK
  (blinded).

## Limitations

| Feature | Behaviour |
|---|---|
| ML-DSA context string | Requires `--add-exports java.base/sun.security.provider=ALL-UNNAMED`; without it, `setContext` with a non-empty context throws `InvalidAlgorithmParameterException` and composite ML-DSA signatures are not available. |
| ML-DSA / ML-KEM seeds on JDK 25 GA | The JDK has no seed expansion (`ML_DSA_Impls.seedToExpanded`, `ML_KEM_Impls.seedToExpanded`) and parses only private keys in the expanded-key format; `expandMldsaSeed` / `expandMlkemSeed` throw `UnsupportedOperationException`. The context string is not affected. |
| ECDH with brainpool, SM2 | Not supported (xipki uses key agreement only with X25519/X448). |
| RSA-OAEP names | `OAEPWith<hash>AndMGF1Padding` uses MGF1 with SHA-1 in the JDK; use `RSA/ECB/OAEPPadding` with an `OAEPParameterSpec`. |

## Tests

```
# conformance, routing, provider and arithmetic tests of this module; the execution no-bc runs
# some of them without BouncyCastle on the classpath, the execution sm-disabled runs
# SmDisabledTest with xipki.crypto.disableSm=true
mvn -pl crypto-be-jdk test
```

The statistical timing test (dudect: Welch's t-test of a fixed versus random inputs) of the
ladder and of the inversion mod n, with a sensitivity check on the variable-time multiplier, is
opt-in (about a minute):

```
mvn -pl crypto-be-jdk test -Dtest=ConstantTimeTest -Dxipki.timingTest=true
```

The other modules of the main project (security, gateway, pki-client, ocsp-server, pkcs11test,
...) are tested with crypto-be-jdk. The cross tests with the BouncyCastle backends
(`CryptoJdkCrossTest`, based on `CryptoApiCrossTest` of the crypto-api test-jar) are in
xicrypto/crypto-be-bc and xicrypto/crypto-be-bc-fips.

The tests run on JDK 25+, as do the tests of the other modules that use crypto-be-jdk.
