# crypto-be-jdk

Implementation of `org.xipki.crypto.api.CryptoApi` using the providers of the JDK (SunJCE,
SunEC, SunRsaSign, SUN), and the module `crypto-extra` for the algorithms the JDK does not
support. It is an alternative to `crypto-be-bc` (BouncyCastle) and `crypto-be-bcfips` (BouncyCastle
FIPS), offered as library only.

## Requirements

- At runtime: JDK 11 or later. Some algorithms need a newer JDK; on an older one they fail
  with a clear message, e.g. `NoSuchAlgorithmException("KeyPairGenerator ML-DSA requires JDK 25
  or later (ML-DSA, ML-KEM), running on 17.0.10")`:

  | Algorithms | JDK |
  |---|---|
  | RSA (PKCS#1 v1.5 and PSS with SHA-1/SHA-2/SHA-3), ECDSA with SHA-1/SHA-2/SHA-3/SHAKE, X25519, X448, AES, DESede, PBKDF2, HKDF, HMAC with SHA-1/SHA-2/SHA-3, SHA-1/SHA-2/SHA-3 digests, SHAKE, SM2/SM3, AES-GMAC | 11+ |
  | Ed25519, Ed448 | 15+ |
  | ML-DSA, ML-KEM (incl. the context string of ML-DSA) | 25+ |
  | Seed expansion of ML-DSA and ML-KEM; import of private keys containing the seed | newer than 25 GA |

- On JDK 11 to 15, which have SHA3 only as `MessageDigest`, HmacSHA3-\*, SHA3-\*withRSA,
  RSASSA-PSS with SHA3 (MGF1 with the same hash) and the signing of SHA3-\*withECDSA (RFC 6979
  with HmacSHA3) come from crypto-extra, on the SHA3 digest and the raw RSA operation of the JDK. On
  JDK 16+ the JDK's own implementations are used.
- On JDK 11 to 15, SunEC supports brainpool and further curves with its legacy native library
  (removed in JDK 16). The EC routing goes by capability, so on these versions such keys use
  SunEC; on JDK 16+ they use crypto-extra. P-256/384/521 always use SunEC, SM2 and FRP256v1 always
  crypto-extra.
- On JDK 11, X25519 and X448 private keys are read and written by the JDK in a form that is not
  that of RFC 8410 (JDK-8213363, fixed in JDK 12). crypto-be-jdk converts the input and wraps the
  keys of the JDK, so that `getEncoded()` returns the form of RFC 8410 on every JDK
  (`Jdk11Xdh`).
- Build: compiled with Java 11 (`release 11`, as the other modules), so the whole project builds
  with JDK 11+. The APIs of newer JDKs are not used at compile time: HKDF is implemented on
  `HmacSHA256` (no `javax.crypto.KDF`), `javax.crypto.KEM` is called through reflection
  (`JdkKem`), and the ML-DSA / ML-KEM parameter sets are given by name.
- Runtime dependencies: `crypto-api`, `crypto-extra` (and transitively `codec`).
  No BouncyCastle.

## Usage

Put `crypto-be-jdk` (with `crypto-extra`) instead of `crypto-be-bc` on the classpath. If more than one
backend is on the classpath, select it with the system property:

```
-Dxipki.crypto.backend=jdk
```

Only the providers of the JDK and an own instance of the XiPKI provider are used, even if other
providers such as BouncyCastle are registered. The XiPKI provider instance is not registered in
`java.security.Security`, so the JCA lookup of other code in the JVM is not affected.

## Algorithms not supported by the JDK

They are provided by `crypto-extra`, with the primitives (SHA-1/2/3, HMAC, raw RSA, AES/GCM) of
the JDK providers:

| Algorithm | Note |
|---|---|
| SM3, SM3withSM2 | `xipki.crypto.disableSm=true` disables them |
| SHAKE128/256withRSAPSS (RFC 8702) | |
| SHAKE128/256withECDSA (RFC 8692) | all curves |
| EC keys and ECDSA on brainpoolP256r1/P384r1/P512r1, SM2, FRP256v1 | see below |
| AES-GMAC | |
| `xof` (SHAKE128, SHAKE256) | |
| `getByOID` (EC arithmetic of the 8 curves) | `sumOfTwoMultiplies` is the fast variable-time variant |

### EC curves

SunEC supports only the NIST curves P-256, P-384 and P-521. `CryptoJdk` chooses per curve:

- `newKeyFactory("EC")`, `newKeyPairGenerator("EC")`, `getPublicKey`, `getPrivateKey` and the
  ECDSA signatures use SunEC if it can generate keys on the curve, otherwise crypto-extra. The
  decision is made per curve, not per key class: SunEC still knows the brainpool curves in its
  curve table and parses brainpool keys, but fails when signing or verifying.
- The returned `KeyFactory`, `KeyPairGenerator` and `Signature` objects choose their delegate
  at initialization; their `getProvider()` returns null.
- If a future JDK supports one of these curves, it is used automatically.

## Limitations

| Feature | Behaviour |
|---|---|
| ML-DSA context string | Requires `--add-exports java.base/sun.security.provider=ALL-UNNAMED`; without it, `setContext` with a non-empty context throws `InvalidAlgorithmParameterException` and composite ML-DSA signatures are not available. |
| ML-DSA / ML-KEM seeds on JDK 25 GA | The JDK has no seed expansion (`ML_DSA_Impls.seedToExpanded`, `ML_KEM_Impls.seedToExpanded`) and parses only private keys in the expanded-key format; `expandMldsaSeed` / `expandMlkemSeed` throw `UnsupportedOperationException`. The context string is not affected. |
| ECDH with brainpool, SM2, FRP256v1 | Not supported (xipki uses key agreement only with X25519/X448). |
| RSA-OAEP names | `OAEPWith<hash>AndMGF1Padding` uses MGF1 with SHA-1 in the JDK; use `RSA/ECB/OAEPPadding` with an `OAEPParameterSpec`. |

## Tests

```
# conformance and routing tests of this module; the execution no-bc runs them without
# BouncyCastle on the classpath
mvn -pl crypto-be-jdk test
```

The other modules of the main project (security, gateway, pki-client, ocsp-server, pkcs11test,
...) are tested with crypto-be-jdk. The cross tests with the BouncyCastle backends
(`CryptoJdkCrossTest`, based on `CryptoApiCrossTest` of the crypto-api test-jar) are in
xicrypto/crypto-be-bc and xicrypto/crypto-be-bcfips.

The tests of this module run on every JDK 11+: the tests of algorithms the running JDK lacks
are skipped, or check the clear error instead (`CryptoJdkRuntimeTest`). They have been run on
JDK 11, 17, 21 and 25. The tests of the other modules must be run on JDK 25+, because they use
ML-DSA and ML-KEM throughout.
