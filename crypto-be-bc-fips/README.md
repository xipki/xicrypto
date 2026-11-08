# crypto-be-bc-fips

Implementation of `org.xipki.crypto.api.CryptoApi` using BouncyCastle FIPS (`bc-fips`,
`bcpqc-fips`).

## Algorithms not supported by BC-FIPS

All cryptographic operations are those of BC-FIPS (and BCPQC-FIPS for the PQC algorithms). The
backend has no own implementation of any algorithm and composes none from BC-FIPS operations. No
other JCA provider registered in the JVM is used: an algorithm that BC-FIPS and BCPQC-FIPS do not
have is a `NoSuchAlgorithmException`.

Not offered therefore: SM3, SM3withSM2, SHAKE128/256withRSAPSS (RFC 8702) and
SHAKE128/256withECDSA (RFC 8692). Use `crypto-be-bc` or `crypto-be-openssl` for them. Keys and
curve parameters on sm2p256v1 still come from BC-FIPS (not in the approved-only mode).

AES-GMAC is taken from BC-FIPS.

## Approved-only mode (always)

The backend always runs in the approved-only mode of BC-FIPS. `CryptoBcFips` sets the system
property and the security property `org.bouncycastle.fips.approved_only` to `true` when the
class is initialized, before it uses BC-FIPS; another value, e.g. from
`-Dorg.bouncycastle.fips.approved_only=false` or `java.security`, is overridden. No JVM option is
needed:

```sh
java -Dxipki.crypto.backend=bc-fips ...
```

BC-FIPS reads the property once, at its first use in the JVM. If other code uses BC-FIPS before
`CryptoBcFips` is initialized, BC-FIPS stays in the normal mode, and `new CryptoBcFips()` throws
`IllegalStateException` ("... BC-FIPS was used in the normal mode before the backend was
created"). Use `crypto-be-bc` if the approved-only mode is not wanted. Note that both properties
are global: other code in the JVM that uses BC-FIPS later also runs in the approved-only mode.

If no default `SecureRandom` of BC-FIPS is set (`CryptoServicesRegistrar.setSecureRandom`),
`CryptoBcFips` sets an approved DRBG (`FipsDRBG.SHA512`, 256-bit security strength, seeded from
the platform `SecureRandom`). A default set by the application before the backend is created is
kept; it must be an approved DRBG, a plain `SecureRandom` throws `FipsUnapprovedOperationError`.

Restrictions of the approved-only mode (checked with BC-FIPS 2.1.3 / BCPQC-FIPS 2.1.0 on JDK
25.0.4.1 by `BcProvUtilTest` and `CryptoJdkCrossTest`):

| Operation | Approved-only mode |
|---|---|
| SHA-1 signatures (PKCS#1 v1.5, PSS) | verification only; signing: `FipsUnapprovedOperationError` |
| RSA-OAEP encryption | only in `Cipher.WRAP_MODE`; `ENCRYPT_MODE`: `InvalidParameterException` |
| RSAES-PKCS1-v1_5 encryption | not at all, also not in `WRAP_MODE`: `FipsUnapprovedOperationError` |
| RSA decryption (OAEP and PKCS#1 v1.5) | works in `DECRYPT_MODE` and `UNWRAP_MODE` |
| DESede | decryption only; encryption: `FipsUnapprovedOperationError` |
| HMAC | keys of at least 112 bits |
| PBKDF2 | passwords of at least 112 bits (14 characters) |
| X25519, X448 | not available: no `KeyPairGenerator` / `KeyAgreement`; the raw functions (`generateX25519PrivateKey`, `calculateX25519Agreement`, ...) throw `UnsupportedOperationException` |
| Keys on sm2p256v1 | rejected: EC domain parameters not on approved list |

All other algorithms of the matrix in the [main README](../README.md) work: SHA-2, SHA-3, SHAKE,
AES-GMAC, HKDF, RSA PKCS#1 v1.5 and PSS signatures with SHA-2 and SHA-3, ECDSA with SHA-2 and
SHA-3 (also on brainpool), ECDH, Ed25519, Ed448, ML-DSA (with context string and seed
expansion), ML-KEM, AES-GCM/CBC/CTR and AES key wrap.

**CMS / SCEP (RFC 8894):** RSA key transport can be decrypted (a CA or RA decrypts the SCEP
request), but not encrypted: RSAES-PKCS1-v1_5, the default of SCEP, is not available, and
RSA-OAEP works only through `WRAP_MODE`, while the CMS code of xipki (`CmsCrypto`) encrypts in
`ENCRYPT_MODE`. So enveloped data for an RSA recipient (e.g. the SCEP response) cannot be
created with this backend.

## Tests

```
# all tests with -Dorg.bouncycastle.fips.approved_only=false, which the backend overrides:
# conformance tests (BcProvUtilTest), cross tests with crypto-be-jdk (CryptoJdkCrossTest),
# BcFipsOnlyTest (no other provider is used), ApprovedOnlyModeTest; UsedBeforeTest in its own
# JVM (BC-FIPS used before the backend: rejected)
mvn -f xicrypto/pom.xml -pl crypto-be-bc-fips test
```

The modules of the main project are tested with crypto-be-jdk only.
