# XiPKI Crypto

Cryptographic building blocks of [XiPKI](https://github.com/xipki/xipki): ASN.1/CBOR codec, a pluggable crypto API with JDK and BouncyCastle backends, a PKCS#11 wrapper, and an emulated HSM (`xihsm`) for testing.

- Java 11 or later; the backends `crypto-be-jdk`, `crypto-be-openssl` and
  `crypto-be-openssl-fips` require Java 25 or later. Building requires JDK 25 or later.
- License: [Apache License 2.0](LICENSE)

## Modules

| Module             | Artifact                    | Description                                                                 |
|--------------------|-----------------------------|-----------------------------------------------------------------------------|
| `codec`            | `codec`                     | ASN.1 (DER/BER) and CBOR encoding and decoding, utilities.                  |
| `crypto-api`       | `crypto-api`                | Backend-neutral crypto API (`CryptoApi`) and its loader `CryptoApiFactory`. |
| `crypto-core`      | `crypto-core`               | Algorithm enums, key specs, KEM, composite signatures, PEM.                |
| `crypto-be-jdk`    | `crypto-be-jdk`             | Backend based on the JDK providers. Requires JDK 25+.                       |
| `crypto-be-bc`     | `crypto-be-bc`              | Backend based on the BouncyCastle LTS provider (`bcprov-lts8on`).           |
| `crypto-be-bc-fips`| `crypto-be-bc-fips`         | Backend based on the BouncyCastle FIPS provider (`bc-fips`, `bcpqc-fips`).  |
| `crypto-openssl`   | `crypto-openssl`            | Code of the OpenSSL backends: libcrypto of OpenSSL 3.5+ (incl. 4.x) via FFM. Requires JDK 25+. |
| `crypto-be-openssl`| `crypto-be-openssl`         | Backend `openssl` on `crypto-openssl`; OpenSSL must not be in the FIPS mode. |
| `crypto-be-openssl-fips`| `crypto-be-openssl-fips` | Backend `openssl-fips` on `crypto-openssl`; OpenSSL must be in the FIPS mode. |
| `pkcs11`           | `pkcs11`                    | Java wrapper for PKCS#11 modules, with JNI native libraries.                |
| `xihsm`            | `xihsm`                     | Emulated PKCS#11 HSM in pure Java, mimicking the behavior of several vendors. |
| `pkcs11test`       | `pkcs11test`                | Tests of the PKCS#11 wrapper against `xihsm` and real HSMs.                 |
| `assembly`         | `crypto-backends-assembly`  | Distribution package of the crypto backends for XiPKI.                      |

All artifacts use the group ID `org.xipki.crypto`.

## Build

```sh
mvn clean install
```

To skip the tests:

```sh
mvn clean install -DskipTests
```

The performance tests (`*SpeedTest` of the crypto backends and of `pkcs11test`)
run only with the profile `speed`, together with the other tests:

```sh
mvn test -Pspeed -pl crypto-be-jdk,crypto-be-bc,crypto-be-bc-fips,crypto-openssl,pkcs11test
# duration of each test and threads of the crypto backend speed tests (default: 1s, 1 thread)
mvn test -Pspeed -pl crypto-openssl -Dspeed.duration=10s -Dspeed.threads=4
```

The duration and threads of the `pkcs11test` speed tests are configured in
`pkcs11test/src/test/resources/pkcs11.json` (`speed`).

The backend package is written to `assembly/target/crypto-backends-<version>.tar.gz`. See
[assembly/src/assembly/README.md](assembly/src/assembly/README.md) for how to use them in an
XiPKI installation.

## Crypto backends

`CryptoApiFactory.get()` loads the implementation of `CryptoApi` via `ServiceLoader`.
Put exactly one backend (`crypto-be-jdk`, `crypto-be-bc`, `crypto-be-bc-fips`, `crypto-be-openssl`
or `crypto-be-openssl-fips`) on the classpath, or select one with the system property
`xipki.crypto.backend`:

```sh
java -Dxipki.crypto.backend=bc ...    # or jdk, bc-fips, openssl, openssl-fips
```

```java
CryptoApi crypto = CryptoApiFactory.get();
```

### Supported algorithms

✅ supported, ❌ not supported. Each entry is a real operation through `CryptoApi` (key
generation, sign and verify, encrypt and decrypt, derive), not only the lookup of the name.

| Algorithm | jdk | bc | openssl | bc-fips | openssl-fips |
|---|:-:|:-:|:-:|:-:|:-:|
| **PQC** | | | | | |
| ML-DSA-44/65/87 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA with context string | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-KEM-512/768/1024 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA and ML-KEM seed expansion | ✅ | ✅ | ✅ | ✅ | ✅ |
| **EC** | | | | | |
| ECDSA on P-256/384/521 with SHA-2, SHA-3 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ECDSA with SHAKE128/256 (RFC 8692) | ✅ | ✅ | ✅ | ❌ | ❌ |
| ECDSA on brainpoolP256r1/P384r1/P512r1 | ✅ | ✅ | ✅ | ✅ | ❌ |
| SM2 (SM3withSM2) | ✅ | ✅ | ✅ | ❌ | ❌ |
| ECDH on P-256 | ✅ | ✅ | ✅ | ✅ | ✅ |
| EC arithmetic (`getByOID`) on P-256, brainpool, sm2p256v1 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ed25519, Ed448 | ✅ | ✅ | ✅ | ✅ | ✅ |
| X25519, X448 | ✅ | ✅ | ✅ | ❌ | ❌ |
| **RSA** | | | | | |
| PKCS#1 v1.5 signature with SHA-2, SHA-3 | ✅ | ✅ | ✅ | ✅ | ✅ |
| PKCS#1 v1.5 signature with SHA-1 (signing) | ✅ | ✅ | ✅ | ❌ ¹ | ❌ ¹ |
| RSASSA-PSS with SHA-2, SHA-3 | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSASSA-PSS with SHAKE128/256 (RFC 8702) | ✅ | ✅ | ✅ | ❌ | ❌ |
| RSAES-OAEP | ✅ | ✅ | ✅ | ✅ ² | ✅ |
| RSAES-PKCS1-v1_5 encryption | ✅ | ✅ | ✅ | ❌ ³ | ❌ |
| **Digests, XOF** | | | | | |
| SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256 | ✅ | ✅ | ✅ | ✅ | ✅ |
| SHA3-224/256/384/512 | ✅ | ✅ | ✅ | ✅ | ✅ |
| SHAKE128, SHAKE256 (XOF) | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM3 | ✅ | ✅ | ✅ | ❌ | ❌ |
| **MAC, KDF** | | | | | |
| HMAC with SHA-1, SHA-2, SHA-3 | ✅ | ✅ | ✅ | ✅ ⁴ | ✅ ⁴ |
| HMAC with SM3 | ✅ | ✅ | ✅ | ❌ | ❌ |
| AES-GMAC | ✅ | ✅ | ✅ | ✅ | ✅ |
| PBKDF2, HKDF-SHA256 | ✅ | ✅ | ✅ | ✅ ⁵ | ✅ ⁶ |
| **Symmetric** | | | | | |
| AES-GCM, AES-CBC, AES-CTR | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES key wrap (AESWrap, RFC 3394) | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES key wrap with padding (AESWrapPad, RFC 5649) | ✅ | ✅ | ✅ | ✅ | ✅ |
| DESede-CBC encryption | ✅ | ✅ | ✅ | ❌ ³ | ❌ ³ |
| DESede-CBC decryption | ✅ | ✅ | ✅ | ✅ | ✅ |

1. Verification works.
2. Encryption only in `Cipher.WRAP_MODE`; decryption works in `DECRYPT_MODE` and `UNWRAP_MODE`.
3. Decryption works.
4. Keys of at least 112 bits.
5. PBKDF2: passwords of at least 112 bits (14 characters).
6. PBKDF2: salts of at least 128 bits.

For the details of the FIPS modes see [crypto-be-bc-fips/README.md](crypto-be-bc-fips/README.md)
and [crypto-openssl](crypto-openssl).

Tested on macOS (aarch64) with JDK 25.0.4.1, BouncyCastle LTS 2.73.13, BC-FIPS 2.1.3 /
BCPQC-FIPS 2.1.0 (in the approved-only mode), and OpenSSL 3.5.9, 3.6.1 and 4.1.0 (identical results). "openssl-fips" was tested on OpenSSL
3.5.9 with the provider fips 3.5.9.

## PKCS#11

The `pkcs11` module accesses PKCS#11 modules via JNI. Prebuilt native libraries for
Linux (amd64, arm64) and macOS (arm64) are bundled in the jar; the C sources and build
scripts for further platforms are in `pkcs11/src/main/c`.

The module path passed to `PKCS11Module.getInstance(...)` is either

- the path of a native PKCS#11 library, e.g. `/usr/local/lib/softhsm/libsofthsm2.so`, or
- `xihsm:<conf>` for the emulated HSM, e.g.
  - `xihsm:mem:vendor=softhsm` – objects kept in memory,
  - `xihsm:file:tenant=utimaco,vendor=utimaco` – objects persisted in files.

`xihsm` emulates the vendors `cloudhsm`, `luna`, `ncipher`, `sansec`, `softhsm`, `tass`,
`utimaco` and `xihsm`. The test configuration in
[pkcs11test/src/test/resources/pkcs11.json](pkcs11test/src/test/resources/pkcs11.json) lists
examples.
