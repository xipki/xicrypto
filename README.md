# XiPKI Crypto

Cryptographic building blocks of [XiPKI](https://github.com/xipki/xipki): ASN.1/CBOR codec,
a pluggable crypto API with JDK and BouncyCastle backends, a PKCS#11 wrapper, and an emulated
HSM (`xihsm`) for testing.

- Java 11 or later
- License: [Apache License 2.0](LICENSE)

## Modules

| Module             | Artifact                    | Description                                                                 |
|--------------------|-----------------------------|-----------------------------------------------------------------------------|
| `codec`            | `codec`                     | ASN.1 (DER/BER) and CBOR encoding and decoding, utilities.                  |
| `crypto-api`       | `crypto-api`                | Backend-neutral crypto API (`CryptoApi`) and its loader `CryptoApiFactory`. |
| `crypto-extra`     | `crypto-extra`              | Additional JCA provider (`XiPKIProvider`): RSA-PSS, SM3, SHAKE, HMAC-SHA3, AES-GMAC, EC. |
| `crypto-core`      | `crypto-core`               | Algorithm enums, key specs, KEM, composite signatures, PEM.                |
| `crypto-be-jdk`    | `crypto-be-jdk`             | Backend based on the JDK providers.                                         |
| `crypto-be-bc`     | `crypto-be-bc`              | Backend based on the BouncyCastle LTS provider (`bcprov-lts8on`).           |
| `crypto-be-bcfips` | `crypto-be-bcfips`          | Backend based on the BouncyCastle FIPS provider (`bc-fips`, `bcpqc-fips`).  |
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

The backend package is written to `assembly/target/crypto-backends-<version>.tar.gz`. See
[assembly/src/assembly/README.md](assembly/src/assembly/README.md) for how to use them in an
XiPKI installation.

## Crypto backends

`CryptoApiFactory.get()` loads the implementation of `CryptoApi` via `ServiceLoader`.
Put exactly one backend (`crypto-be-jdk`, `crypto-be-bc` or `crypto-be-bcfips`) on the classpath,
or select one with the system property `xipki.crypto.backend`:

```sh
java -Dxipki.crypto.backend=bc ...    # or jdk, bcfips
```

```java
CryptoApi crypto = CryptoApiFactory.get();
```

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
