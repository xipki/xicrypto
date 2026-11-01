# XiPKI Crypto Backends

This package contains the crypto backends to be used in xipki:

- `crypto-be-jdk`: based on the JDK, requires JDK 25 or later. It is the default backend of
  `xipki-setup-<version>.tar.gz`; use this folder to switch back to it from another backend.
- `crypto-be-bc`: based on the BouncyCastle LTS provider (`bcprov-lts8on`).
- `crypto-be-bc-fips`: based on the BouncyCastle FIPS provider (`bc-fips` and `bcpqc-fips`),
  always in its approved-only mode (set by the backend itself).
- `crypto-be-openssl`: based on libcrypto of OpenSSL 4.1+, not in the FIPS mode. See below for
  its requirements.
- `crypto-be-openssl-fips`: as `crypto-be-openssl`, but OpenSSL must be in the FIPS mode.

Each backend has its own folder `<backend>/crypto` containing all jar files it requires.

## Usage

1. Unpack `xipki-setup-<version>.tar.gz`.
2. Replace the folder `setup/jars/crypto` of the unpacked `xipki-setup-<version>` with the
   folder `crypto` of the chosen backend, e.g. for `crypto-be-bc`:

   ```sh
   rm -rf xipki-setup-<version>/setup/jars/crypto
   cp -r crypto-backends-<version>/crypto-be-bc/crypto xipki-setup-<version>/setup/jars/crypto
   ```

3. Continue the installation as described in `xipki-setup-<version>/INSTALL.md`.
   The script `prepare.sh` copies the jar files in `setup/jars/crypto` to the
   destination folders, so step 2 must be done before calling `prepare.sh`.

## crypto-be-openssl and crypto-be-openssl-fips

- JDK 25 or later.
- `crypto-be-openssl` refuses to start if OpenSSL is in the FIPS mode, `crypto-be-openssl-fips`
  if it is not. The FIPS mode is configured in the openssl.cnf of the environment variable
  `OPENSSL_CONF`: activate the providers fips and base (not default), and set
  `default_properties = fips=yes`.
- libcrypto of OpenSSL 4.1 or later, installed on the system (not part of this package). By
  default, `libcrypto.so.4` (Linux), `libcrypto.4.dylib` (macOS, also in the Homebrew folders of
  `openssl@4`) or `libcrypto-4-x64.dll` (Windows) is loaded; another one can be set with the
  system property `xipki.openssl.lib`, e.g. `-Dxipki.openssl.lib=/opt/openssl-4.1/lib64/libcrypto.so.4`.
- The JVM option `--enable-native-access=ALL-UNNAMED`, otherwise the JDK prints a warning about
  the native access.
