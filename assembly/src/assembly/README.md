# XiPKI Crypto Backends

This package contains the crypto backends to be used in xipki:

- `crypto-be-jdk`: based on the JDK.
- `crypto-be-bc`: based on the BouncyCastle LTS provider (`bcprov-lts8on`).
- `crypto-be-bcfips`: based on the BouncyCastle FIPS provider (`bc-fips` and `bcpqc-fips`).

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
