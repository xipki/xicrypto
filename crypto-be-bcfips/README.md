# crypto-be-bcfips

Implementation of `org.xipki.crypto.api.CryptoApi` using BouncyCastle FIPS (`bc-fips`,
`bcpqc-fips`).

## Algorithms not supported by BC-FIPS

For the algorithms BC-FIPS does not support, the backend falls back to `BcFipsXiPKIProvider`, a
subclass of the XiPKI provider of the module `crypto-extra`, with the primitives of BC-FIPS
(provider name `XiPKI-BCFIPS`, not registered in `java.security.Security`). The fallback is used
only for MessageDigest and Signature, and only if BC-FIPS throws `NoSuchAlgorithmException`; an
algorithm that a later BC-FIPS version supports is taken from BC-FIPS.

Today (BC-FIPS 2.1.3) these are:

| Algorithm | Implementation |
|---|---|
| MessageDigest SM3 | crypto-extra |
| Signature SM3withSM2 | crypto-extra (SM2 arithmetic of crypto-extra; the keys may come from BC-FIPS) |
| Signature SHAKE128/256withRSAPSS (RFC 8702) | crypto-extra: EMSA-PSS and SHAKE in crypto-extra, the raw RSA operation (`RSA/ECB/NoPadding`) of BC-FIPS |
| Signature SHAKE128/256withECDSA (RFC 8692) | `ShakeEcdsaSignatureSpi`: SHAKE128 (256 bits) / SHAKE256 (512 bits) and `NONEwithECDSA` of BC-FIPS |

ECDSA with SHAKE uses a random nonce (X9.62 / SEC1). RFC 8692 recommends the deterministic nonce
of RFC 6979 for CAs and permits the random one under a stated policy. Verification does not
depend on the nonce.

AES-GMAC is taken from BC-FIPS.

**FIPS note:** these algorithms are not FIPS-approved. SM3, SM2 and RSA-PSS with SHAKE are
computed outside the BC-FIPS module boundary; ECDSA with SHAKE consists of BC-FIPS operations
only. A deployment that must use FIPS-approved algorithms only must not configure them.

In the approved-only mode of BC-FIPS (`-Dorg.bouncycastle.fips.approved_only=true`, checked with
BC-FIPS 2.1.3):

| Algorithm | Approved-only mode |
|---|---|
| SM3 | works: it is computed outside BC-FIPS, so the mode does not restrict it |
| SM3withSM2 | fails: BC-FIPS rejects keys on sm2p256v1 ("EC domain parameters not on approved list") |
| SHAKE128/256withRSAPSS | fails: the raw RSA operation is not available |
| SHAKE128/256withECDSA | works |

If no default `SecureRandom` of BC-FIPS is set (`CryptoServicesRegistrar.setSecureRandom`),
`CryptoBcFips` sets an approved DRBG (`FipsDRBG.SHA512`, 256-bit security strength, seeded from
the platform `SecureRandom`). This works in both modes. A default set by the application before
the backend is created is kept. `ApprovedOnlyModeTest` (surefire execution `approved-only`)
creates the backend in approved-only mode.

## Tests

```
# conformance tests, cross tests with crypto-be-jdk (CryptoJdkCrossTest), BcFipsXiPKIProviderTest
# (the fallback provider), and ApprovedOnlyModeTest in its own JVM in the approved-only mode of
# BC-FIPS
mvn -f xicrypto/pom.xml -pl crypto-be-bcfips test
```

The modules of the main project are tested with crypto-be-jdk only.
