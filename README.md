# MedVault

Orvosi leletek és képek manipulációbiztos titkosítására, digitális aláírására és kriptográfiai támadások demonstrálására szolgáló alkalmazás.

## Kriptográfiai felépítés

* **Kulcslevezetés:** `Argon2id` (64 MB RAM, 3 iteráció, 4 szál, 16 bájtos véletlen só) → 256 bites AES kulcs.
* **Hitelesített titkosítás (AEAD):** `AES-256-GCM` (12 bájtos Nonce, 16 bájtos GMAC integritási címke).
* **Társított adatok (AAD):** A nyílt fejléc (páciens metaadatok, só, nonce) AAD-ként védett a GMAC címke által.
* **Digitális aláírás:** 2048 bites `RSA-PSS` (`SHA-256`), `PKCS#8` védett privát kulccsal.
* **Kripto Labor:** `AES-ECB` képi szivárgás, bit-flipping és fejléc-módosítási (AAD) szimulációk.

## `.medvault` csomagformátum

```text
[MEDV (4B)] [SALT (16B)] [NONCE (12B)] [LEN (2B)] [AAD JSON] [CIPHERTEXT] [GMAC TAG (16B)] [RSA-PSS SIG (256B)]
```
