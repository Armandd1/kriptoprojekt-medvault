# 🛡️ MedVault – Zero-Knowledge Orvosi Lelet- és Képtár
**Haladó Kriptográfia és Számítógépbiztonság Projekt (Sapientia EMTE, 2026)**  
**Oktató:** Dr. Márton Gyöngyvér  
**Hallgató:** Tőtős Armand (Szoftverfejlesztés mesteri)  

---

## 1. A Történet (A Megoldandó Kiber-Incidens: „BioShield Művelet”)

A **St. Camillus Onkológiai Központban** Dr. Kovács vezető sebész egy kritikus daganatos páciens (**Kovács „#MED-8042” Péter**) CT felvételét és laboreredményeit várja egy távoli felhőszerverről a reggeli műtét előtt.

A kórházi IT biztonsági rendszer riasztást ad ki: **egy zsarolóvírus-csoport behatolt a felhőtárhelyre!**  
A támadók két veszélyes dolgot próbálnak végrehajtani:
1. **A Kísértet-lelet (Képi adatszivárgás):** Ha a képeket naiv ECB módban tárolnák, a bűnözők kulcs nélkül is pontosan látnák a páciens daganatának méretét és helyét.
2. **A Csendes Szike (Életveszélyes adatmanipuláció):** A támadók 1 bit átírásával (bit-flipping) megpróbálják a daganat típusát vagy a tumor-marker koncentrációt lecsökkenteni, hogy az orvos tévesen malignus helyett benignusnak ítélje az elváltozást, és törölje a műtétet, ami a beteg halálához vezetne!
3. **Személyazonosság-csere:** Átírják a páciens azonosítóját a fejlécben, hogy a mérgező kemoterápiát egy másik beteg kapja meg.

A **MedVault** feladata: a leletek kliensoldali Zero-Knowledge lezárása és a támadások azonnali, életmentő elhárítása a **Kriptográfiai Vizsgáló Laborban**.

---

## 2. Alkalmazott Kriptográfiai Architektúra

| Modul / Cél | Alkalmazott Primitív | Kurzus Előadás | Biztonsági Szerep |
| :--- | :--- | :--- | :--- |
| **Kulcslevezetés (KDF)** | `Argon2id` (`argon2-cffi`, RFC 9106) | 3. Előadás | NFC-normalizált mesterjelszóból 256 bites kulcsot képez ($m = 64\text{ MiB}$, $t = 3$, $p = 4$). GPU/ASIC ellenálló. |
| **Kriptográfiai Só** | CSPRNG 16 bájt (`secrets`, PEP 506) | 2. Előadás | Fájlonként egyedi 256 bites AES kulcsot biztosít, kizárva a szivárványtáblát és a GCM nonce-ütközést. |
| **Hitelesített Titkosítás** | `AES-256-GCM` (`pycryptodome`, NIST SP 800-38D) | 5. Előadás | 12 bájtos (96 bites) Nonce, CTR mód (nincs padding oracle!), 128 bites Galois-mező $GF(2^{128})$ GMAC címke. |
| **Teljes Fejléc Védelem** | **Associated Data (AAD)** | 4. és 5. Előadás | A teljes nyílt csomagfejléc (`MEDV` + só + nonce + páciens JSON) nyíltan indexelhető, de a GMAC miatt hamisíthatatlan. |
| **Digitális Aláírás** | `RSA-2048 PSS` + `SHA-256` (`PKCS#8` kulcsvédelem) | 6. Előadás | Letagadhatatlanság és gyors (~0.1 ms) külső előellenőrzés még az Argon2id futtatása előtt; privát kulcs PKCS#8-cal védve. |
| **Támadásszimulátor** | Képi ECB vs GCM, Bit-flipping, AAD csere | 4. és 5. Előadás | Közvetlen demonstrációk az 5. előadás `4aes_bmp.py` (kulcsszétválasztással) és a 4. előadás sebezhetőségeiből. |

---

## 3. A Kriptográfiai Csomag Felépítése (`.medvault`)

A titkosított és digitálisan aláírt orvosi állomány egyetlen kompakt bináris csomagba van ágyazva:

```text
+------------+-------------+-------------+----------+------------------+-------------------+--------------+------------------+
| MAGIC (4B) | SALT (16B)  | NONCE (12B) | LEN (2B) | AAD FEJLÉC (var) | REJTJELSZÖVEG     | GMAC TAG(16B)| RSA-PSS SIG(256B)|
| b"MEDV"    | Argon2id só | GCM IV      | AAD hossz| Nyílt Páciens ID | AES-GCM adatok    | 128 bit MAC  | Orvosi aláírás   |
+------------+-------------+-------------+----------+------------------+-------------------+--------------+------------------+
|<------------------------ Teljes fejléc AAD-ként védve ------------------------>|
|<------------------------------------ Külső RSA-PSS (SHA-256) aláírással védve ------------------------------------>|
```

---

## 4. Telepítés és Indítás

A projekt tiszta Python alapú, Streamlit grafikus felülettel:

```bash
# 1. Függőségek telepítése
pip install -r requirements.txt

# 2. MedVault alkalmazás indítása
python -m streamlit run app.py
```

---

## 5. A 10 Perces Védési Forgatókönyv (Dr. Márton Gyöngyvér Tanárnőnél)

Amikor a laborórán bemutatod a projektet:

1. **0–2. perc (A Valós Orvosi Helyzet & A Történet):**
   > *"A telemedicinában a legnagyobb kockázat nemcsak az adatszivárgás, hanem a rosszindulatú adatmanipuláció, ahol 1 átírt laborérték páciens halálát okozza. A MedVault ezt oldja meg a St. Camillus Onkológiai Központ kiber-incidensén keresztül."*
2. **2–4. perc (Kriptográfiai Megoldás):**
   * Nyisd meg a kódot és mutasd meg az **Argon2id** 64 MB-os memóriaköltségét (`crypto/kdf.py`).
   * Magyarázd el az **AES-256-GCM** működését (`crypto/cipher.py`) és az **Associated Data (AAD)** szerepét.
3. **4–8. perc (A Kripto Labor – Az Élő Támadások a Képernyőn):**
   * **1. Demó:** Kattints az *"Összehasonlító szimuláció futtatása"* gombra:  
     *"Nézze tanárnő: az ECB módban a bordák és a daganat kontúrja tisztán kivehető a titkosított képen! (Ez a tanárnő órai pingvin-kódjának orvosi párja). Ezzel szemben az AES-GCM tökéletes kriptográfiai diffúziót ad."*
   * **2. Demó:** Kattints az *"1 Bit átfordítása a fájlban"*, majd a *"Manipulált fájl visszafejtése"* gombra:  
     A rendszer azonnal eldobja `GMAC` integritási hibával: a páciens megmenekült a hamisított diagnózistól!
   * **3. Demó:** Kattints a *"Fejléc átírása (#MED-9999-REPLACED)"*, majd az *"Átírt fejlécű csomag visszafejtése"* gombra:  
     A GMAC ezt is detektálja az AAD védelem miatt!
4. **8–10. perc (Kérdések & Zárszó):**
   * Mutasd meg a rövid, letisztult modulokat (`crypto/kdf.py`, `crypto/cipher.py`, `crypto/attacks.py`).
