"""
AES-256-GCM hitelesített titkosítás (AEAD) + RSA-PSS digitális aláírás (5. és 6. előadás)

A .medvault csomag bináris felépítése:
[MEDV (4B)] + [Salt (16B)] + [Nonce (12B)] + [AAD hossz (2B)] + [AAD JSON] + [Ciphertext] + [GMAC Tag (16B)] + [RSA-PSS Aláírás (256B)]
"""

import json
import os
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from .kdf import derive_key, SALT_LENGTH


MAGIC_BYTES = b"MEDV"
NONCE_LENGTH = 12       # 96 bites GCM számláló-kezdet (Nonce)
TAG_LENGTH = 16         # 128 bites GMAC hitelesítő címke
RSA_BITS = 2048         # 2048 bites RSA kulcspár
SIGNATURE_LENGTH = 256  # 256 bájtos RSA-PSS digitális aláírás

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "keys")
PRIV_KEY_PATH = os.path.join(KEYS_DIR, "private_key_RSA.pem")
PUB_KEY_PATH = os.path.join(KEYS_DIR, "public_key_RSA.pem")
KEY_PASSPHRASE = os.getenv("MEDVAULT_KEY_PASSWORD", "DrKovacs#RSAKey!2026")


class CryptoIntegrityError(Exception):
    """GMAC vagy RSA-PSS integritási hiba."""


class InvalidVaultFormatError(Exception):
    """Érvénytelen .medvault fájlformátum."""


def _ensure_keypair_exists() -> None:
    """Első futáskor legenerálja a PKCS#8-cal védett 2048 bites RSA kulcspárt (6. előadás rsaOAEP.py alapján)."""
    if os.path.exists(PRIV_KEY_PATH) or os.path.exists(PUB_KEY_PATH):
        return

    os.makedirs(KEYS_DIR, exist_ok=True)
    key = RSA.generate(RSA_BITS)

    encrypted_priv = key.export_key(
        passphrase=KEY_PASSPHRASE,
        pkcs=8,
        protection="PBKDF2WithHMAC-SHA512AndAES256-CBC",
    )
    with open(PRIV_KEY_PATH, "wb") as f:
        f.write(encrypted_priv)
    with open(PUB_KEY_PATH, "wb") as f:
        f.write(key.public_key().export_key())


def load_signing_key() -> RSA.RsaKey:
    """Betölti az orvos PKCS#8 jelszóval védett privát aláíró kulcsát."""
    _ensure_keypair_exists()
    with open(PRIV_KEY_PATH, "rb") as f:
        return RSA.import_key(f.read(), passphrase=KEY_PASSPHRASE)


def load_public_key() -> RSA.RsaKey:
    """Kizárólag a publikus kulcsot tölti be az aláírás-ellenőrzéshez."""
    _ensure_keypair_exists()
    with open(PUB_KEY_PATH, "rb") as f:
        return RSA.import_key(f.read())


def verify_vault_signature(vault_bytes: bytes) -> bool:
    """Ellenőrzi a csomag végén lévő 256 bájtos RSA-PSS digitális aláírást a publikus kulccsal."""
    min_size = len(MAGIC_BYTES) + SALT_LENGTH + NONCE_LENGTH + 2 + TAG_LENGTH + SIGNATURE_LENGTH
    if len(vault_bytes) < min_size or not vault_bytes.startswith(MAGIC_BYTES):
        return False

    unsigned_packet = vault_bytes[:-SIGNATURE_LENGTH]
    signature = vault_bytes[-SIGNATURE_LENGTH:]
    try:
        pss.new(load_public_key()).verify(SHA256.new(unsigned_packet), signature)
        return True
    except (ValueError, TypeError):
        return False


def encrypt_medical_record(plaintext_data: bytes, password: str, metadata: dict) -> bytes:
    """Orvosi fájl titkosítása (AES-256-GCM + AAD fejléc) és aláírása (RSA-PSS)."""
    # 1. 256 bites AES kulcs levezetése Argon2id-vel (fájlonként új 16 bájtos sóval)
    key, salt = derive_key(password)
    nonce = get_random_bytes(NONCE_LENGTH)

    # 2. Nyílt fejléc (Associated Data - AAD) összeállítása
    aad_bytes = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")
    header = MAGIC_BYTES + salt + nonce + struct.pack(">H", len(aad_bytes)) + aad_bytes

    # 3. AES-256-GCM titkosítás és 16 bájtos GMAC címke képzése (a teljes fejléc AAD-ként védett)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_data)

    # 4. Külső RSA-PSS digitális aláírás (SHA-256 hash alapján)
    unsigned_packet = header + ciphertext + tag
    signature = pss.new(load_signing_key()).sign(SHA256.new(unsigned_packet))
    return unsigned_packet + signature


def unpack_raw_vault(vault_bytes: bytes) -> dict:
    """Szétbontja a bináris .medvault csomagot az egyes összetevőire."""
    min_size = len(MAGIC_BYTES) + SALT_LENGTH + NONCE_LENGTH + 2 + TAG_LENGTH + SIGNATURE_LENGTH
    if len(vault_bytes) < min_size or not vault_bytes.startswith(MAGIC_BYTES):
        raise InvalidVaultFormatError("Érvénytelen vagy sérült MedVault csomag.")

    offset = len(MAGIC_BYTES)
    salt = vault_bytes[offset : offset + SALT_LENGTH]
    offset += SALT_LENGTH

    nonce = vault_bytes[offset : offset + NONCE_LENGTH]
    offset += NONCE_LENGTH

    aad_len = struct.unpack(">H", vault_bytes[offset : offset + 2])[0]
    offset += 2

    if offset + aad_len + TAG_LENGTH + SIGNATURE_LENGTH > len(vault_bytes):
        raise InvalidVaultFormatError("Sérült fájlméret vagy fejléc hossz.")

    aad_bytes = vault_bytes[offset : offset + aad_len]
    offset += aad_len
    header = vault_bytes[:offset]

    tag_and_sig = TAG_LENGTH + SIGNATURE_LENGTH
    ciphertext = vault_bytes[offset:-tag_and_sig]
    tag = vault_bytes[-tag_and_sig:-SIGNATURE_LENGTH]
    signature = vault_bytes[-SIGNATURE_LENGTH:]

    try:
        aad_dict = json.loads(aad_bytes.decode("utf-8"))
    except Exception as exc:
        raise InvalidVaultFormatError("Sérült JSON metaadat a fejlécben.") from exc

    return {
        "header": header,
        "salt": salt,
        "nonce": nonce,
        "aad_bytes": aad_bytes,
        "aad_dict": aad_dict,
        "ciphertext": ciphertext,
        "tag": tag,
        "signature": signature,
        "ciphertext_offset": offset,
    }


def decrypt_medical_record(
    vault_bytes: bytes,
    password: str,
    verify_signature: bool = True,
) -> tuple[bytes, dict]:
    """Visszafejti a csomagot: 1. RSA-PSS ellenőrzés -> 2. Argon2id -> 3. AES-GCM + GMAC ellenőrzés."""
    # 1. Külső RSA-PSS aláírás ellenőrzése (még a lassú Argon2id futtatása előtt)
    if verify_signature and not verify_vault_signature(vault_bytes):
        unpack_raw_vault(vault_bytes)
        raise CryptoIntegrityError("KRIPTOGRÁFIAI HIBA: Érvénytelen RSA-PSS digitális aláírás!")

    raw = unpack_raw_vault(vault_bytes)

    # 2. 256 bites AES kulcs újraelőállítása a csomagban tárolt sóval
    key, _ = derive_key(password, salt=raw["salt"])

    # 3. AES-256-GCM visszafejtés és a 16 bájtos GMAC címke + AAD fejléc ellenőrzése
    cipher = AES.new(key, AES.MODE_GCM, nonce=raw["nonce"], mac_len=TAG_LENGTH)
    cipher.update(raw["header"])
    try:
        plaintext_data = cipher.decrypt_and_verify(raw["ciphertext"], raw["tag"])
    except ValueError as exc:
        raise CryptoIntegrityError(
            "KRIPTOGRÁFIAI HIBA: Érvénytelen GMAC címke (manipulált adat/fejléc vagy hibás jelszó)!"
        ) from exc

    return plaintext_data, raw["aad_dict"]
