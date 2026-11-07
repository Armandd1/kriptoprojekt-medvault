"""
Argon2id kulcslevezetés (KDF) és jelszó-entrópia számítás (2. és 3. előadás)
"""

import math
import secrets
import string
import unicodedata
from argon2.low_level import hash_secret_raw, Type


ARGON2_TIME_COST = 3          # 3 iteráció
ARGON2_MEMORY_COST = 65536    # 64 MB RAM (GPU/ASIC szótártámadás ellen)
ARGON2_PARALLELISM = 4        # 4 párhuzamos szál
ARGON2_HASH_LEN = 32          # 256 bites (32 bájtos) AES kulcs
SALT_LENGTH = 16              # 128 bites (16 bájtos) véletlen só


def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Mesterjelszóból és 16 bájtos sóból 256 bites AES kulcsot vezet le Argon2id-vel."""
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)
    elif len(salt) != SALT_LENGTH:
        raise ValueError(f"A sónak {SALT_LENGTH} bájtosnak kell lennie.")

    secret_bytes = unicodedata.normalize("NFC", password).encode("utf-8")

    derived_key = hash_secret_raw(
        secret=secret_bytes,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    return derived_key, salt


def calculate_entropy(password: str) -> dict:
    """Jelszó-entrópia számítása a 2. előadás képlete alapján: H = L * log2(N)"""
    length = len(password)
    if length == 0:
        return {"entropy": 0.0, "strength": "Üres", "badge_class": "badge-red"}

    charset_size = (
        (26 if any(c in string.ascii_lowercase for c in password) else 0)
        + (26 if any(c in string.ascii_uppercase for c in password) else 0)
        + (10 if any(c in string.digits for c in password) else 0)
        + (32 if any(c in string.punctuation for c in password) else 0)
        + (1 if " " in password else 0)
        + (18 if any(ord(c) > 127 for c in password) else 0)
    )
    entropy = length * math.log2(max(charset_size, 2))

    if entropy < 40:
        strength, badge_class = "Gyenge", "badge-red"
    elif entropy < 65:
        strength, badge_class = "Közepes", "badge-amber"
    else:
        strength, badge_class = "Erős", "badge-green"

    return {
        "entropy": round(entropy, 2),
        "strength": strength,
        "badge_class": badge_class,
    }
