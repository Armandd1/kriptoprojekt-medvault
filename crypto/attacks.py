"""
Kriptográfiai Támadásszimulációk (4. és 5. előadás)
1. Orvosi BMP kép ECB-szivárgása vs. AES-GCM (4aes_bmp.py alapján)
2. Bit-flipping támadás a rejtjelszöveg ellen
3. Páciens-azonosító átírása a nyílt AAD fejlécben
"""

import json
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from .cipher import MAGIC_BYTES, TAG_LENGTH, SIGNATURE_LENGTH, unpack_raw_vault


def simulate_bmp_ecb_leak(bmp_bytes: bytes) -> dict:
    """Megőrzi a BMP fejlécet, és összehasonlítja a naiv AES-ECB és a biztonságos AES-GCM képtitkosítást."""
    if len(bmp_bytes) < 54 or not bmp_bytes.startswith(b"BM"):
        raise ValueError("Nem érvényes BMP képfájl.")

    pixel_offset = struct.unpack("<I", bmp_bytes[10:14])[0]
    if pixel_offset < 54 or pixel_offset >= len(bmp_bytes):
        pixel_offset = 54

    header = bmp_bytes[:pixel_offset]
    pixel_data = bmp_bytes[pixel_offset:]

    # Külön 256 bites kulcs a két üzemmódhoz (kulcsszétválasztás)
    ecb_key = get_random_bytes(32)
    gcm_key = get_random_bytes(32)

    # 1. AES-ECB: 16 bájtos blokktitkosító (padding kell; azonos képpont-blokkok azonosak maradnak!)
    ecb_cipher = AES.new(ecb_key, AES.MODE_ECB)
    ecb_encrypted = ecb_cipher.encrypt(pad(pixel_data, AES.block_size))
    ecb_bmp = header + ecb_encrypted[: len(pixel_data)]

    # 2. AES-GCM: belső CTR számláló mód (nem kell padding; teljes kriptográfiai diffúzió)
    gcm_cipher = AES.new(gcm_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    gcm_encrypted = gcm_cipher.encrypt(pixel_data)
    gcm_bmp = header + gcm_encrypted

    return {"ecb_bmp": ecb_bmp, "gcm_bmp": gcm_bmp}


def inject_bit_flip(vault_bytes: bytes, byte_offset_from_end: int = 25) -> tuple[bytes, dict]:
    """Átfordít 1 bitet (XOR 0x01) a rejtjelezett orvosi állományban."""
    raw = unpack_raw_vault(vault_bytes)
    ct_start = raw["ciphertext_offset"]
    ct_end = len(vault_bytes) - TAG_LENGTH - SIGNATURE_LENGTH
    target_idx = min(max(ct_start, ct_end - byte_offset_from_end), ct_end - 1)

    vault_array = bytearray(vault_bytes)
    original_byte = vault_array[target_idx]
    flipped_byte = original_byte ^ 0x01
    vault_array[target_idx] = flipped_byte

    details = {
        "target_index": target_idx,
        "original_byte_hex": f"0x{original_byte:02x}",
        "tampered_byte_hex": f"0x{flipped_byte:02x}",
        "original_bin": f"{original_byte:08b}",
        "tampered_bin": f"{flipped_byte:08b}",
    }
    return bytes(vault_array), details


def tamper_patient_id_header(vault_bytes: bytes, new_patient_id: str) -> tuple[bytes, dict]:
    """Átírja a páciens azonosítót a nyílt AAD fejlécben, miközben a rejtjelszöveg és a tag változatlan marad."""
    raw = unpack_raw_vault(vault_bytes)
    metadata = dict(raw["aad_dict"])
    old_id = metadata.get("patient_id", "ISMERETLEN")
    metadata["patient_id"] = new_patient_id

    new_aad_bytes = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")
    new_header = (
        MAGIC_BYTES
        + raw["salt"]
        + raw["nonce"]
        + struct.pack(">H", len(new_aad_bytes))
        + new_aad_bytes
    )
    tampered_vault = new_header + raw["ciphertext"] + raw["tag"] + raw["signature"]

    return tampered_vault, {"old_patient_id": old_id, "new_patient_id": new_patient_id}
