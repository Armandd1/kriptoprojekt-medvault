import html
import io
import os
import streamlit as st
from PIL import Image

from crypto.kdf import calculate_entropy
from crypto.cipher import (
    encrypt_medical_record,
    decrypt_medical_record,
    verify_vault_signature,
    unpack_raw_vault,
    CryptoIntegrityError,
    InvalidVaultFormatError,
)
from crypto.attacks import (
    simulate_bmp_ecb_leak,
    inject_bit_flip,
    tamper_patient_id_header,
)


st.set_page_config(page_title="MedVault", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .card {
        background: #ffffff; border: 1px solid #e2e8f0;
        border-radius: 12px; padding: 16px 20px; margin-bottom: 14px;
    }
    .badge {
        display: inline-block; padding: 3px 10px; border-radius: 6px;
        font-size: 0.78rem; font-weight: 600; margin-right: 6px;
    }
    .badge-blue  { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    .badge-green { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
    .badge-amber { background: #fffbeb; color: #b45309; border: 1px solid #fde68a; }
    .badge-red   { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    div.stButton > button {
        background-color: #2563eb !important; color: #ffffff !important;
        border: none !important; border-radius: 8px !important; font-weight: 600 !important;
    }
    div.stButton > button:hover { background-color: #1d4ed8 !important; }
</style>
""", unsafe_allow_html=True)

VAULT_DIR = os.path.join(os.path.dirname(__file__), "storage", "vault")
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)


def sanitize_filename(p_id: str, file_name: str) -> str:
    """Biztonságos fájlnév képzése a mentéshez."""
    clean_id = "".join(c for c in p_id if c.isalnum() or c in ("-", "_")) or "MED"
    clean_file = os.path.basename(file_name) or "lelet.bin"
    return f"{clean_id}_{clean_file}.medvault"


tab1, tab2, tab3 = st.tabs(["Titkosítás", "Visszafejtés", "Kripto Labor"])


# 1. FÜL: TITKOSÍTÁS ÉS ALÁÍRÁS
with tab1:
    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.markdown("##### Páciens és Kulcs")
        p_id = st.text_input("Páciens ID:", value="#MED-8042")
        p_name = st.text_input("Páciens Neve:", value="Kovács Péter")
        master_password = st.text_input("Mesterjelszó:", type="password", value="DrKovacs#2026!Oncology")

        ent = calculate_entropy(master_password)
        st.markdown(
            f"<span class='badge badge-blue'>Argon2id (64 MB, t=3, p=4)</span>"
            f"<span class='badge {ent['badge_class']}'>Entrópia: {ent['entropy']} bit ({ent['strength']})</span>",
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown("##### Orvosi Fájl")
        source_choice = st.selectbox(
            "Forrás kiválasztása:",
            [
                "Minta CT / Röntgen felvétel (sample_chest_xray.bmp)",
                "Minta Onkológiai Zárójelentés (sample_lab_report.txt)",
                "Saját fájl feltöltése",
            ],
        )

        file_bytes, file_name = None, ""
        if source_choice.startswith("Minta CT"):
            file_name = "sample_chest_xray.bmp"
            sample_path = os.path.join(ASSETS_DIR, file_name)
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as f:
                    file_bytes = f.read()
                st.image(Image.open(io.BytesIO(file_bytes)), width=180, caption=file_name)
        elif source_choice.startswith("Minta Onkológiai"):
            file_name = "sample_lab_report.txt"
            sample_path = os.path.join(ASSETS_DIR, file_name)
            if os.path.exists(sample_path):
                with open(sample_path, "rb") as f:
                    file_bytes = f.read()
                st.text_area("Előnézet:", file_bytes.decode("utf-8", errors="replace"), height=150, disabled=True)
        else:
            uploaded = st.file_uploader("Fájl feltöltése:", type=["bmp", "png", "jpg", "pdf", "txt"])
            if uploaded:
                file_bytes, file_name = uploaded.read(), uploaded.name

    if st.button("Titkosítás, Aláírás és Mentés (.medvault)"):
        if not file_bytes or not master_password:
            st.error("Adj meg minden szükséges adatot!")
        else:
            metadata = {
                "patient_id": p_id,
                "patient_name": p_name,
                "original_filename": os.path.basename(file_name),
            }
            vault_bytes = encrypt_medical_record(file_bytes, master_password, metadata)
            safe_name = sanitize_filename(p_id, file_name)
            with open(os.path.join(VAULT_DIR, safe_name), "wb") as f:
                f.write(vault_bytes)

            raw = unpack_raw_vault(vault_bytes)
            st.success(f"Sikeresen titkosítva, aláírva és elmentve: {safe_name}")
            st.markdown(
                f"<div class='card' style='font-size: 0.85rem; color: #475569;'>"
                f"<strong>Kripto Fejléc:</strong> Só (16B): <code>{raw['salt'].hex()[:16]}...</code> | "
                f"Nonce (12B): <code>{raw['nonce'].hex()}</code> | "
                f"GMAC Tag (16B): <code>{raw['tag'].hex()[:16]}...</code> | "
                f"RSA-PSS Aláírás (256B): <code>{raw['signature'].hex()[:16]}...</code>"
                f"</div>",
                unsafe_allow_html=True,
            )
            st.download_button("Titkosított Csomag Letöltése (.medvault)", vault_bytes, file_name=safe_name)


# 2. FÜL: VISSZAFEJTÉS ÉS HITELESÍTÉS
with tab2:
    vault_files = sorted(f for f in os.listdir(VAULT_DIR) if f.endswith(".medvault"))

    if not vault_files:
        st.info("Nincs még titkosított állomány a tárolóban.")
    else:
        col_v1, col_v2 = st.columns(2, gap="large")

        with col_v1:
            st.markdown("##### Kiválasztott Csomag")
            chosen_file = st.selectbox("Tárolt leletek:", vault_files)
            with open(os.path.join(VAULT_DIR, chosen_file), "rb") as f:
                vault_data = f.read()

            try:
                sig_valid = verify_vault_signature(vault_data)
                raw_info = unpack_raw_vault(vault_data)
                raw_meta = raw_info["aad_dict"]

                esc_name = html.escape(str(raw_meta.get("patient_name", "")))
                esc_id = html.escape(str(raw_meta.get("patient_id", "")))
                esc_fname = html.escape(str(raw_meta.get("original_filename", "")))
                sig_badge = (
                    "<span class='badge badge-blue'>✍️ Külső RSA-PSS aláírás: Érvényes</span>"
                    if sig_valid
                    else "<span class='badge badge-red'>🚨 Külső RSA-PSS aláírás: ÉRVÉNYTELEN!</span>"
                )

                st.markdown(
                    f"<div class='card' style='font-size: 0.9rem;'>"
                    f"<div style='margin-bottom: 8px;'>{sig_badge}</div>"
                    f"<strong>Páciens (AAD fejléc):</strong> {esc_name} (<code>{esc_id}</code>)<br>"
                    f"<strong>Eredeti fájlnév:</strong> {esc_fname}<br>"
                    f"<span style='font-size: 0.8rem; color: #64748b;'>"
                    f"GMAC Tag: <code>{raw_info['tag'].hex()}</code></span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            except InvalidVaultFormatError as fmt_err:
                st.error(str(fmt_err))

        with col_v2:
            st.markdown("##### Megnyitás")
            dec_pwd = st.text_input("Jelszó:", type="password", value="DrKovacs#2026!Oncology", key="v_pwd")
            open_btn = st.button("Hitelesítés és Megnyitás")

        if open_btn:
            try:
                decrypted, meta = decrypt_medical_record(vault_data, dec_pwd)
                st.markdown(
                    "<div style='margin-bottom: 12px;'>"
                    "<span class='badge badge-blue'>✍️ Érvényes RSA-2048 (PSS) Digitális Aláírás</span>"
                    "<span class='badge badge-green'>✅ Érvényes GMAC címke (Sértetlen lelet és AAD fejléc)</span>"
                    "</div>",
                    unsafe_allow_html=True,
                )

                orig_fname = os.path.basename(str(meta.get("original_filename", "lelet.bin")))
                if orig_fname.lower().endswith((".bmp", ".png", ".jpg", ".jpeg")):
                    st.image(Image.open(io.BytesIO(decrypted)), width=320, caption=orig_fname)
                elif orig_fname.lower().endswith(".txt"):
                    st.text_area("Lelet tartalma:", decrypted.decode("utf-8", errors="replace"), height=220)
                else:
                    st.info(f"Bináris dokumentum sikeresen visszafejtve ({len(decrypted)} bájt): {orig_fname}")

                st.download_button("Visszafejtett Eredeti Fájl Letöltése", decrypted, file_name=orig_fname)
            except (CryptoIntegrityError, InvalidVaultFormatError) as err:
                st.markdown(
                    f"<div style='margin-bottom: 12px;'>"
                    f"<span class='badge badge-red'>🚨 {html.escape(str(err))}</span>"
                    f"</div>",
                    unsafe_allow_html=True,
                )


# 3. FÜL: KRIPTO LABOR (TÁMADÁSSZIMULÁCIÓK)
with tab3:
    # 1. Képi szivárgás (ECB vs GCM)
    with st.expander("1. Orvosi Kép ECB Szivárgása", expanded=True):
        st.write("Az ECB mód determinisztikus jellege miatt a daganat és a csontok kontúrja rejtjelezve is látható marad.")
        sample_xray = os.path.join(ASSETS_DIR, "sample_chest_xray.bmp")

        if st.button("Összehasonlító szimuláció futtatása") and os.path.exists(sample_xray):
            with open(sample_xray, "rb") as f:
                raw_bmp = f.read()
            leak = simulate_bmp_ecb_leak(raw_bmp)

            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("**1. Eredeti Röntgen**")
                st.image(Image.open(io.BytesIO(raw_bmp)), use_container_width=True)
            with c2:
                st.markdown("**2. Naiv AES-ECB (Szivárgás)**")
                st.image(Image.open(io.BytesIO(leak["ecb_bmp"])), use_container_width=True)
                st.markdown("<span class='badge badge-red'>Körvonal látható</span>", unsafe_allow_html=True)
            with c3:
                st.markdown("**3. AES-256-GCM (Védett)**")
                st.image(Image.open(io.BytesIO(leak["gcm_bmp"])), use_container_width=True)
                st.markdown("<span class='badge badge-green'>Kriptográfiai zaj</span>", unsafe_allow_html=True)

    if "lab_ref_vault" not in st.session_state:
        st.session_state["lab_ref_vault"] = encrypt_medical_record(
            b"DIAGNOSIS: Adenocarcinoma pulmonis. CEA: 14.8 ng/mL",
            "DrKovacs#2026!Oncology",
            {"patient_id": "#MED-8042", "patient_name": "Kovács Péter", "original_filename": "sample_lab_report.txt"},
        )
    orig_vbytes = st.session_state["lab_ref_vault"]

    # 2. Bit-Flipping manipuláció
    with st.expander("2. Bit-Flipping Manipuláció & GMAC Védelem"):
        st.write("1 bit módosítása a rejtjelezett állományban (`XOR 0x01`). Az AES-GCM GMAC címkéje azonnal elutasítja.")

        cb1, cb2 = st.columns(2)
        with cb1:
            if st.button("1 Bit átfordítása a fájlban"):
                t_bytes, d = inject_bit_flip(orig_vbytes)
                st.session_state["t_bytes"] = t_bytes
                st.session_state["t_details"] = d

            if "t_details" in st.session_state:
                d = st.session_state["t_details"]
                st.markdown(
                    f"<div class='card' style='font-size: 0.85rem;'>"
                    f"<strong>Módosított pozíció:</strong> <code>{d['target_index']}</code>. bájt<br>"
                    f"<strong>Hexa:</strong> <code>{d['original_byte_hex']}</code> &rarr; <code>{d['tampered_byte_hex']}</code> "
                    f"(<code>{d['original_bin']}</code> &rarr; <code>{d['tampered_bin']}</code>)"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        with cb2:
            if "t_bytes" in st.session_state and st.button("Manipulált fájl visszafejtése"):
                try:
                    decrypt_medical_record(
                        st.session_state["t_bytes"],
                        "DrKovacs#2026!Oncology",
                        verify_signature=False,
                    )
                    st.error("Nem vette észre a hibát!")
                except CryptoIntegrityError:
                    st.markdown(
                        "<span class='badge badge-green'>🛡️ Sikeres védelem: GMAC hiba miatt a megnyitás megtagadva!</span>",
                        unsafe_allow_html=True,
                    )

    # 3. Fejléc (AAD) manipuláció
    with st.expander("3. Páciens Fejléc Manipuláció & AAD Védelem"):
        st.write("A páciens azonosító átírása a nyílt fejlécben. A GMAC címke a nyílt fejlécet is védi AAD-ként.")

        ca1, ca2 = st.columns(2)
        with ca1:
            if st.button("Fejléc átírása (#MED-9999-REPLACED)"):
                h_bytes, hd = tamper_patient_id_header(orig_vbytes, "#MED-9999-REPLACED")
                st.session_state["h_bytes"] = h_bytes
                st.session_state["h_details"] = hd

            if "h_details" in st.session_state:
                hd = st.session_state["h_details"]
                st.markdown(
                    f"<div class='card' style='font-size: 0.85rem;'>"
                    f"<strong>Nyílt fejléc (AAD) módosítva:</strong><br>"
                    f"<code>{html.escape(hd['old_patient_id'])}</code> &rarr; <code>{html.escape(hd['new_patient_id'])}</code>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

        with ca2:
            if "h_bytes" in st.session_state and st.button("Átírt fejlécű csomag visszafejtése"):
                try:
                    decrypt_medical_record(
                        st.session_state["h_bytes"],
                        "DrKovacs#2026!Oncology",
                        verify_signature=False,
                    )
                    st.error("Nem vette észre a hibát!")
                except CryptoIntegrityError:
                    st.markdown(
                        "<span class='badge badge-green'>🛡️ Sikeres védelem: AAD/GMAC hiba miatt a megnyitás megtagadva!</span>",
                        unsafe_allow_html=True,
                    )
