"""
Minta orvosi röntgenkép (BMP) és szöveges zárójelentés generáló segédszkript
"""

import os
from PIL import Image, ImageDraw


def generate_chest_xray_bmp(output_path: str) -> None:
    """Létrehoz egy 300x300-as röntgen BMP képet nagy egyszínű területekkel az ECB szivárgás bemutatásához."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img = Image.new("RGB", (300, 300), color=(15, 15, 20))
    draw = ImageDraw.Draw(img)

    draw.ellipse([30, 20, 270, 280], outline=(70, 70, 85), width=4)
    draw.ellipse([50, 50, 130, 220], fill=(25, 25, 35), outline=(90, 90, 110), width=3)
    draw.ellipse([170, 50, 250, 220], fill=(25, 25, 35), outline=(90, 90, 110), width=3)
    draw.rectangle([140, 30, 160, 270], fill=(180, 180, 190))

    for y in range(70, 220, 25):
        draw.arc([40, y, 145, y + 35], start=180, end=360, fill=(160, 160, 175), width=4)
        draw.arc([155, y, 260, y + 35], start=180, end=360, fill=(160, 160, 175), width=4)

    draw.ellipse([115, 140, 175, 210], fill=(130, 130, 145))
    draw.ellipse([75, 100, 110, 135], fill=(245, 245, 255), outline=(255, 100, 100), width=2)

    draw.text((10, 10), "ST. CAMILLUS ONCOLOGY - CT/X-RAY", fill=(120, 120, 130))
    draw.text((10, 280), "PATIENT: #MED-8042 (FOV: 300mm)", fill=(120, 120, 130))
    draw.text((80, 85), "NODULE", fill=(255, 120, 120))

    img.save(output_path, format="BMP")


def generate_sample_report(output_path: str) -> None:
    """Létrehoz egy minta szöveges onkológiai zárójelentést."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    report_text = """===================================================================
ST. CAMILLUS ONKOLÓGIAI ÉS TÁVDIAGNOSZTIKAI KÖZPONT
SZIGORÚAN BIZALMAS ORVOSI ZÁRÓJELENTÉS
===================================================================

PÁCIENS ADATAI:
- Név: Kovács Péter
- Páciens Azonosító: #MED-8042
- Kezelőorvos: Dr. Kovács Béla Ph.D., vezető onkológus sebész
- Osztály: Mellkassebészeti és Onkológiai Klinika

KLINIKAI DIAGNÓZIS ÉS LELET:
- Vizsgálat: Alacsony dózisú mellkasi CT és szövettani biopszia
- Megállapítás: A bal tüdőmező felső lebenyében 22x18 mm-es szolid nodulus.
- Szövettan: Adenocarcinoma pulmonis (Malignus elváltozás).
- Daganatmarker CEA szint: 14.8 ng/mL (Referencia: 0.0 - 3.4 ng/mL)
- Vércukorszint: 5.4 mmol/L (Normál)

TERÁPIÁS DÖNTÉS:
- Műtéti indikáció: SÜRGŐS VATS bal felső lobectomia.
===================================================================
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)


if __name__ == "__main__":
    generate_chest_xray_bmp("assets/sample_chest_xray.bmp")
    generate_sample_report("assets/sample_lab_report.txt")
