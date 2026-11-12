# ami_encoder.py
# Mengubah CIPHERTEXT menjadi BINER (bit), dan membuat sinyal Bipolar AMI untuk grafik.
#
# Urutan yang dipakai aplikasi:
#   teks asli -> dienkripsi (RSA, public key penerima) -> ciphertext (bytes)
#   -> di-encode menjadi BINER (deretan 0 dan 1)  <- inilah yang disimpan di database
# Sinyal Bipolar AMI HANYA untuk tampilan grafik: dihitung dari biner itu saat halaman
# dibuka dan tidak disimpan. Tidak ada start bit, end bit, maupun parity.
#
# Bipolar AMI: bit 0 = 0 V, bit 1 bergantian +V / -V (bit 1 pertama = +V).
# Grafiknya digambar di browser (static/js/main.js), bukan di server.


# ---------- bytes <-> bit ----------
def bytes_to_bits(data: bytes) -> str:
    """Setiap byte menjadi 8 bit (MSB dulu)."""
    return "".join(f"{byte:08b}" for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("jumlah bit bukan kelipatan 8")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


# ---------- Bipolar AMI ----------
def ami_encode(bits: str):
    """Bit 0 -> 0, bit 1 -> +1 / -1 bergantian (mulai dari +1)."""
    levels = []
    last = -1
    for bit in bits:
        if bit == "0":
            levels.append(0)
        else:
            last = -last
            levels.append(last)
    return levels


def build_signal(bits: str) -> dict:
    """Biner -> level AMI (hanya untuk grafik)."""
    levels = ami_encode(bits)
    return {"levels": levels, "total_bits": len(bits)}


def levels_to_text(levels) -> str:
    """Level -> teks pendek untuk dikirim ke browser: 0, + (=+V), - (=-V)."""
    return "".join("0" if v == 0 else ("+" if v > 0 else "-") for v in levels)


# ---------- Biner yang disimpan di database ----------
def encode_binary(cipher: bytes) -> str:
    """Ciphertext (bytes) -> teks biner, misalnya '0100110101...' (8 bit per byte)."""
    return bytes_to_bits(cipher)


def decode_binary(text: str) -> bytes:
    """
    Teks biner -> ciphertext (bytes).
    Melempar ValueError jika kosong, berisi selain 0/1, atau jumlah bit bukan kelipatan 8.
    """
    if not text or set(text) - set("01"):
        raise ValueError("biner kosong atau berisi karakter selain 0 dan 1")
    return bits_to_bytes(text)
