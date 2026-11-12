# encryption.py
# Tugas file ini: pasangan kunci (public/private) dan enkripsi pesan dengan RSA.
# Tidak memakai AES. Cukup RSA, sehingga alurnya sederhana:
#   - Setiap pengguna punya pasangan kunci. PUBLIC key disimpan di database,
#     PRIVATE key dipegang pengguna sendiri (tidak disimpan server).
#   - Pengirim mengenkripsi pesan dengan PUBLIC key penerima.
#   - Hanya penerima dengan PRIVATE key yang cocok yang bisa membukanya,
#     seperti pintu yang hanya bisa dibuka anak kunci yang pas.
# Hasil enkripsi (ciphertext) kemudian di-encode menjadi sinyal Bipolar AMI (ami_encoder.py).
# Penyusup yang mengambil data dari database hanya mendapat sinyal hasil encode itu.
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECURE_DIR = os.path.join(BASE_DIR, "secure_data")   # tempat secret key Flask

KEY_SIZE = 2048                       # bit; satu blok ciphertext = 256 byte


class PrivateKeyError(Exception):
    """Private key tidak valid atau bukan pasangan dari public key akun ini."""


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)


def generate_keypair():
    """Buat pasangan kunci RSA. Mengembalikan (private_pem, public_pem) berupa teks."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    private_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()
    return private_pem, _public_pem(key.public_key())


def _public_pem(public_key) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def key_fingerprint(public_pem: str) -> str:
    """Sidik jari singkat public key (untuk dicocokkan dengan mata)."""
    import hashlib
    return hashlib.sha256(public_pem.strip().encode()).hexdigest()[:16]


def public_from_private(private_pem: str) -> str:
    """Ambil public key dari sebuah private key (untuk memeriksa apakah kuncinya cocok)."""
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        return _public_pem(private_key.public_key())
    except Exception as err:          # format salah, bukan RSA, dsb.
        raise PrivateKeyError("private key tidak valid") from err


def _chunk_size(key_bytes: int) -> int:
    """Jumlah byte teks maksimal per blok untuk RSA-OAEP(SHA-256)."""
    return key_bytes - 2 * 32 - 2


def encrypt_message(plaintext: bytes, public_pem: str) -> bytes:
    """
    Enkripsi dengan PUBLIC key penerima. RSA hanya mampu mengenkripsi potongan kecil,
    jadi teks dipecah per blok; setiap blok menjadi 256 byte ciphertext.
    """
    public_key = serialization.load_pem_public_key(public_pem.encode())
    size = _chunk_size(public_key.key_size // 8)
    blocks = [plaintext[i:i + size] for i in range(0, len(plaintext), size)]
    return b"".join(public_key.encrypt(block, _oaep()) for block in blocks)


def decrypt_message(cipher: bytes, private_pem: str):
    """
    Dekripsi dengan PRIVATE key penerima. Melempar:
      PrivateKeyError -> private key tidak valid
      ValueError      -> ciphertext rusak / dimanipulasi (OAEP menolak)
    Mengembalikan (plaintext_bytes, info_proses).
    """
    try:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        key_bytes = private_key.key_size // 8
    except Exception as err:
        raise PrivateKeyError("private key tidak valid") from err
    if not cipher or len(cipher) % key_bytes != 0:
        raise ValueError("panjang ciphertext tidak sesuai ukuran blok")

    blocks = [cipher[i:i + key_bytes] for i in range(0, len(cipher), key_bytes)]
    plain = b"".join(private_key.decrypt(block, _oaep()) for block in blocks)  # ValueError jika rusak
    info = {"blocks": len(blocks), "block_bytes": key_bytes,
            "cipher_len": len(cipher), "cipher_hex": cipher.hex()}
    return plain, info
