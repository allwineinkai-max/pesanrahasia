# security.py
# Tugas file ini: pencatatan log dan deteksi akses tidak sah.
from datetime import datetime, timezone
from location import collect_request_info, distance_km

# Jenis kejadian yang dihitung sebagai "percobaan akses tidak sah"
UNAUTHORIZED_EVENTS = (
    "akses_pesan_orang_lain",
    "manipulasi_pesan",
    "private_key_salah",
)

EVENT_LABELS = {
    "akses_pesan_orang_lain": "Mencoba membuka pesan orang lain",
    "manipulasi_pesan": "Manipulasi / data pesan rusak",
    "pesan_dibaca": "Pesan dibaca penerima",
    "login_gagal": "Login gagal",
    "izin_lokasi_ditolak": "Verifikasi lokasi ditolak / gagal",
    "private_key_salah": "Private key salah / tidak cocok",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log_event(db, event_type, detail, user_id=None, message_id=None,
              status="info", lookup=True, geo=None) -> int:
    """Catat satu kejadian ke tabel security_logs. geo = hasil GPS (opsional)."""
    info = collect_request_info(lookup=lookup)
    lat = lon = acc = addr = None
    if geo:
        lat, lon, acc, addr = geo["lat"], geo["lon"], geo["accuracy"], geo["address"]
        extra = []
        if info.get("ip_lat") is not None:
            km = distance_km(lat, lon, info["ip_lat"], info["ip_lon"])
            extra.append(f"GPS berjarak {km:.0f} km dari titik IP" +
                         (" (titik IP tidak dapat diandalkan, pakai GPS)" if km > 25 else ""))
        if acc and acc > 1000:
            extra.append(f"akurasi GPS rendah (±{acc / 1000:.1f} km): perangkat tanpa GPS memakai "
                         "perkiraan Wi-Fi/IP")
        if extra:
            info["location_note"] = ((info["location_note"] or "") + " · " + " · ".join(extra)).strip(" ·")
    cur = db.execute(
        """INSERT INTO security_logs
           (message_id, user_id, event_type, detail, status, ip_address,
            browser, os, location_text, location_note, ip_lat, ip_lon,
            latitude, longitude, gps_accuracy, gps_address, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (message_id, user_id, event_type, detail, status, info["ip"],
         info["browser"], info["os"], info["location"], info["location_note"],
         info["ip_lat"], info["ip_lon"], lat, lon, acc, addr, now_utc()),
    )
    db.commit()
    return cur.lastrowid


def log_violation(db, event_type, detail, user_id, message_id, geo=None) -> int:
    """
    Catat akses tidak sah sebagai 'diblokir'. Pesan TIDAK diubah atau dihapus.
    Mengembalikan ID log pelanggaran.
    """
    return log_event(db, event_type, detail, user_id, message_id,
                     status="diblokir", lookup=True, geo=geo)


def security_status(unauthorized_last_24h: int):
    """Status keamanan sistem untuk dashboard: (teks, kelas_warna)."""
    if unauthorized_last_24h == 0:
        return "AMAN", "safe"
    return f"WASPADA ({unauthorized_last_24h} percobaan dalam 24 jam)", "danger"
