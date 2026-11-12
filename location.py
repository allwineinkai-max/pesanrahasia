# location.py
# Tugas file ini: mengumpulkan info pengakses (IP, browser, OS) dan lokasinya.
#
# Lokasi dicari otomatis dari alamat IP, tanpa izin GPS dan tanpa tombol apa pun
# di sisi pengunjung. Hasilnya berupa kota / kecamatan, provinsi, negara, kode pos,
# dan koordinat tengah wilayah tersebut. Akurasi IP memang setingkat kota, jadi
# alamat jalan tidak bisa didapat dari cara ini.
#
# Beberapa layanan IP ditanya sekaligus, lalu dipilih titik yang disepakati paling
# banyak layanan. Jika hasilnya terbelah, keyakinan diberi label RENDAH.
import concurrent.futures
import ipaddress
import math
import threading
import time

import requests
from flask import request

LOOKUP_TIMEOUT = 3          # detik per layanan
CACHE_TTL = 6 * 3600        # hasil sukses disimpan 6 jam
FAIL_TTL = 60               # hasil gagal disimpan 1 menit
CLUSTER_KM = 60             # dua layanan dianggap sepakat jika titiknya berjarak maksimal ini
COUNTRY_NAMES = {"ID": "Indonesia"}
_cache = {}
_lock = threading.Lock()


# ---------- IP pengunjung ----------
def get_client_ip() -> str:
    ip = request.remote_addr or "tidak diketahui"
    # Lewat Cloudflare Tunnel, koneksi ke Flask datang dari cloudflared di komputer ini
    # (alamat loopback). IP pengunjung yang sebenarnya ada di header CF-Connecting-IP.
    # Header ini hanya dipercaya jika koneksinya memang dari loopback.
    if ip in ("127.0.0.1", "::1"):
        real_ip = request.headers.get("CF-Connecting-IP", "").strip()
        try:
            ipaddress.ip_address(real_ip)
            return real_ip
        except ValueError:
            pass
    return ip


def parse_user_agent(ua: str):
    """Deteksi browser dan sistem operasi secara sederhana dari User-Agent."""
    ua = ua or ""
    if "Edg/" in ua:
        browser = "Microsoft Edge"
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "Tidak diketahui"

    if "Windows" in ua:
        os_name = "Windows"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Tidak diketahui"
    return browser, os_name


# ---------- Layanan geolokasi IP ----------
# Setiap fungsi mengembalikan dict seragam atau None bila gagal.
def _clean(value):
    value = (str(value).strip() if value is not None else "")
    return "" if value.lower() in ("none", "null", "unknown", "-") else value


def _from_ip_api(ip):
    """ip-api.com: paling lengkap (ada kecamatan, penanda seluler / proxy)."""
    r = requests.get(
        f"http://ip-api.com/json/{ip}",
        params={"fields": "status,country,regionName,city,district,zip,lat,lon,"
                          "isp,org,mobile,proxy,hosting"},
        timeout=LOOKUP_TIMEOUT)
    d = r.json()
    if d.get("status") != "success":
        return None
    return {"district": _clean(d.get("district")), "city": _clean(d.get("city")),
            "region": _clean(d.get("regionName")), "country": _clean(d.get("country")),
            "postal": _clean(d.get("zip")), "lat": d.get("lat"), "lon": d.get("lon"),
            "isp": _clean(d.get("isp")) or _clean(d.get("org")),
            "mobile": bool(d.get("mobile")),
            "proxy": bool(d.get("proxy") or d.get("hosting"))}


def _from_ipwho(ip):
    """ipwho.is: cadangan pertama, memakai HTTPS."""
    r = requests.get(f"https://ipwho.is/{ip}", timeout=LOOKUP_TIMEOUT)
    d = r.json()
    if not d.get("success"):
        return None
    conn = d.get("connection") or {}
    return {"district": "", "city": _clean(d.get("city")),
            "region": _clean(d.get("region")), "country": _clean(d.get("country")),
            "postal": _clean(d.get("postal")), "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "isp": _clean(conn.get("isp")) or _clean(conn.get("org")),
            "mobile": False, "proxy": False}


def _from_ipapi_co(ip):
    """ipapi.co: layanan ketiga, memakai HTTPS."""
    url = f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"
    r = requests.get(url, timeout=LOOKUP_TIMEOUT,
                     headers={"User-Agent": "SecureMessage/1.0"})
    d = r.json()
    if d.get("error"):
        return None
    return {"district": "", "city": _clean(d.get("city")),
            "region": _clean(d.get("region")), "country": _clean(d.get("country_name")),
            "postal": _clean(d.get("postal")), "lat": d.get("latitude"),
            "lon": d.get("longitude"), "isp": _clean(d.get("org")),
            "mobile": False, "proxy": False}


def _from_ipinfo(ip):
    """ipinfo.io: layanan keempat, memakai HTTPS, tanpa token."""
    url = f"https://ipinfo.io/{ip}/json" if ip else "https://ipinfo.io/json"
    d = requests.get(url, timeout=LOOKUP_TIMEOUT).json()
    if d.get("bogon") or d.get("error"):
        return None
    try:
        lat, lon = (d.get("loc") or "").split(",")
    except ValueError:
        lat = lon = None
    country = _clean(d.get("country"))
    return {"district": "", "city": _clean(d.get("city")),
            "region": _clean(d.get("region")), "country": COUNTRY_NAMES.get(country, country),
            "postal": _clean(d.get("postal")), "lat": lat, "lon": lon,
            "isp": _clean(d.get("org")), "mobile": False, "proxy": False}


PROVIDERS = (("ip-api.com", _from_ip_api), ("ipwho.is", _from_ipwho),
             ("ipapi.co", _from_ipapi_co), ("ipinfo.io", _from_ipinfo))


def _is_public(ip: str):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None                      # bukan alamat IP yang valid
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)


def _run_provider(name, func, target):
    """Jalankan satu layanan. Error apa pun dianggap layanan itu gagal."""
    try:
        data = func(target)
    except Exception:
        return None
    if not data or not (data["city"] or data["region"] or data["country"]):
        return None
    try:
        data["lat"], data["lon"] = float(data["lat"]), float(data["lon"])
    except (TypeError, ValueError):
        data["lat"] = data["lon"] = None
    data["source"] = name
    return data


def _query_all(target):
    """Tanya semua layanan sekaligus (paralel). Urutan hasil mengikuti urutan PROVIDERS."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PROVIDERS)) as pool:
        futures = [pool.submit(_run_provider, name, func, target) for name, func in PROVIDERS]
        return [r for r in (f.result() for f in futures) if r]


def _place(d: dict) -> str:
    return d["city"] or d["district"] or d["region"] or d["country"]


def _consensus(results):
    """
    Pilih titik yang disepakati paling banyak layanan (jarak antar titik <= CLUSTER_KM).
    Jika dua kelompok sama besar, layanan yang lebih awal di PROVIDERS menang,
    tetapi keyakinannya RENDAH. Mengembalikan (terpilih, keyakinan, jumlah_sepakat, lainnya).
    """
    pool = [r for r in results if r["lat"] is not None] or results
    groups = []
    for r in pool:
        if r["lat"] is None:
            groups.append([r])
        else:
            groups.append([o for o in pool if o["lat"] is not None and
                           distance_km(r["lat"], r["lon"], o["lat"], o["lon"]) <= CLUSTER_KM])
    top = max(len(g) for g in groups)
    best = next(g for g in groups if len(g) == top)
    best_ids = {id(x) for x in best}
    split = any(len(g) == top and not ({id(x) for x in g} & best_ids) for g in groups)

    level = 2 if top >= 3 else (1 if top == 2 else 0)        # 2 tinggi, 1 sedang, 0 rendah
    if split:
        level = 0
    if any(r["mobile"] or r["proxy"] for r in best):          # seluler / VPN kurang bisa dipercaya
        level = max(0, level - 1)
    others = [r for r in results if id(r) not in best_ids]
    return best[0], ("rendah", "sedang", "tinggi")[level], top, others


def _format_address(d: dict) -> str:
    """Susun alamat dari yang terkecil ke terbesar, tanpa nama ganda berurutan."""
    parts = []
    for key in ("district", "city", "region", "country"):
        value = d.get(key)
        if value and (not parts or parts[-1].lower() != value.lower()):
            parts.append(value)
    text = ", ".join(parts)
    if d.get("postal"):
        text += f" {d['postal']}"
    return text


def _format_note(d: dict, local: bool, level: str, agree: int, total: int, others) -> str:
    notes = ["Akses lokal: lokasi jaringan internet komputer server" if local
             else "Perkiraan dari IP (setingkat kota)"]
    notes.append(f"keyakinan {level.upper()} ({agree} dari {total} layanan sepakat)")
    if d.get("isp"):
        notes.append(f"ISP: {d['isp']}")
    if d.get("mobile"):
        notes.append("jaringan seluler, titik bisa berbeda dari posisi sebenarnya")
    if d.get("proxy"):
        notes.append("terdeteksi VPN / proxy / hosting, lokasi bisa menyesatkan")
    if others:
        notes.append("layanan lain: " + "; ".join(f"{o['source']} = {_place(o)}" for o in others[:3]))
    if level != "tinggi":
        notes.append("titik IP sering menunjuk pusat jaringan ISP, bukan posisi perangkat")
    return " · ".join(notes)


def lookup_location(ip: str) -> dict:
    """
    Hasil: {"text": alamat, "note": keterangan, "lat": float|None, "lon": float|None}
    IP privat / loopback (akses lewat jaringan lokal) diganti dengan lokasi
    jaringan internet komputer server.
    """
    public = _is_public(ip)
    if public is None:
        return {"text": "Tidak diketahui", "note": "IP tidak valid", "lat": None, "lon": None}
    local = not public
    key = "server" if local else ip

    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > time.time():
            return hit[1]

    results = _query_all("" if local else ip)
    if results:
        data, level, agree, others = _consensus(results)
        result = {"text": _format_address(data),
                  "note": _format_note(data, local, level, agree, len(results), others),
                  "lat": data["lat"], "lon": data["lon"], "confidence": level}
        ttl = CACHE_TTL
    else:
        result = {"text": "Tidak diketahui", "note": "Layanan lokasi tidak dapat dihubungi",
                  "lat": None, "lon": None, "confidence": "rendah"}
        ttl = FAIL_TTL
    with _lock:
        _cache[key] = (time.time() + ttl, result)
    return result


def collect_request_info(lookup: bool = True) -> dict:
    """Kumpulkan semua info pengakses untuk dicatat di log."""
    ip = get_client_ip()
    browser, os_name = parse_user_agent(request.headers.get("User-Agent", ""))
    loc = lookup_location(ip) if lookup else \
        {"text": "-", "note": None, "lat": None, "lon": None}
    return {"ip": ip, "browser": browser, "os": os_name,
            "location": loc["text"], "location_note": loc["note"],
            "ip_lat": loc["lat"], "ip_lon": loc["lon"]}


# ---------- GPS: alamat dari koordinat ----------
def reverse_geocode(lat: float, lon: float) -> str:
    """Ubah koordinat GPS menjadi alamat jalan lewat OpenStreetMap Nominatim."""
    try:
        r = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 18,
                    "addressdetails": 0, "accept-language": "id"},
            headers={"User-Agent": "SecureMessage/1.0 (aplikasi pesan rahasia)"},
            timeout=5)
        name = _clean(r.json().get("display_name"))
        if name:
            return name[:300]
    except (requests.RequestException, ValueError):
        pass
    return "Alamat tidak tersedia (koordinat tetap tercatat)"


def distance_km(lat1, lon1, lat2, lon2) -> float:
    """Jarak dua titik di bumi (rumus haversine)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))
