# app.py
# File utama aplikasi Flask: semua route (halaman) ada di sini.
# Logika berat (enkripsi, AMI, keamanan) ada di file lain agar kode mudah dibaca.
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, g, jsonify)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash

import ami_encoder
import location
import encryption
import security
from pymysql.err import IntegrityError
from database import get_db, close_db, init_db

app = Flask(__name__)

# ---------- Konfigurasi ----------
def load_secret_key():
    """Secret key session disimpan di secure_data/, dibuat otomatis sekali."""
    os.makedirs(encryption.SECURE_DIR, exist_ok=True)
    path = os.path.join(encryption.SECURE_DIR, "secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(os.urandom(32).hex())
    with open(path) as f:
        return f.read().strip()


app.config["SECRET_KEY"] = load_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True      # cookie tidak bisa dibaca JavaScript
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024     # batas ukuran upload (file private key kecil)

csrf = CSRFProtect(app)          # proteksi CSRF untuk semua form POST
app.teardown_appcontext(close_db)
init_db()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- Filter & helper template ----------
@app.template_filter("wib")
def wib_filter(value):
    """Ubah waktu UTC di database menjadi WIB (UTC+7) untuk tampilan."""
    if not value:
        return "-"
    dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S") + timedelta(hours=7)
    return dt.strftime("%d %b %Y %H:%M:%S") + " WIB"


@app.template_filter("event_label")
def event_label_filter(value):
    return security.EVENT_LABELS.get(value, value)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
    response.headers["Permissions-Policy"] = "geolocation=(self)"
    response.headers["Cache-Control"] = "no-store"   # pesan rahasia tidak di-cache
    return response


# ---------- Autentikasi ----------
@app.before_request
def load_current_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        g.user = get_db().execute("SELECT id, username, email FROM users WHERE id = ?",
                                  (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("Silakan login terlebih dahulu.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # Validasi input
        error = None
        if not USERNAME_RE.match(username):
            error = "Username 3-30 karakter: huruf, angka, atau underscore."
        elif not EMAIL_RE.match(email) or len(email) > 120:
            error = "Format email tidak valid."
        elif len(password) < 8 or len(password) > 128 \
                or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            error = "Password minimal 8 karakter dan mengandung huruf serta angka."
        elif password != confirm:
            error = "Konfirmasi password tidak sama."

        if error:
            flash(error, "danger")
        else:
            try:
                db = get_db()
                # Pasangan kunci RSA dibuat di sini. PRIVATE KEY hanya ditampilkan sekali
                # kepada pengguna dan TIDAK disimpan; server hanya menyimpan public key.
                private_pem, public_pem = encryption.generate_keypair()
                db.execute("INSERT INTO users (username, email, password_hash, public_key, created_at) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (username, email, generate_password_hash(password),
                            public_pem, security.now_utc()))
                db.commit()
                return render_template("private_key.html", username=username,
                                       private_pem=private_pem,
                                       fingerprint=encryption.key_fingerprint(public_pem))
            except IntegrityError:
                flash("Username atau email sudah terdaftar.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        # Batasi percobaan login: maks 5 kegagalan dari IP yang sama dalam 10 menit
        from location import get_client_ip
        limit_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        failed = db.execute("SELECT COUNT(*) FROM security_logs WHERE event_type = 'login_gagal' "
                            "AND ip_address = ? AND created_at > ?",
                            (get_client_ip(), limit_time)).fetchone()[0]
        if failed >= 5:
            flash("Terlalu banyak percobaan login gagal. Coba lagi dalam 10 menit.", "danger")
            return render_template("login.html"), 429

        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()                 # cegah session fixation
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))

        security.log_event(db, "login_gagal", f"Login gagal untuk username '{username[:30]}'",
                           user_id=user["id"] if user else None, status="diblokir")
        flash("Username atau password salah.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Anda sudah logout.", "success")
    return redirect(url_for("login"))


# ---------- Query bantu ----------
def visible_logs(db, user_id, limit=100):
    """Log yang boleh dilihat pengguna: aktivitasnya sendiri + yang menyangkut pesannya."""
    return db.execute(
        """SELECT l.*, u.username FROM security_logs l
           LEFT JOIN users u ON u.id = l.user_id
           WHERE l.user_id = ?
              OR l.message_id IN (SELECT id FROM messages
                                  WHERE sender_id = ? OR recipient_id = ?)
           ORDER BY l.id DESC LIMIT ?""",
        (user_id, user_id, user_id, limit)).fetchall()


def count_unauthorized(db, user_id, since=None):
    marks = ",".join("?" * len(security.UNAUTHORIZED_EVENTS))
    sql = f"""SELECT COUNT(*) FROM security_logs
              WHERE event_type IN ({marks})
                AND (user_id = ? OR message_id IN
                     (SELECT id FROM messages WHERE sender_id = ? OR recipient_id = ?))"""
    params = list(security.UNAUTHORIZED_EVENTS) + [user_id, user_id, user_id]
    if since:
        sql += " AND created_at > ?"
        params.append(since)
    return db.execute(sql, params).fetchone()[0]


# ---------- Dashboard ----------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]
    one = lambda sql, *p: db.execute(sql, p).fetchone()[0]

    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    status_text, status_class = security.security_status(count_unauthorized(db, uid, since))
    stats = {
        "sent": one("SELECT COUNT(*) FROM messages WHERE sender_id = ?", uid),
        "received": one("SELECT COUNT(*) FROM messages WHERE recipient_id = ?", uid),
        "read": one("SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NOT NULL", uid),
        "unauthorized": count_unauthorized(db, uid),
    }
    return render_template("dashboard.html", stats=stats, status_text=status_text,
                           status_class=status_class, logs=visible_logs(db, uid, 10))


# ---------- Kirim pesan ----------
@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    db = get_db()
    selected = []
    if request.method == "POST":
        # Penerima bisa lebih dari satu (checkbox bernama "recipient"); hilangkan duplikat.
        selected = list(dict.fromkeys(n.strip().lower() for n in request.form.getlist("recipient")
                                      if n.strip()))
        body = request.form.get("body", "").strip()

        recipients, error = [], None
        if not selected:
            error = "Pilih minimal satu penerima."
        elif not body or len(body) > 300:
            error = "Isi pesan wajib diisi (maksimal 300 karakter)."
        else:
            for name in selected:
                row = db.execute("SELECT id, public_key FROM users WHERE username = ?",
                                 (name,)).fetchone()
                if row is None:
                    error = f"Penerima '{name[:30]}' tidak ditemukan."
                elif row["id"] == g.user["id"]:
                    error = "Tidak dapat mengirim pesan ke diri sendiri."
                elif not row["public_key"]:
                    error = (f"Penerima '{name}' belum memiliki kunci (akun lama). "
                             "Minta ia mendaftar ulang.")
                if error:
                    break
                recipients.append((name, row))

        if error:
            flash(error, "danger")
        else:
            results = []
            sent_at = security.now_utc()
            for name, row in recipients:
                message_id = str(uuid.uuid4())

                # 1. Enkripsi teks dengan PUBLIC KEY tiap penerima (RSA)
                cipher = encryption.encrypt_message(body.encode("utf-8"), row["public_key"])
                # 2. Ciphertext di-encode menjadi BINER (inilah yang disimpan di database)
                binary = ami_encoder.encode_binary(cipher)
                # 3. Sinyal Bipolar AMI hanya untuk grafik di halaman, tidak disimpan
                signal = ami_encoder.build_signal(binary)

                # Hanya biner dari ciphertext yang masuk database, teks asli tidak disimpan.
                db.execute("INSERT INTO messages (id, sender_id, recipient_id, ciphertext_bin, "
                           "sent_at, status) VALUES (?, ?, ?, ?, ?, 'terkirim')",
                           (message_id, g.user["id"], row["id"], binary, sent_at))
                results.append({"recipient": name, "cipher_hex": cipher.hex(), "binary": binary,
                                "signal": ami_encoder.levels_to_text(signal["levels"]),
                                "total_bits": signal["total_bits"]})
            db.commit()
            return render_template("compose_result.html", body=body, results=results)

    # Daftar penerima: akun terdaftar di database (selain akun sendiri) yang sudah punya kunci
    users = db.execute("SELECT username FROM users WHERE id != ? AND public_key IS NOT NULL "
                       "AND public_key != '' ORDER BY username", (g.user["id"],)).fetchall()
    return render_template("compose.html", users=users, selected=selected,
                           body=request.form.get("body", ""))


# ---------- Daftar pesan ----------
@app.route("/inbox")
@login_required
def inbox():
    db = get_db()
    rows = db.execute("SELECT m.*, u.username AS other FROM messages m "
                      "JOIN users u ON u.id = m.sender_id "
                      "WHERE m.recipient_id = ? ORDER BY m.sent_at DESC",
                      (g.user["id"],)).fetchall()
    return render_template("inbox.html", messages=rows)


@app.route("/sent")
@login_required
def sent():
    db = get_db()
    rows = db.execute("SELECT m.*, u.username AS other FROM messages m "
                      "JOIN users u ON u.id = m.recipient_id "
                      "WHERE m.sender_id = ? ORDER BY m.sent_at DESC",
                      (g.user["id"],)).fetchall()
    return render_template("sent.html", messages=rows)


@app.route("/history")
@login_required
def history():
    db = get_db()
    uid = g.user["id"]
    rows = db.execute("SELECT m.*, s.username AS sender_name, r.username AS recipient_name "
                      "FROM messages m JOIN users s ON s.id = m.sender_id "
                      "JOIN users r ON r.id = m.recipient_id "
                      "WHERE m.sender_id = ? OR m.recipient_id = ? ORDER BY m.sent_at DESC",
                      (uid, uid)).fetchall()
    return render_template("history.html", messages=rows)


# ---------- Baca pesan (dekripsi + deteksi akses tidak sah) ----------
def show_alert(log_id, title, reason, binary=None):
    """
    Tampilkan halaman peringatan keamanan (akses diblokir).
    binary = data yang berhasil diambil pengakses (hanya hasil encode ciphertext).
    """
    log = get_db().execute("SELECT ip_address, location_text, location_note, ip_lat, ip_lon, "
                           "latitude, longitude, gps_accuracy, gps_address "
                           "FROM security_logs WHERE id = ?", (log_id,)).fetchone()
    return render_template("security_alert.html", log=log, title=title,
                           reason=reason, binary=binary), 403


GEO_MAX_AGE = 300   # detik: hasil GPS penyusup hanya berlaku untuk satu kali percobaan


def take_geo(message_id):
    """Ambil (dan hapus) hasil GPS terbaru dari sesi untuk pesan ini."""
    geo = session.pop("geo", None)
    if not geo or geo.get("mid") != message_id:
        return None
    if datetime.now(timezone.utc).timestamp() - geo["ts"] > GEO_MAX_AGE:
        return None
    return geo


@app.route("/message/<message_id>/location", methods=["POST"])
@login_required
def submit_location(message_id):
    """Terima hasil verifikasi lokasi dari browser. Hanya dipakai untuk pengakses yang bukan penerima."""
    db = get_db()
    msg = db.execute("SELECT sender_id, recipient_id FROM messages WHERE id = ?",
                     (message_id,)).fetchone()
    if msg is None:
        return jsonify(ok=False, error="Pesan tidak ditemukan"), 404
    if g.user["id"] in (msg["sender_id"], msg["recipient_id"]):
        return jsonify(ok=True)         # pengguna sah: lokasi tidak diambil

    data = request.get_json(silent=True) or {}
    if data.get("denied"):
        reason = {1: "Izin lokasi ditolak oleh pengguna atau browser.",
                  2: "Posisi perangkat tidak tersedia.",
                  3: "Pengambilan lokasi melewati batas waktu."}.get(data.get("code"),
                                                                    "Lokasi tidak dapat diambil.")
        security.log_violation(db, "akses_pesan_orang_lain",
                               "Pengguna mencoba membuka pesan yang bukan miliknya. " + reason,
                               g.user["id"], message_id)
        return jsonify(ok=False, error=reason), 403
    try:
        lat, lon = float(data["latitude"]), float(data["longitude"])
        acc = max(0.0, float(data.get("accuracy") or 0))
    except (KeyError, TypeError, ValueError):
        return jsonify(ok=False, error="Data tidak valid"), 400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify(ok=False, error="Koordinat tidak valid"), 400
    session["geo"] = {"mid": message_id, "lat": lat, "lon": lon, "accuracy": acc,
                      "address": location.reverse_geocode(lat, lon),
                      "ts": datetime.now(timezone.utc).timestamp()}
    return jsonify(ok=True)


def read_private_key():
    """Ambil private key dari kotak teks atau file yang diunggah. Kosong jika tidak ada."""
    pem = request.form.get("private_key", "").strip()
    upload = request.files.get("key_file")
    if not pem and upload and upload.filename:
        pem = upload.read(20000).decode("utf-8", errors="ignore").strip()
    return pem


@app.route("/message/<message_id>/signal")
@login_required
def message_signal(message_id):
    """Halaman sinyal Bipolar AMI. Dari sini penerima memilih 'Terjemahkan pesan' -> private key."""
    db = get_db()
    msg = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if msg is None:
        flash("Pesan tidak ditemukan.", "warning")
        return redirect(url_for("inbox"))
    # Bukan penerima: biarkan read_message yang menangani (pengirim ditolak, orang lain = penyusup).
    if msg["recipient_id"] != g.user["id"]:
        return redirect(url_for("read_message", message_id=message_id))
    if not msg["ciphertext_bin"]:
        flash("Data pesan ini sudah tidak tersedia.", "warning")
        return redirect(url_for("inbox"))
    sender = db.execute("SELECT username FROM users WHERE id = ?", (msg["sender_id"],)).fetchone()
    return render_template("signal.html", msg=msg, sender=sender["username"],
                           signal=ami_encoder.levels_to_text(
                               ami_encoder.ami_encode(msg["ciphertext_bin"])),
                           total_bits=len(msg["ciphertext_bin"]))


@app.route("/message/<message_id>", methods=["GET", "POST"])
@login_required
def read_message(message_id):
    db = get_db()
    uid = g.user["id"]
    msg = db.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    if msg is None:
        flash("Pesan tidak ditemukan.", "warning")
        return redirect(url_for("inbox"))

    # Bukan penerima: pengirim hanya boleh melihat status, orang lain dianggap penyusup.
    if msg["recipient_id"] != uid:
        if msg["sender_id"] == uid:
            flash("Pengirim tidak dapat membaca isi pesan. Hanya penerima yang bisa.", "warning")
            return redirect(url_for("sent"))
        # Lokasi penyusup diverifikasi lewat GPS, lalu dicatat bersama IP-nya.
        geo = take_geo(message_id)
        if geo is None:
            return render_template("location_gate.html", message_id=message_id)
        log_id = security.log_violation(
            db, "akses_pesan_orang_lain",
            "Pengguna mencoba membuka pesan yang bukan miliknya "
            "(hanya memperoleh hasil encode ciphertext).",
            uid, message_id, geo=geo)
        return show_alert(
            log_id, "Akses Ditolak",
            "Anda bukan penerima pesan ini. Data yang berhasil diambil hanya hasil encode ciphertext.",
            binary=msg["ciphertext_bin"])

    # Penerima sah: tidak ada verifikasi lokasi, langsung minta PRIVATE KEY.
    if not msg["ciphertext_bin"]:
        flash("Data pesan ini sudah tidak tersedia.", "warning")
        return redirect(url_for("inbox"))
    private_pem = read_private_key() if request.method == "POST" else ""
    if not private_pem:
        return render_template("unlock.html", message_id=message_id,
                               attempted=request.method == "POST")

    # Private key harus pasangan dari public key akun ini
    stored_pub = db.execute("SELECT public_key FROM users WHERE id = ?", (uid,)).fetchone()["public_key"]
    try:
        if encryption.public_from_private(private_pem).strip() != (stored_pub or "").strip():
            raise encryption.PrivateKeyError("bukan pasangan kunci akun ini")
    except encryption.PrivateKeyError:
        # Salah kunci bisa berarti akun dibobol: dicatat beserta perkiraan lokasi dari IP.
        security.log_violation(db, "private_key_salah",
                               "Private key yang dimasukkan tidak cocok dengan akun ini.",
                               uid, message_id)
        flash("Private key tidak cocok. Pastikan memakai kunci milik akun Anda.", "danger")
        return render_template("unlock.html", message_id=message_id, attempted=True)

    # Biner -> ciphertext (bytes), lalu dekripsi RSA dengan private key
    try:
        cipher = ami_encoder.decode_binary(msg["ciphertext_bin"])
        data, info = encryption.decrypt_message(cipher, private_pem)
        plaintext = data.decode("utf-8")
    except ValueError as err:            # biner rusak / ciphertext dimanipulasi
        log_id = security.log_violation(db, "manipulasi_pesan",
                                        f"Biner atau ciphertext tidak valid: {err}.",
                                        uid, message_id)
        return show_alert(log_id, "Manipulasi Terdeteksi",
                          "Data pesan tidak valid sehingga tidak dibuka.")

    # Berhasil: tandai dibaca (tanpa pencarian lokasi untuk penerima sah)
    db.execute("UPDATE messages SET status = 'dibaca', read_at = COALESCE(read_at, ?) WHERE id = ?",
               (security.now_utc(), message_id))
    db.commit()
    security.log_event(db, "pesan_dibaca", "Pesan berhasil didekripsi oleh penerima.",
                       uid, message_id, status="info", lookup=False)
    sender = db.execute("SELECT username FROM users WHERE id = ?", (msg["sender_id"],)).fetchone()
    return render_template("message.html", msg=msg, plaintext=plaintext, info=info,
                           sender=sender["username"], binary=msg["ciphertext_bin"])


# ---------- Security Monitoring ----------
@app.route("/security")
@login_required
def security_monitoring():
    db = get_db()
    return render_template("security_monitoring.html", logs=visible_logs(db, g.user["id"]),
                           unauthorized=security.UNAUTHORIZED_EVENTS)


# ---------- Error handler ----------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Sesi form kedaluwarsa atau token CSRF tidak valid. Silakan coba lagi.", "danger")
    return redirect(request.referrer or url_for("login"))


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, text="Halaman tidak ditemukan."), 404


if __name__ == "__main__":
    # Debug dimatikan karena aplikasi dapat diakses melalui Cloudflare Tunnel.
    app.run(host="127.0.0.1", port=5000, debug=False)
