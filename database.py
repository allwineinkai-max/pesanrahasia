# database.py - koneksi MySQL (Laragon) dan pembuatan tabel.
import os
import sys

import pymysql
from pymysql.cursors import DictCursor
from flask import g

# Bawaan Laragon: root tanpa password. Bisa diubah lewat variabel lingkungan.
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "securemessage")

# Waktu disimpan sebagai teks UTC 'YYYY-MM-DD HH:MM:SS'
TABLES = [
    """CREATE TABLE IF NOT EXISTS users (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        username      VARCHAR(30)  NOT NULL UNIQUE,
        email         VARCHAR(120) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        public_key    TEXT,
        created_at    VARCHAR(19)  NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    # ciphertext_bin = biner hasil encode ciphertext (teks asli tidak disimpan)
    """CREATE TABLE IF NOT EXISTS messages (
        id             VARCHAR(36) PRIMARY KEY,
        sender_id      INT         NOT NULL,
        recipient_id   INT         NOT NULL,
        ciphertext_bin LONGTEXT    NOT NULL,
        sent_at        VARCHAR(19) NOT NULL,
        status         VARCHAR(20) NOT NULL DEFAULT 'terkirim',
        read_at        VARCHAR(19),
        FOREIGN KEY (sender_id)    REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

    """CREATE TABLE IF NOT EXISTS security_logs (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        message_id    VARCHAR(36),
        user_id       INT,
        event_type    VARCHAR(60) NOT NULL,
        detail        TEXT,
        status        VARCHAR(20) NOT NULL,
        ip_address    VARCHAR(64),
        browser       VARCHAR(60),
        os            VARCHAR(60),
        location_text TEXT,
        location_note TEXT,
        ip_lat        DOUBLE,
        ip_lon        DOUBLE,
        latitude      DOUBLE,
        longitude     DOUBLE,
        gps_accuracy  DOUBLE,
        gps_address   TEXT,
        created_at    VARCHAR(19) NOT NULL,
        FOREIGN KEY (message_id) REFERENCES messages(id),
        FOREIGN KEY (user_id)    REFERENCES users(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


class Row(dict):
    """Hasil query: bisa row['kolom'] maupun row[0]."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class RowCursor(DictCursor):
    dict_type = Row


class Database:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        cur.execute(sql.replace("?", "%s"), params)   # query ditulis dengan ?
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


def _connect(with_db=True):
    return pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
                           database=DB_NAME if with_db else None, charset="utf8mb4",
                           cursorclass=RowCursor, autocommit=True)


def connect():
    return Database(_connect())


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Buat database dan tabel jika belum ada."""
    try:
        conn = _connect(with_db=False)
    except pymysql.err.OperationalError as err:
        sys.exit(f"\nTidak dapat terhubung ke MySQL ({err}).\n"
                 "Buka Laragon lalu klik 'Start All', kemudian jalankan ulang aplikasi.\n")
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    conn.close()
    conn = _connect()
    with conn.cursor() as cur:
        for statement in TABLES:
            cur.execute(statement)
    conn.close()
