# ============================================================
#  logger.py — Collecteur de logs centralisé (SQLite)
# ============================================================

import sqlite3
import logging
import os
from datetime import datetime
from config import DB_PATH, LOG_FILE

# ── Setup du logger console/fichier
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),   # affiche aussi dans le terminal
    ]
)
log = logging.getLogger("honeypot")


def init_db():
    """Crée les tables SQLite si elles n'existent pas."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()

    # Mode WAL : permet lectures/ecritures concurrentes sans verrou global,
    # indispensable car plusieurs modules ecrivent depuis des threads distincts.
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")

    # Table principale des connexions
    c.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            service     TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            src_port    INTEGER,
            username    TEXT,
            password    TEXT,
            success     INTEGER DEFAULT 0,   -- 1 = faux succès (attaquant croit être connecté)
            duration    REAL    DEFAULT 0,
            notes       TEXT
        )
    """)

    # Table des commandes saisies (pour SSH/Telnet)
    c.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id INTEGER REFERENCES connections(id),
            timestamp     TEXT    NOT NULL,
            command       TEXT    NOT NULL
        )
    """)

    # Table des payloads HTTP (formulaires soumis)
    c.execute("""
        CREATE TABLE IF NOT EXISTS http_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            method      TEXT,
            path        TEXT,
            user_agent  TEXT,
            body        TEXT
        )
    """)

    # Table dediee aux messages SMTP captures (mail_from, rcpt_to, corps)
    c.execute("""
        CREATE TABLE IF NOT EXISTS smtp_messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            mail_from   TEXT,
            rcpt_to     TEXT,
            body        TEXT
        )
    """)

    conn.commit()
    conn.close()
    log.info("Base de données initialisée : %s", DB_PATH)


def log_connection(service, src_ip, src_port=None, username=None,
                   password=None, success=False, duration=0.0, notes=""):
    """Enregistre une tentative de connexion et retourne l'id."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("""
        INSERT INTO connections
            (timestamp, service, src_ip, src_port, username, password, success, duration, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        service, src_ip, src_port,
        username, password,
        int(success), duration, notes
    ))
    conn.commit()
    conn_id = c.lastrowid
    conn.close()

    # Log console coloré
    status = "✅ AUTH" if success else "❌ FAIL"
    log.info("[%s] %s  %s:%s  user=%s pass=%s",
             service.upper(), status, src_ip, src_port, username, password)
    return conn_id


def log_command(connection_id, command):
    """Enregistre une commande saisie après connexion SSH/Telnet."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("""
        INSERT INTO commands (connection_id, timestamp, command)
        VALUES (?, ?, ?)
    """, (connection_id, datetime.now().isoformat(), command))
    conn.commit()
    conn.close()
    log.info("[CMD] conn_id=%s  $ %s", connection_id, command)


def log_http(src_ip, method, path, user_agent="", body=""):
    """Enregistre une requête HTTP."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("""
        INSERT INTO http_requests (timestamp, src_ip, method, path, user_agent, body)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), src_ip, method, path, user_agent, body))
    conn.commit()
    conn.close()
    log.info("[HTTP] %s  %s %s  UA=%s", src_ip, method, path, user_agent[:60])


def log_smtp(src_ip, mail_from="", rcpt_to="", body=""):
    """Enregistre un message SMTP capture dans sa table dediee."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute("""
        INSERT INTO smtp_messages (timestamp, src_ip, mail_from, rcpt_to, body)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), src_ip, mail_from, str(rcpt_to), body))
    conn.commit()
    conn.close()
    log.info("[SMTP] %s  from=%s  to=%s", src_ip, mail_from, rcpt_to)


def get_stats():
    """Retourne des stats rapides pour le dashboard."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()

    stats = {}

    # Total connexions par service
    c.execute("SELECT service, COUNT(*) FROM connections GROUP BY service")
    stats["by_service"] = dict(c.fetchall())

    # Top 10 IPs
    c.execute("""
        SELECT src_ip, COUNT(*) as cnt
        FROM connections
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 10
    """)
    stats["top_ips"] = c.fetchall()

    # Top credentials essayés
    c.execute("""
        SELECT username, password, COUNT(*) as cnt
        FROM connections
        WHERE username IS NOT NULL
        GROUP BY username, password
        ORDER BY cnt DESC
        LIMIT 10
    """)
    stats["top_creds"] = c.fetchall()

    # Total général
    c.execute("SELECT COUNT(*) FROM connections")
    stats["total"] = c.fetchone()[0]

    conn.close()
    return stats
