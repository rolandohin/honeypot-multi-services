# ============================================================
#  main.py — Orchestrateur principal du honeypot
#  Lance tous les modules en parallèle
# ============================================================

import threading
import time
import signal
import sys
from logger import init_db, log, get_stats
from modules.ssh_module  import start_ssh_server
from modules.http_module import start_http_server
from modules.ftp_module  import start_ftp_server
from modules.smtp_module import start_smtp_server

MODULES = [
    ("SSH",  start_ssh_server),
    ("HTTP", start_http_server),
    ("FTP",  start_ftp_server),
    ("SMTP", start_smtp_server),
]

threads = []

def start_all():
    """Démarre tous les modules dans des threads séparés."""
    for name, func in MODULES:
        t = threading.Thread(target=func, name=f"module-{name}", daemon=True)
        t.start()
        threads.append(t)
        log.info("✅ Module %s démarré", name)
        time.sleep(0.3)   # léger décalage pour lisibilité des logs

def print_stats():
    """Affiche un résumé des stats toutes les 60 secondes."""
    while True:
        time.sleep(60)
        stats = get_stats()
        log.info("📊 STATS — Total: %s  |  Par service: %s",
                 stats.get("total", 0), stats.get("by_service", {}))

def shutdown(sig, frame):
    log.info("\n🛑 Arrêt du honeypot...")
    stats = get_stats()
    log.info("📊 Bilan final : %s connexions capturées", stats.get("total", 0))
    if stats.get("top_ips"):
        log.info("🏆 Top IPs : %s", stats["top_ips"][:3])
    sys.exit(0)

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════╗
║   🍯 HONEYPOT MULTI-SERVICES v2.0        ║
║   Projet Annuel ESGI — Sécurité Info     ║
╚══════════════════════════════════════════╝
    """)

    # Init base de données
    init_db()

    # Gestion Ctrl+C propre
    signal.signal(signal.SIGINT, shutdown)

    # Démarrage des modules
    start_all()

    # Stats périodiques (thread daemon)
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()

    log.info("🍯 Honeypot actif sur SSH:2222 | HTTP:8080 | FTP:2121 | SMTP:2525")
    log.info("🌐 Dashboard : http://<IP_VM>:8080/api/stats")

    # Maintien du processus principal
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)
