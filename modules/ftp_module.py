# ============================================================
#  modules/ftp_module.py — Honeypot FTP (corrigé)
#  Force la demande de username ET password, logue tout
# ============================================================

import os
import sys
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import PORTS, BANNERS
from logger import log_connection, log, init_db

FAKE_FTP_ROOT = "/tmp/honeypot_ftp"


# ──────────────────────────────────────────────
#  Authorizer custom : demande TOUJOURS user+pass
# ──────────────────────────────────────────────
class HoneypotAuthorizer(DummyAuthorizer):
    """
    Accepte n'importe quel username/password
    mais les enregistre tous dans la DB.
    Supprime 'anonymous' pour forcer la saisie.
    """

    def validate_authentication(self, username, password, handler):
        # Stocke le password pour on_login
        handler._captured_password = password
        # Accepte toujours sans lever d'exception

    def get_home_dir(self, username):
        return FAKE_FTP_ROOT

    def has_user(self, username):
        # Toujours True → le serveur demande le password
        return True

    def has_perm(self, username, perm, path=None):
        return True

    def get_perms(self, username):
        return "elradfmwMT"

    def get_msg_login(self, username):
        return "Login successful."

    def get_msg_quit(self, username):
        return "Goodbye."


# ──────────────────────────────────────────────
#  Handler FTP
# ──────────────────────────────────────────────
class HoneypotFTPHandler(FTPHandler):

    def on_connect(self):
        log.info("[FTP] Connexion entrante  %s:%s", self.remote_ip, self.remote_port)

    def on_disconnect(self):
        log.info("[FTP] Déconnexion  %s", self.remote_ip)

    def on_login(self, username):
        password = getattr(self, "_captured_password", "")
        log_connection(
            service="ftp",
            src_ip=self.remote_ip,
            src_port=self.remote_port,
            username=username,
            password=password,
            success=True,
        )
        log.info("[FTP] LOGIN  %s  user=%s  pass=%s",
                 self.remote_ip, username, password)

    def on_login_failed(self, username, password):
        log_connection(
            service="ftp",
            src_ip=self.remote_ip,
            src_port=self.remote_port,
            username=username,
            password=password,
            success=False,
        )
        log.info("[FTP] FAIL  %s  user=%s  pass=%s",
                 self.remote_ip, username, password)

    def on_file_retrieved(self, file):
        log.info("[FTP] Download  %s  par  %s", file, self.remote_ip)

    def on_file_sent(self, file):
        log.info("[FTP] Upload  %s  par  %s", file, self.remote_ip)


# ──────────────────────────────────────────────
#  Démarrage
# ──────────────────────────────────────────────
def start_ftp_server():
    os.makedirs(FAKE_FTP_ROOT, exist_ok=True)
    lure_files = {
        "backup_2024.sql": b"-- MySQL dump 10.13\n-- Database: corporate_db\n",
        "passwords.txt":   b"# DO NOT SHARE\nadmin:C0rp0r@te2024!\nroot:Sup3rS3cr3t!\n",
        "config.ini":      b"[database]\nhost=10.0.1.20\nuser=dbadmin\npassword=Db@2024!\n",
        "README.txt":      b"Corporate backup files - Confidential\n",
    }
    for fname, content in lure_files.items():
        path = os.path.join(FAKE_FTP_ROOT, fname)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(content)

    handler = HoneypotFTPHandler
    handler.authorizer    = HoneypotAuthorizer()
    handler.banner        = BANNERS["ftp"]
    handler.passive_ports = range(60000, 60100)

    port = PORTS["ftp"]
    server = FTPServer(("0.0.0.0", port), handler)
    log.info("[FTP] Honeypot FTP demarre sur port %s", port)
    server.serve_forever()


if __name__ == "__main__":
    init_db()
    start_ftp_server()
