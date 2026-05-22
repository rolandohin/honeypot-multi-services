# ============================================================
#  modules/ssh_module.py — Honeypot SSH
#  Émule un serveur SSH vulnérable, capture credentials + cmds
# ============================================================

import socket
import threading
import time
import paramiko
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import PORTS, BANNERS, FAKE_CREDENTIALS, FAKE_COMMANDS, SESSION_TIMEOUT
from logger import log_connection, log_command, log

# ──────────────────────────────────────────────
#  Génération de la clé hôte SSH (une seule fois)
# ──────────────────────────────────────────────
HOST_KEY_PATH = "keys/ssh_host_rsa"

def get_host_key():
    os.makedirs("keys", exist_ok=True)
    if not os.path.exists(HOST_KEY_PATH):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        log.info("[SSH] Clé hôte générée : %s", HOST_KEY_PATH)
    return paramiko.RSAKey(filename=HOST_KEY_PATH)


# ──────────────────────────────────────────────
#  Interface Paramiko : gestion auth + shell
# ──────────────────────────────────────────────
class HoneypotSSHInterface(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.username    = None
        self.password    = None
        self.conn_id     = None
        self.event       = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        # On accepte TOUJOURS (faux succès pour piéger l'attaquant)
        success = True
        self.conn_id = log_connection(
            service="ssh",
            src_ip=self.client_ip,
            src_port=self.client_port,
            username=username,
            password=password,
            success=success,
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


# ──────────────────────────────────────────────
#  Gestion d'une session shell interactive
# ──────────────────────────────────────────────
def handle_shell(channel, conn_id, client_ip):
    """Simule un shell bash après connexion réussie."""
    start = time.time()

    def send(msg):
        try:
            channel.send(msg)
        except Exception:
            pass

    # Accueil réaliste
    send("\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.15.0-71-generic x86_64)\r\n")
    send("\r\n * Documentation:  https://help.ubuntu.com\r\n")
    send(" * Management:     https://landscape.canonical.com\r\n\r\n")
    send("Last login: Mon Jan 15 08:23:41 2024 from 10.0.0.50\r\n\r\n")
    send("root@ubuntu-server:~# ")

    buf = ""
    try:
        channel.settimeout(SESSION_TIMEOUT)
        while True:
            data = channel.recv(1024)
            if not data:
                break

            # Echo des caractères
            for char in data.decode("utf-8", errors="ignore"):
                if char in ("\r", "\n"):
                    send("\r\n")
                    cmd = buf.strip()
                    buf = ""

                    if cmd:
                        log_command(conn_id, cmd)

                        # Commandes de déconnexion
                        if cmd in ("exit", "logout", "quit"):
                            send("logout\r\n")
                            break

                        # Réponse simulée
                        response = FAKE_COMMANDS.get(cmd)
                        if response:
                            send(response + "\r\n")
                        else:
                            # Commande inconnue → message d'erreur réaliste
                            send(f"-bash: {cmd.split()[0]}: command not found\r\n")

                    send("root@ubuntu-server:~# ")

                elif char == "\x7f":  # backspace
                    if buf:
                        buf = buf[:-1]
                        send("\b \b")
                elif char == "\x03":  # Ctrl+C
                    buf = ""
                    send("^C\r\nroot@ubuntu-server:~# ")
                else:
                    buf += char
                    send(char)

    except (socket.timeout, EOFError, OSError):
        pass
    finally:
        duration = round(time.time() - start, 2)
        log.info("[SSH] Session terminée  ip=%s  durée=%ss  conn_id=%s",
                 client_ip, duration, conn_id)
        channel.close()


# ──────────────────────────────────────────────
#  Gestion d'une connexion cliente complète
# ──────────────────────────────────────────────
def handle_client(client_socket, client_addr):
    client_ip, client_port = client_addr
    log.info("[SSH] Nouvelle connexion  %s:%s", client_ip, client_port)

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNERS["ssh"]   # bannière réaliste
        transport.add_server_key(get_host_key())

        server = HoneypotSSHInterface(client_ip, client_port)
        transport.start_server(server=server)

        # Attendre qu'un channel s'ouvre
        channel = transport.accept(30)
        if channel is None:
            return

        # Attendre la demande de shell
        server.event.wait(10)

        if server.conn_id is not None:
            handle_shell(channel, server.conn_id, client_ip)

    except paramiko.SSHException as e:
        log.debug("[SSH] SSHException  %s:%s  %s", client_ip, client_port, e)
    except Exception as e:
        log.debug("[SSH] Erreur  %s:%s  %s", client_ip, client_port, e)
    finally:
        try:
            if transport:
                transport.close()
            client_socket.close()
        except Exception:
            pass


# ──────────────────────────────────────────────
#  Serveur principal
# ──────────────────────────────────────────────
def start_ssh_server():
    port = PORTS["ssh"]
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(10)
    log.info("[SSH] 🟢 Honeypot SSH démarré sur port %s", port)

    while True:
        try:
            client_sock, client_addr = server_socket.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            log.info("[SSH] Arrêt du serveur")
            break
        except Exception as e:
            log.error("[SSH] Erreur accept : %s", e)

    server_socket.close()


if __name__ == "__main__":
    # Test standalone du module SSH
    from logger import init_db
    init_db()
    start_ssh_server()
