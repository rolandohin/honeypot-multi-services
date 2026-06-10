# ============================================================
#  modules/smtp_module.py — Honeypot SMTP
#  Capture les tentatives d'envoi de mail et commandes SMTP
# ============================================================

import asyncio
import sys
import os
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import PORTS, BANNERS
from logger import log_connection, log_smtp, log, init_db


class HoneypotSMTPHandler:
    """Handler appelé à chaque mail reçu."""

    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        log.info("[SMTP] EHLO reçu  ip=%s  hostname=%s", session.peer, hostname)
        # IMPORTANT : marquer la session comme saluee, sinon aiosmtpd refuse
        # les commandes MAIL/RCPT suivantes avec "send HELO first".
        session.host_name = hostname
        # On reconstruit la liste de reponses avec une banniere realiste
        responses = [
            "250-honeypot.corp-internal.local",
            "250-SIZE 10240000",
            "250-AUTH LOGIN PLAIN",
            "250 HELP",
        ]
        return responses

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        log.info("[SMTP] MAIL FROM  ip=%s  from=%s", session.peer, address)
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        log.info("[SMTP] RCPT TO  ip=%s  to=%s", session.peer, address)
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        ip = session.peer[0] if session.peer else "unknown"
        body = envelope.content.decode("utf-8", errors="ignore")

        log.info("[SMTP] Mail reçu  ip=%s  from=%s  to=%s",
                 ip, envelope.mail_from, envelope.rcpt_tos)

        # Enregistre le message dans la table SMTP dediee
        log_smtp(
            src_ip=ip,
            mail_from=envelope.mail_from,
            rcpt_to=envelope.rcpt_tos,
            body=body[:2000]   # on conserve jusqu'a 2000 caracteres du corps
        )

        # Enregistre aussi la connexion pour les stats par service
        log_connection(
            service="smtp",
            src_ip=ip,
            username=envelope.mail_from,
            success=True,
            notes=f"to={envelope.rcpt_tos}"
        )
        return "250 Message accepted"


def start_smtp_server():
    handler = HoneypotSMTPHandler()
    port = PORTS["smtp"]

    controller = Controller(
        handler,
        hostname="0.0.0.0",
        port=port,
        ident=BANNERS["smtp"],
    )
    controller.start()
    log.info("[SMTP] 🟢 Honeypot SMTP démarré sur port %s", port)

    # Maintien du thread
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    init_db()
    start_smtp_server()
