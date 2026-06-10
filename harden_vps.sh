#!/bin/bash
# ============================================================
#  harden_vps.sh - Durcissement du VPS avant deploiement honeypot
#  Projet Annuel ESGI - Honeypot Multi-Services
#
#  CE SCRIPT DOIT ETRE LANCE EN PREMIER, AVANT le honeypot.
#  Il deplace votre SSH d'administration sur un port discret
#  pour LIBERER le port 22 au profit du honeypot.
#
#  Usage : sudo bash harden_vps.sh
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

# ── Port choisi pour le VRAI SSH d'administration.
#    Choisissez un port haut, peu commun. NE PAS utiliser 2222
#    (le honeypot SSH pourra l'utiliser en interne).
ADMIN_SSH_PORT=49222

step() { echo -e "\n${BOLD}${CYAN}[ETAPE]${NC} $1"; }
ok()   { echo -e "${GREEN}  [OK] $1${NC}"; }
warn() { echo -e "${YELLOW}  [!] $1${NC}"; }
err()  { echo -e "${RED}  [ERREUR] $1${NC}"; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Lancez ce script avec sudo."

echo -e "${CYAN}${BOLD}"
echo "============================================================"
echo "  DURCISSEMENT VPS - Preparation deploiement honeypot"
echo "============================================================"
echo -e "${NC}"
warn "Ce script va deplacer votre SSH d'administration sur le port ${ADMIN_SSH_PORT}."
warn "GARDEZ VOTRE SESSION ACTUELLE OUVERTE jusqu'a avoir teste la nouvelle."
echo ""
read -p "Continuer ? (oui/non) " confirm
[ "$confirm" = "oui" ] || { echo "Annule."; exit 0; }

# ── 1. Sauvegarde de la config SSH
step "Sauvegarde de la configuration SSH actuelle"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)
ok "Sauvegarde creee"

# ── 2. Deplacement du SSH admin sur un port discret
step "Deplacement du SSH d'administration sur le port ${ADMIN_SSH_PORT}"
if grep -qE "^#?Port " /etc/ssh/sshd_config; then
  sed -i "s/^#\?Port .*/Port ${ADMIN_SSH_PORT}/" /etc/ssh/sshd_config
else
  echo "Port ${ADMIN_SSH_PORT}" >> /etc/ssh/sshd_config
fi

# ── 3. Durcissement SSH de base
step "Durcissement de la configuration SSH"
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/'        /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PubkeyAuthentication .*/PubkeyAuthentication yes/'     /etc/ssh/sshd_config
ok "Root login desactive, authentification par cle uniquement"
warn "ASSUREZ-VOUS d'avoir une cle SSH installee, sinon vous serez bloque !"
warn "Si vous utilisez encore un mot de passe, NE relancez PAS sshd maintenant."
echo ""
read -p "Avez-vous bien une cle SSH configuree pour vous connecter ? (oui/non) " haskey
if [ "$haskey" != "oui" ]; then
  warn "PasswordAuthentication reactive pour ne pas vous bloquer."
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
fi

# ── 4. Pare-feu UFW
step "Configuration du pare-feu (UFW)"
apt-get install -y -qq ufw >/dev/null 2>&1 || true
ufw --force reset >/dev/null

# Admin SSH (votre acces)
ufw allow ${ADMIN_SSH_PORT}/tcp comment "Admin SSH"

# Ports honeypot exposes aux attaquants
ufw allow 22/tcp   comment "Honeypot SSH"
ufw allow 80/tcp   comment "Honeypot HTTP"
ufw allow 21/tcp   comment "Honeypot FTP"
ufw allow 25/tcp   comment "Honeypot SMTP"

# Plage FTP passif
ufw allow 60000:60100/tcp comment "Honeypot FTP passif"

# Dashboard : NE PAS exposer publiquement. Acces via tunnel SSH uniquement.
# (volontairement non ouvert dans UFW)

ufw --force enable
ok "Pare-feu configure"
echo ""
echo -e "  ${CYAN}Ports ouverts :${NC}"
echo "    ${ADMIN_SSH_PORT}/tcp  -> VOTRE acces admin (a retenir !)"
echo "    22, 80, 21, 25       -> honeypot (exposes aux attaquants)"
echo "    Dashboard (5000)     -> NON expose, via tunnel SSH uniquement"

# ── 5. Redemarrage SSH
step "Application de la nouvelle configuration SSH"
warn "Le service SSH va redemarrer sur le port ${ADMIN_SSH_PORT}."
warn "OUVREZ UN NOUVEAU TERMINAL et testez AVANT de fermer celui-ci :"
echo ""
echo -e "    ${BOLD}ssh -p ${ADMIN_SSH_PORT} votre_user@IP_DU_VPS${NC}"
echo ""
read -p "Pret a redemarrer SSH ? (oui/non) " restart
if [ "$restart" = "oui" ]; then
  systemctl restart ssh || systemctl restart sshd
  ok "SSH redemarre sur le port ${ADMIN_SSH_PORT}"
  echo ""
  echo -e "${RED}${BOLD}  >>> NE FERMEZ PAS cette session avant d'avoir teste la nouvelle <<<${NC}"
else
  warn "SSH non redemarre. Relancez 'systemctl restart ssh' quand vous serez pret."
fi

# ── 6. Resume
echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}  Durcissement termine.${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo ""
echo -e "  Prochaines etapes :"
echo "    1. Testez votre acces admin : ssh -p ${ADMIN_SSH_PORT} user@IP"
echo "    2. Une fois confirme, le port 22 est libre pour le honeypot"
echo "    3. Deployez le honeypot avec la config production (ports reels)"
echo "    4. Accedez au dashboard via tunnel :"
echo "       ssh -p ${ADMIN_SSH_PORT} -L 5000:localhost:5000 user@IP"
echo "       puis ouvrez http://localhost:5000 dans votre navigateur"
echo ""
