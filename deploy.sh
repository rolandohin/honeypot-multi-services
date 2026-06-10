#!/bin/bash
# ============================================================
#  deploy.sh - Deploiement automatise du Honeypot Multi-Services
#  Projet Annuel ESGI - Securite Informatique
#  Usage : sudo bash deploy.sh
#  Cible : Ubuntu 22.04 LTS
#
#  NOTE IMPORTANTE :
#  Ce script installe les dependances, cree l'environnement
#  Python et configure les services systemd en mode PRODUCTION.
#  Il NE touche PAS a la configuration SSH (deplacement du port
#  d'administration) ni au pare-feu : ces etapes de durcissement
#  sont realisees separement et volontairement a la main, pour
#  garder le controle de l'acces au serveur. Voir le guide de
#  deploiement pour la procedure complete.
# ============================================================

set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="$HOME/honeypot"
SERVICE_USER="$USER"
LOG_DIR="$INSTALL_DIR/logs"
VENV="$INSTALL_DIR/venv"

step() { echo -e "\n${BOLD}${CYAN}[ETAPE]${NC} $1"; }
ok()   { echo -e "${GREEN}  [OK] $1${NC}"; }
warn() { echo -e "${YELLOW}  [!] $1${NC}"; }

echo -e "${CYAN}${BOLD}"
echo "============================================================"
echo "  HONEYPOT MULTI-SERVICES - Deploiement"
echo "  ESGI - Projet Annuel - Securite Informatique"
echo "============================================================"
echo -e "${NC}"

# ── 1. Verification systeme
step "Verification du systeme"
if grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
  ok "Ubuntu detecte"
else
  warn "OS non Ubuntu - adaptations possibles"
fi
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PY_MINOR" -lt 9 ]; then
  echo "  Python 3.9+ requis (trouve 3.$PY_MINOR)"; exit 1
fi
ok "Python $(python3 --version)"

# ── 2. Dependances systeme
step "Installation des dependances systeme"
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv sqlite3 curl
ok "Dependances systeme installees"

# ── 3. Environnement Python
step "Configuration de l'environnement Python"
cd "$INSTALL_DIR"
if [ ! -d "$VENV" ]; then
  python3 -m venv venv
  ok "Environnement virtuel cree"
else
  ok "Environnement virtuel existant conserve"
fi
source "$VENV/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet paramiko pyftpdlib aiosmtpd flask geoip2
ok "Dependances Python installees"
deactivate

# ── 4. Base de geolocalisation (telechargement si absente)
step "Base de geolocalisation GeoLite2"
mkdir -p "$INSTALL_DIR/geoip"
if [ ! -f "$INSTALL_DIR/geoip/GeoLite2-Country.mmdb" ]; then
  curl -sL -o "$INSTALL_DIR/geoip/GeoLite2-Country.mmdb" \
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb" || \
    warn "Telechargement GeoLite2 echoue - la geolocalisation sera desactivee"
  [ -f "$INSTALL_DIR/geoip/GeoLite2-Country.mmdb" ] && ok "Base GeoLite2 telechargee"
else
  ok "Base GeoLite2 deja presente"
fi

# ── 5. Structure des dossiers
step "Creation de la structure"
mkdir -p "$LOG_DIR" "$INSTALL_DIR/keys"
ok "Dossiers crees"

# ── 6. Services systemd (mode PRODUCTION)
step "Configuration des services systemd"

sudo tee /etc/systemd/system/honeypot.service > /dev/null <<EOF
[Unit]
Description=Honeypot Multi-Services (ESGI PA)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=HONEYPOT_ENV=production
ExecStart=${VENV}/bin/python ${INSTALL_DIR}/main.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/honeypot.log
StandardError=append:${LOG_DIR}/honeypot_err.log

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/honeypot-dashboard.service > /dev/null <<EOF
[Unit]
Description=Honeypot Dashboard (ESGI PA)
After=network.target honeypot.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV}/bin/python ${INSTALL_DIR}/dashboard.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/dashboard.log
StandardError=append:${LOG_DIR}/dashboard_err.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
ok "Services systemd crees (mode production)"

# ── 7. Resume
IP=$(hostname -I | awk '{print $1}')
echo -e "\n${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}  DEPLOIEMENT TERMINE${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo ""
echo -e "  ${CYAN}Demarrer le honeypot et le dashboard :${NC}"
echo "    sudo systemctl start honeypot"
echo "    sudo systemctl start honeypot-dashboard"
echo "    sudo systemctl enable honeypot honeypot-dashboard   # demarrage auto"
echo ""
echo -e "  ${CYAN}Ports honeypot (production) :${NC} SSH:22  HTTP:80  FTP:21  SMTP:25"
echo ""
echo -e "  ${YELLOW}PREREQUIS DE SECURITE (a faire AVANT, manuellement) :${NC}"
echo "    - Deplacer le SSH d'administration sur un port dedie (ex: 49222)"
echo "      pour liberer le port 22 au profit du honeypot"
echo "    - Configurer le pare-feu (UFW) : autoriser le port admin +"
echo "      22/80/21/25, SANS exposer le dashboard (port 5000)"
echo ""
echo -e "  ${CYAN}Acces au dashboard (jamais expose publiquement) :${NC}"
echo "    Via tunnel SSH depuis votre poste :"
echo "    ssh -p <PORT_ADMIN> -L 5000:localhost:5000 <user>@${IP}"
echo "    puis ouvrir http://localhost:5000 dans le navigateur"
echo ""
