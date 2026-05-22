#!/bin/bash
# ============================================================
#  deploy.sh — Déploiement automatisé du Honeypot Multi-Services
#  Usage : sudo bash deploy.sh
#  Testé sur Ubuntu 20.04 / 22.04 LTS
# ============================================================

set -e  # Arrêt immédiat si une commande échoue

# ── Couleurs terminal
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

INSTALL_DIR="$HOME/honeypot"
SERVICE_USER="$USER"
LOG_DIR="$INSTALL_DIR/logs"
VENV="$INSTALL_DIR/venv"

banner() {
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════════════╗"
  echo "║   🍯 HONEYPOT MULTI-SERVICES — DEPLOIEMENT   ║"
  echo "║   ESGI · Projet Annuel · Sécurité Info        ║"
  echo "╚══════════════════════════════════════════════╝"
  echo -e "${NC}"
}

step() { echo -e "\n${BOLD}${CYAN}[STEP]${NC} $1"; }
ok()   { echo -e "${GREEN}  ✅ $1${NC}"; }
warn() { echo -e "${YELLOW}  ⚠  $1${NC}"; }
err()  { echo -e "${RED}  ❌ $1${NC}"; exit 1; }

# ── Vérifie qu'on est bien sur Ubuntu
check_os() {
  step "Vérification du système"
  if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    warn "OS non Ubuntu détecté — le script peut nécessiter des adaptations"
  else
    ok "Ubuntu détecté"
  fi

  # Python 3.9+
  PY_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
  if [ "$PY_VER" -lt 9 ]; then
    err "Python 3.9+ requis (trouvé 3.$PY_VER)"
  fi
  ok "Python $(python3 --version)"
}

# ── Mise à jour & dépendances système
install_deps() {
  step "Installation des dépendances système"
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    sqlite3 net-tools curl git \
    2>/dev/null
  ok "Dépendances système installées"
}

# ── Structure des dossiers
create_structure() {
  step "Création de la structure du projet"
  mkdir -p "$INSTALL_DIR"/{modules,logs,keys,static,reports}

  # Faux répertoire FTP
  mkdir -p /tmp/honeypot_ftp
  cat > /tmp/honeypot_ftp/README.txt     <<< "Corporate backup files - Confidential"
  cat > /tmp/honeypot_ftp/passwords.txt  <<< "# DO NOT SHARE\nadmin:C0rp0r@te2024!\nroot:Sup3rS3cr3t!"
  cat > /tmp/honeypot_ftp/config.ini     <<< "[database]\nhost=10.0.1.20\nuser=dbadmin\npassword=Db@2024!"
  cat > /tmp/honeypot_ftp/backup_2024.sql <<< "-- MySQL dump\n-- Database: corporate_db"
  ok "Structure créée : $INSTALL_DIR"
}

# ── Environnement Python virtuel
setup_venv() {
  step "Configuration de l'environnement Python"
  cd "$INSTALL_DIR"

  if [ ! -d "$VENV" ]; then
    python3 -m venv venv
    ok "Environnement virtuel créé"
  else
    ok "Environnement virtuel existant conservé"
  fi

  source "$VENV/bin/activate"

  pip install --quiet --upgrade pip
  pip install --quiet \
    paramiko \
    asyncssh \
    flask \
    pyftpdlib \
    aiosmtpd \
    pandas \
    matplotlib \
    seaborn \
    reportlab

  ok "Dépendances Python installées"
  deactivate
}

# ── Service systemd (optionnel, lance au démarrage)
setup_systemd() {
  step "Configuration du service systemd"

  HONEYPOT_SERVICE="/etc/systemd/system/honeypot.service"
  DASHBOARD_SERVICE="/etc/systemd/system/honeypot-dashboard.service"

  sudo tee "$HONEYPOT_SERVICE" > /dev/null <<EOF
[Unit]
Description=Honeypot Multi-Services (ESGI PA)
After=network.target
Wants=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV}/bin/python ${INSTALL_DIR}/main.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${LOG_DIR}/honeypot.log
StandardError=append:${LOG_DIR}/honeypot_err.log

[Install]
WantedBy=multi-user.target
EOF

  sudo tee "$DASHBOARD_SERVICE" > /dev/null <<EOF
[Unit]
Description=Honeypot Dashboard (ESGI PA)
After=network.target honeypot.service
Wants=honeypot.service

[Service]
Type=simple
User=${SERVICE_USER}
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
  ok "Services systemd créés"
  echo -e "  ${CYAN}Commandes utiles :${NC}"
  echo "    sudo systemctl start  honeypot"
  echo "    sudo systemctl start  honeypot-dashboard"
  echo "    sudo systemctl enable honeypot  # démarrage auto"
  echo "    sudo systemctl status honeypot"
}

# ── Règles UFW (pare-feu)
setup_firewall() {
  step "Configuration du pare-feu (UFW)"
  if command -v ufw &>/dev/null; then
    sudo ufw allow 2222/tcp comment "Honeypot SSH"   2>/dev/null || true
    sudo ufw allow 8080/tcp comment "Honeypot HTTP"  2>/dev/null || true
    sudo ufw allow 2121/tcp comment "Honeypot FTP"   2>/dev/null || true
    sudo ufw allow 2525/tcp comment "Honeypot SMTP"  2>/dev/null || true
    sudo ufw allow 5000/tcp comment "Honeypot Dashboard" 2>/dev/null || true
    ok "Ports ouverts dans UFW"
  else
    warn "UFW non installé — pas de règles pare-feu"
  fi
}

# ── Résumé final
summary() {
  IP=$(hostname -I | awk '{print $1}')
  echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗"
  echo    "║   ✅  DÉPLOIEMENT TERMINÉ                 ║"
  echo -e "╚══════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${CYAN}IP de la VM :${NC}      $IP"
  echo ""
  echo -e "  ${CYAN}Pour démarrer :${NC}"
  echo    "    cd $INSTALL_DIR"
  echo    "    source venv/bin/activate"
  echo    ""
  echo    "    # Terminal 1 — honeypot"
  echo    "    python main.py"
  echo    ""
  echo    "    # Terminal 2 — dashboard"
  echo    "    python dashboard.py"
  echo    ""
  echo -e "  ${CYAN}Accès dashboard :${NC}  http://$IP:5000"
  echo ""
  echo -e "  ${CYAN}Ports actifs :${NC}"
  echo    "    SSH   → $IP:2222"
  echo    "    HTTP  → $IP:8080"
  echo    "    FTP   → $IP:2121"
  echo    "    SMTP  → $IP:2525"
  echo ""
  echo -e "  ${CYAN}Logs :${NC}             $LOG_DIR/"
  echo -e "  ${CYAN}Base de données :${NC}  $LOG_DIR/honeypot.db"
  echo ""
}

# ── MAIN
banner
check_os
install_deps
create_structure
setup_venv
setup_systemd
setup_firewall
summary
