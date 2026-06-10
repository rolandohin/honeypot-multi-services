#!/bin/bash
# ============================================================
#  HONEYPOT MULTI-SERVICES - Script de setup initial
#  Lance ce script UNE FOIS sur ta VM Ubuntu pour tout installer
# ============================================================

echo "========================================="
echo "  Honeypot Multi-Services - Setup"
echo "========================================="

# Mise à jour système
sudo apt update && sudo apt upgrade -y

# Python et pip
sudo apt install -y python3 python3-pip python3-venv

# Créer la structure du projet
mkdir -p ~/honeypot/{modules,logs,reports,keys,static}

# Environnement virtuel
cd ~/honeypot
python3 -m venv venv
source venv/bin/activate

# Dépendances
pip install paramiko asyncssh flask pyftpdlib pandas matplotlib aiosmtpd

echo ""
echo "✅ Setup terminé !"
echo "Pour activer l'env : source ~/honeypot/venv/bin/activate"
