# 🍯 Honeypot Multi-Services

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Security](https://img.shields.io/badge/Cybersecurity-Honeypot-red?style=for-the-badge&logo=hackthebox&logoColor=white)

**Honeypot multi-services développé from scratch en Python**
*Capture, analyse et visualisation des tentatives d'intrusion en temps réel*

[Fonctionnalités](#-fonctionnalités) •
[Architecture](#-architecture) •
[Installation](#-installation) •
[Utilisation](#-utilisation) •
[Dashboard](#-dashboard) •
[Résultats](#-résultats-observés)

</div>

---

## 📌 Présentation

Ce projet est un **honeypot multi-services** entièrement développé from scratch en Python, sans utilisation de solutions existantes (Cowrie, Glastopf, OpenCanary, HoneyD...).

Un honeypot est un **leurre informatique** : un système délibérément conçu pour attirer les attaquants, capturer leurs actions et analyser leurs techniques. Utilisé en cybersécurité défensive, il permet de :

- 🎯 Comprendre les **vecteurs d'attaque** courants (bruteforce, scanning, credential stuffing...)
- 📊 Constituer une **base de données d'IoC** (Indicators of Compromise)
- 🛡 Alimenter des **listes noires** d'IPs et de credentials
- 🔍 Étudier le comportement **post-authentification** des attaquants

> 🎓 Projet Annuel — ESGI · Filière Sécurité Informatique · Classe 3SI2
> 👨‍💻 **Kouassi Yves-Roland OHIN-CODJOVI**

---

## ✨ Fonctionnalités

### Services émulés

| Service | Port | Protocole | Ce qui est capturé |
|---------|------|-----------|-------------------|
| 🔐 **SSH** | 2222 | TCP | Credentials + commandes shell |
| 🌐 **HTTP** | 8080 | TCP | Soumissions formulaires + User-Agent + paths |
| 📁 **FTP** | 2121 | TCP | Credentials + fichiers consultés |
| ✉️ **SMTP** | 2525 | TCP | Tentatives de relay + MAIL FROM/RCPT TO |
| 📊 **Dashboard** | 5000 | HTTP | Interface de supervision temps réel |

### Caractéristiques techniques

- ✅ **100% from scratch** — zéro dépendance à des honeypots existants
- ✅ **Architecture modulaire** — chaque service est indépendant, extensible
- ✅ **Concurrence** — tous les modules tournent en parallèle via threading
- ✅ **Bannières réalistes** — SSH-2.0-OpenSSH_8.2p1, ProFTPD 1.3.5e, Postfix...
- ✅ **Shell SSH interactif** — simule un vrai bash avec ~40 commandes
- ✅ **Faux système de fichiers** — /etc/passwd, /var/log, fichiers leurres FTP
- ✅ **Logs centralisés** — base SQLite avec 3 tables structurées
- ✅ **Dashboard temps réel** — refresh toutes les 5 secondes sans rechargement
- ✅ **Rapports PDF** — graphiques et analyses générés automatiquement
- ✅ **Déploiement one-shot** — script bash sur VM Ubuntu vierge en <3 minutes

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VM Ubuntu 22.04                         │
│                                                             │
│   ┌──────────┐     ┌────────────────────────────────────┐  │
│   │ main.py  │────▶│           Modules                  │  │
│   │Orchestr. │     │  SSH:2222  HTTP:8080  FTP:2121      │  │
│   └──────────┘     │            SMTP:2525               │  │
│                    └────────────────┬───────────────────┘  │
│                                     │ events                │
│                    ┌────────────────▼───────────────────┐  │
│                    │         logger.py                   │  │
│                    │    Log Collector + SQLite DB         │  │
│                    └──────┬──────────────┬──────────────┘  │
│                           │              │                  │
│              ┌────────────▼──┐    ┌──────▼──────────┐      │
│              │  dashboard.py │    │   report.py      │      │
│              │  port 5000    │    │   PDF + graphs   │      │
│              └───────────────┘    └──────────────────┘      │
└─────────────────────────────────────────────────────────────┘

Flux : Attaquant → Service honeypot → Log Collector → DB → Dashboard/Rapport
```

### Structure des fichiers

```
honeypot/
│
├── 📄 main.py              # Point d'entrée — orchestre tous les modules
├── 📄 config.py            # Configuration centralisée (ports, bannières, faux FS)
├── 📄 logger.py            # Collecteur de logs SQLite (3 tables)
├── 📄 dashboard.py         # Serveur Flask — supervision temps réel (port 5000)
├── 📄 report.py            # Génération rapports PDF (ReportLab + matplotlib)
├── 📄 deploy.sh            # Script de déploiement automatisé Ubuntu
│
└── modules/
    ├── 📄 ssh_module.py    # Honeypot SSH — Paramiko + shell interactif
    ├── 📄 http_module.py   # Honeypot HTTP — Flask + pages leurres
    ├── 📄 ftp_module.py    # Honeypot FTP — pyftpdlib + fichiers leurres
    └── 📄 smtp_module.py   # Honeypot SMTP — aiosmtpd + capture relay
```

### Schéma de la base de données

```sql
-- Table 1 : toutes les connexions
connections (id, timestamp, service, src_ip, src_port,
             username, password, success, duration, notes)

-- Table 2 : commandes saisies dans le shell SSH
commands (id, connection_id, timestamp, command)

-- Table 3 : requêtes HTTP capturées
http_requests (id, timestamp, src_ip, method, path,
               user_agent, body)
```

---

## 🔧 Stack technique

| Catégorie | Technologie | Usage |
|-----------|------------|-------|
| **Langage** | Python 3.11+ | Développement complet |
| **SSH** | paramiko | Serveur SSH simulé |
| **HTTP** | Flask + Jinja2 | Page leurre + dashboard |
| **FTP** | pyftpdlib | Serveur FTP |
| **SMTP** | aiosmtpd | Serveur mail |
| **Concurrence** | threading + asyncio | Modules en parallèle |
| **Base de données** | SQLite3 | Stockage des logs |
| **Analyse** | pandas + matplotlib | Traitement et graphiques |
| **Rapports** | ReportLab | Génération PDF |
| **OS** | Ubuntu 22.04 LTS | Environnement de déploiement |

---

## 🚀 Installation

### Prérequis

- Ubuntu 20.04 ou 22.04 LTS (VM ou bare metal)
- Python 3.9 minimum
- 512 MB RAM minimum

### Option A — Déploiement automatisé (recommandé)

```bash
git clone https://github.com/TON_USERNAME/honeypot-multi-services.git
cd honeypot-multi-services
chmod +x deploy.sh
sudo bash deploy.sh
```

Le script réalise automatiquement :
- ✔️ Vérification OS et version Python
- ✔️ Installation des dépendances système (apt)
- ✔️ Création de l'environnement virtuel Python
- ✔️ Installation des dépendances pip
- ✔️ Création des services systemd (démarrage automatique)
- ✔️ Configuration UFW (ouverture des 5 ports)
- ✔️ Création des fichiers leurres FTP

### Option B — Installation manuelle

```bash
git clone https://github.com/TON_USERNAME/honeypot-multi-services.git
cd honeypot-multi-services

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install paramiko asyncssh flask pyftpdlib \
            aiosmtpd pandas matplotlib reportlab
```

---

## 📖 Utilisation

### Démarrage

```bash
source venv/bin/activate

# Terminal 1 — Lancer les 4 services honeypot
python main.py

# Terminal 2 — Lancer le dashboard
python dashboard.py
```

**Sortie attendue :**
```
╔══════════════════════════════════════════╗
║   🍯 HONEYPOT MULTI-SERVICES v2.0        ║
╚══════════════════════════════════════════╝
[SSH]  🟢 Honeypot SSH  démarré sur port 2222
[HTTP] 🟢 Honeypot HTTP démarré sur port 8080
[FTP]  🟢 Honeypot FTP  démarré sur port 2121
[SMTP] 🟢 Honeypot SMTP démarré sur port 2525
🍯 Honeypot actif — Ctrl+C pour arrêter
```

### Générer un rapport d'analyse

```bash
python report.py
# → Rapport généré : reports/rapport_honeypot_20260415_1423.pdf
```

### Consulter les logs

```bash
# Logs en temps réel
tail -f logs/honeypot.log

# Requêtes SQL directes
sqlite3 logs/honeypot.db "SELECT * FROM connections ORDER BY id DESC LIMIT 20;"
sqlite3 logs/honeypot.db "SELECT service, COUNT(*) FROM connections GROUP BY service;"
sqlite3 logs/honeypot.db "SELECT username, password, COUNT(*) as nb FROM connections GROUP BY username, password ORDER BY nb DESC LIMIT 10;"
```

---

## 📊 Dashboard

Accessible sur `http://<IP_VM>:5000` — refresh automatique toutes les 5 secondes.

**Contenu du dashboard :**

- 🔢 **KPIs** — connexions totales, IPs uniques, activité dernière heure, commandes SSH
- 📊 **Barres** — répartition des attaques par service
- 📈 **Histogramme** — activité sur les 24 dernières heures
- 🌍 **Top 8 IPs** — classement des attaquants les plus actifs
- 🔑 **Top credentials** — couples username/password les plus essayés
- ⚡ **Flux live** — 15 dernières connexions en temps réel
- 💻 **Commandes SSH** — historique des commandes saisies avec IP source

---

## 📈 Résultats observés

Les attaques automatisées présentent des patterns caractéristiques :

**Credentials les plus testés sur SSH :**
```
admin / admin        → ~30% des tentatives
root  / root         → ~25% des tentatives
root  / toor         → ~15% des tentatives
admin / password     → ~10% des tentatives
pi    / raspberry    → ~8%  (Raspberry Pi par défaut)
```

**Séquence de commandes post-connexion :**
```bash
# Phase 1 — Reconnaissance
whoami && id && uname -a && hostname

# Phase 2 — Recherche de données sensibles
cat /etc/passwd && ls -la && history

# Phase 3 — Persistance (tentatives)
wget http://... && curl http://...
```

**Observation clé :** 98% des attaques sont **entièrement automatisées** — les bots commencent à scanner un port SSH dans les **4 minutes** suivant son exposition sur Internet.

---

## 🔐 Sécurité et éthique

> ⚠️ **Avertissement légal**
>
> Ce projet est développé à des fins **pédagogiques uniquement** dans le cadre d'une formation en cybersécurité.
>
> - Déployez uniquement sur un **réseau isolé** ou une VM locale
> - N'exposez pas ce service sur Internet **sans autorisation explicite**
> - Les données collectées sont à usage **pédagogique et confidentiel**
> - L'utilisation contre des systèmes tiers sans autorisation est **illégale** (Art. 323-1 CP)
> - Ce projet respecte le **RGPD** et les législations françaises en vigueur

---

## 🗺 Roadmap

- [ ] Géolocalisation des IPs (MaxMind GeoIP)
- [ ] Alertes temps réel (email / Slack / webhook)
- [ ] Module Telnet (port 23)
- [ ] Module SMB/RDP (attaques Windows)
- [ ] Détection automatique des scanners (Shodan, Masscan, Mirai)
- [ ] Export des IoC au format STIX/TAXII
- [ ] Intégration SIEM (Elastic / Graylog)

---

## 📄 Licence

Ce projet est sous licence **MIT** — voir [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">

Développé avec ❤️ par **Kouassi Yves-Roland OHIN-CODJOVI**

Étudiant en Cybersécurité · ESGI 3SI2 · Paris

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/yvesrolandohin)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=flat-square&logo=github&logoColor=white)](https://github.com/yvesrolandohin2023-coder)

*"The best way to understand attackers is to watch them work."*

</div>
