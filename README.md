
![Dashboard de supervision](modules/dashboard.jpg)

# Honeypot multi-services

Honeypot multi-services développé from scratch en Python, sans recourir à des
solutions existantes (Cowrie, Dionaea, OpenCanary). Il émule quatre services
réseau fréquemment ciblés, capture les interactions des attaquants et les
analyse via un tableau de bord de supervision en temps réel.

Projet annuel — ESGI, filière Sécurité Informatique.
Auteur : Kouassi Yves-Roland OHIN-CODJOVI.

## Principe

Un honeypot est un système délibérément exposé, conçu pour être attaqué. Son
intérêt n'est pas le service rendu mais l'observation : en attirant les
attaquants vers un leurre isolé, il révèle les identifiants testés, les
commandes saisies et les techniques employées, sans exposer le moindre actif
réel.

Ce projet est un honeypot d'interaction moyenne : il accepte les connexions et
capture le comportement post-authentification des attaquants, mais ne fournit
jamais de véritable interpréteur de commandes. Les réponses sont simulées,
aucune commande n'est réellement exécutée sur la machine hôte.

## Services émulés

| Service | Port (prod) | Ce qui est capturé |
|---------|-------------|--------------------|
| SSH  | 22 | Identifiants testés et commandes shell saisies |
| HTTP | 80 | Soumissions de formulaires, User-Agent, chemins scannés |
| FTP  | 21 | Identifiants testés et fichiers consultés |
| SMTP | 25 | Tentatives de relais, expéditeur et destinataires |

Le tableau de bord de supervision écoute en local sur le port 5000 et n'est
jamais exposé publiquement (accès par tunnel SSH uniquement).

## Architecture

Le honeypot repose sur un orchestrateur qui lance chaque module de service dans
un fil d'exécution distinct. Tous les modules consignent leurs observations dans
une base SQLite centralisée, exploitée par le tableau de bord et par un module
de génération de rapports. La capture et la supervision tournent en deux
processus séparés : un incident sur le tableau de bord n'interrompt jamais la
collecte.

```
Attaquants
    |
Orchestrateur (main.py)
    |
    +-- Module SSH  (port 22)
    +-- Module HTTP (port 80)
    +-- Module FTP  (port 21)
    +-- Module SMTP (port 25)
    |
Base SQLite centralisée
    |
    +-- Tableau de bord (dashboard.py)
    +-- Module de rapports (report.py)
```

## Fonctionnalités

- Développement intégral en Python, architecture modulaire et extensible.
- Émulation SSH avec shell interactif simulé et journalisation des commandes.
- Fausse interface d'administration HTTP capturant les soumissions de formulaires.
- Serveur FTP factice avec fichiers leurres.
- Capture des tentatives de relais SMTP.
- Journalisation centralisée en SQLite (mode WAL pour la concurrence).
- Tableau de bord de supervision en temps réel, style SIEM.
- Géolocalisation des adresses sources via base GeoLite2 locale (hors-ligne).
- Déploiement automatisé avec configuration test / production.

## Installation

Sur une machine Ubuntu 22.04 :

```bash
git clone https://github.com/rolandohin/honeypot-multi-services.git
cd honeypot-multi-services
sudo bash deploy.sh
```

Le script installe les dépendances, crée l'environnement Python, télécharge la
base de géolocalisation et configure les services systemd en mode production.

## Utilisation

Démarrage via systemd (collecte permanente) :

```bash
sudo systemctl start honeypot
sudo systemctl start honeypot-dashboard
sudo systemctl enable honeypot honeypot-dashboard
```

Lancement manuel en mode test (ports hauts, sans privilèges root) :

```bash
source venv/bin/activate
python main.py
```

## Accès au tableau de bord

Le tableau de bord n'est pas exposé sur Internet. On y accède par tunnel SSH
depuis son poste :

```bash
ssh -p <PORT_ADMIN> -L 5000:localhost:5000 <user>@<IP_SERVEUR>
```

Puis ouvrir `http://localhost:5000` dans le navigateur.

## Sécurité du dispositif

Un honeypot attire délibérément des attaquants ; il doit donc être lui-même
irréprochable. Les mesures retenues :

- Déploiement sur un serveur dédié et isolé, sans donnée sensible.
- SSH d'administration déplacé sur un port dédié, login root désactivé,
  authentification par clé.
- Pare-feu en liste blanche : seuls les ports honeypot et le port
  d'administration sont ouverts ; le tableau de bord reste fermé.
- Audit du code ayant conduit à corriger une injection de patron côté serveur
  (SSTI) dans le module HTTP.
- Aucune commande réellement exécutée : l'attaquant n'obtient jamais un vrai shell.

## Stack technique

Python, Paramiko (SSH), Flask (HTTP et dashboard), pyftpdlib (FTP),
aiosmtpd (SMTP), SQLite, geoip2 / GeoLite2 (géolocalisation).

## Avertissement

Ce projet est développé à des fins pédagogiques et défensives. Il doit être
déployé sur une infrastructure isolée et ne jamais être utilisé contre des
systèmes tiers sans autorisation. Les adresses collectées le sont à usage
pédagogique uniquement.
