# Guide de déploiement VPS — Honeypot Multi-Services

Ce guide explique comment déployer le honeypot sur un VPS exposé à Internet
pour collecter de **vraies attaques**, en toute sécurité. À lire en entier
avant de commencer.

---

## ⚠️ Règle d'or

Le honeypot va prendre le **port 22**, celui que les bots attaquent.
Votre SSH d'administration doit donc **déménager AVANT** sur un autre port.
Si vous lancez le honeypot sur le 22 alors que votre SSH y est encore,
**vous perdez l'accès à votre propre serveur.**

Ordre obligatoire : (1) durcir le VPS → (2) tester le nouvel accès admin →
(3) seulement ensuite, lancer le honeypot.

---

## Étape 0 — Choisir et commander un VPS

- **Recommandé : Hetzner CX22** (~4 €/mois, datacenter Allemagne, RGPD) ou
  **OVH VPS** (français, argument de souveraineté en soutenance).
- Prenez le **moins cher** : un honeypot pédagogique n'a besoin de rien de
  puissant, et il ne contiendra aucune donnée de valeur.
- OS : **Ubuntu 22.04 LTS** (conforme au cahier des charges).
- À la commande, ajoutez votre **clé SSH publique** (fortement recommandé,
  évite les mots de passe).

---

## Étape 1 — Première connexion et mise à jour

```bash
# Connexion initiale (port 22 par défaut, avant durcissement)
ssh root@IP_DU_VPS

# Mise à jour
apt-get update && apt-get upgrade -y

# Créer un utilisateur non-root pour l'administration
adduser yvesadmin
usermod -aG sudo yvesadmin

# Copier votre clé SSH vers ce nouvel utilisateur (depuis VOTRE machine) :
#   ssh-copy-id -p 22 yvesadmin@IP_DU_VPS
```

---

## Étape 2 — Durcir le VPS (déplace le SSH admin)

Transférez le projet sur le VPS puis lancez le script de durcissement.

```bash
# Depuis votre machine locale, envoyez l'archive :
scp honeypot_final.zip yvesadmin@IP_DU_VPS:~/

# Sur le VPS :
unzip honeypot_final.zip
cd honeypot
sudo bash harden_vps.sh
```

Le script va :
- déplacer votre SSH d'administration sur le **port 49222** (modifiable en
  haut du script via `ADMIN_SSH_PORT`),
- désactiver le login root et forcer l'authentification par clé,
- configurer le pare-feu UFW (ouvre 22/80/21/25 pour le honeypot, 49222 pour vous),
- redémarrer SSH.

**Ne fermez pas votre session actuelle.** Le script vous demandera de tester
le nouvel accès dans un autre terminal.

---

## Étape 3 — Tester le nouvel accès admin (CRITIQUE)

Dans un **nouveau terminal**, sans fermer l'ancien :

```bash
ssh -p 49222 yvesadmin@IP_DU_VPS
```

Si ça marche → vous pouvez fermer l'ancienne session. Le port 22 est libre.
Si ça ne marche pas → revenez à l'ancienne session et corrigez avant tout.

---

## Étape 4 — Installer et lancer le honeypot (mode production)

```bash
cd ~/honeypot
sudo bash deploy.sh          # installe les dépendances Python (venv)

# Lancer en mode PRODUCTION (ports réels 22/80/21/25)
# Le -E préserve la variable d'environnement avec sudo
source venv/bin/activate
HONEYPOT_ENV=production sudo -E venv/bin/python main.py
```

Pour un fonctionnement permanent (recommandé pour collecter sur plusieurs
semaines), utilisez les services systemd créés par `deploy.sh`, en ajoutant
`Environment=HONEYPOT_ENV=production` dans le fichier de service, puis :

```bash
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo systemctl status honeypot
```

---

## Étape 5 — Consulter le dashboard SANS l'exposer

Le dashboard ne doit **jamais** être ouvert sur Internet (il révélerait que
c'est un honeypot et exposerait vos données). On y accède par **tunnel SSH** :

```bash
# Depuis VOTRE machine :
ssh -p 49222 -L 5000:localhost:5000 yvesadmin@IP_DU_VPS

# Puis, sur le VPS, lancez le dashboard :
cd ~/honeypot && source venv/bin/activate && python dashboard.py

# Enfin, sur VOTRE navigateur :
#   http://localhost:5000
```

Le trafic passe par le tunnel chiffré : personne d'autre ne voit le dashboard.

---

## Étape 6 — Laisser tourner et collecter

- Laissez le honeypot tourner **2 à 4 semaines** avant la soutenance.
- Sur le port 22, attendez-vous à des **centaines à milliers** de tentatives
  SSH, surtout les premiers jours.
- Vérifiez périodiquement le dashboard et sauvegardez la base de données :

```bash
# Sauvegarde de la base (depuis votre machine)
scp -P 49222 yvesadmin@IP_DU_VPS:~/honeypot/logs/honeypot.db ./honeypot_collecte_$(date +%Y%m%d).db
```

Cette base de **vraies attaques** sera votre meilleur atout en soutenance.

---

## Sécurité du dispositif (à expliquer au jury)

- VPS **jetable**, sans aucune donnée personnelle ni accès à d'autres systèmes.
- SSH admin sur **port discret**, login root désactivé, authentification par clé.
- Dashboard **non exposé**, accessible uniquement par tunnel SSH.
- Snapshots réguliers du VPS pour restauration en cas de compromission.
- Le honeypot émule les services mais ne donne **jamais** un vrai shell :
  les commandes sont simulées, l'attaquant n'exécute rien de réel.
- Conformité RGPD : les IP collectées le sont à usage pédagogique uniquement,
  conservation limitée à la durée du projet.

---

## En cas de blocage

Si vous perdez l'accès SSH (mauvais port, pare-feu) : la plupart des hébergeurs
(Hetzner, OVH) offrent une **console VNC/KVM web** dans leur interface, qui
permet de reprendre la main directement sur la machine sans SSH. Gardez
l'identifiant de connexion à cette console à portée de main.
