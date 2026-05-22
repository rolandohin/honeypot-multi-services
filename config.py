# ============================================================
#  config.py — Configuration centrale du honeypot
# ============================================================

# ── Ports des services (modifie selon ta VM)
PORTS = {
    "ssh":   2222,   # 22 nécessite root, 2222 pour les tests
    "telnet": 2323,
    "http":  8080,
    "ftp":   2121,
    "smtp":  2525,
}

# ── Bandeaux réalistes (ce que voit l'attaquant)
BANNERS = {
    "ssh":    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "ftp":    "220 ProFTPD 1.3.5e Server (Debian) ready.",
    "smtp":   "220 mail.corp-internal.local ESMTP Postfix",
    "telnet": "\r\nUbuntu 20.04.5 LTS\r\nlogin: ",
}

# ── Faux credentials acceptés (pour piéger l'attaquant)
FAKE_CREDENTIALS = [
    ("admin",    "admin"),
    ("root",     "root"),
    ("admin",    "password"),
    ("user",     "123456"),
    ("admin",    "1234"),
    ("guest",    "guest"),
    ("ubuntu",   "ubuntu"),
    ("pi",       "raspberry"),
]

# ── Base de données de logs
DB_PATH = "logs/honeypot.db"

# ── Fichier de log texte (en plus de la DB)
LOG_FILE = "logs/honeypot.log"

# ── Durée max d'une session attaquant (secondes)
SESSION_TIMEOUT = 60

# ── Faux système de fichiers présenté après connexion SSH
FAKE_FS = {
    "/": ["bin", "etc", "home", "var", "tmp", "usr"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "ssh"],
    "/home": ["admin", "user"],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog", "apache2"],
    "/tmp": [],
}

# ── Réponses aux commandes SSH (simulées)
FAKE_COMMANDS = {
    "whoami":   "root",
    "id":       "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu-server 5.15.0-71-generic #78-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "ubuntu-server",
    "pwd":      "/root",
    "ls":       "Desktop  Documents  Downloads  .bash_history  .ssh",
    "ls -la":   "total 32\ndrwx------ 4 root root 4096 Jan 15 08:23 .\ndrwxr-xr-x 20 root root 4096 Jan 14 12:00 ..\n-rw------- 1 root root  220 Jan 14 .bash_logout\n-rw-r--r-- 1 root root 3526 Jan 14 .bashrc\ndrwx------ 2 root root 4096 Jan 15 08:23 .ssh\n-rw-r--r-- 1 root root  807 Jan 14 .profile",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255",
    "ip a":     "1: lo: <LOOPBACK,UP> ...\n2: eth0: <BROADCAST,MULTICAST,UP> inet 192.168.1.100/24",
    "ps aux":   "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169444 13140 ?  Ss   Jan14   0:04 /sbin/init\nroot       512  0.0  0.0  72296  5840 ?  Ss   Jan14   0:00 /usr/sbin/sshd",
    "history":  "    1  apt-get update\n    2  apt-get install apache2\n    3  cd /var/www/html\n    4  nano index.php\n    5  service apache2 restart",
    "env":      "SHELL=/bin/bash\nUSER=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nLANG=en_US.UTF-8",
}
