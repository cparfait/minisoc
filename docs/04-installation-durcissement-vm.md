# Installation et durcissement de la VM Mini-SOC (sur le LAN, sans réseau d'administration)

Ce document décrit l'installation pas à pas de la VM et son durcissement. Il complète
[03-preparation-vm.md](03-preparation-vm.md) (dimensionnement, flux réseau, comptes à préparer).

Référence : **Debian 13** (les commandes sont identiques sous Ubuntu 24.04, sauf mention contraire).

> **Installation automatique (recommandée)** : l'ISO générée par `deploy/iso/build-iso.sh` applique seule les
> § 3 à 8 (voir [§ 2 bis](#2-bis-installation-automatique-par-liso-mini-soc)). Le reste du document sert de
> référence et de procédure manuelle.
Les adresses IP en `192.168.x.x` sont des **exemples à remplacer**.

---

## 0. Pourquoi un durcissement renforcé

Le Mini-SOC concentre des informations sensibles : journaux de connexion, comptes à privilèges, alertes EDR,
jetons d'accès à HarfangLab, au pare-feu et à Microsoft 365. Un attaquant qui le compromet voit ce que vous voyez,
peut effacer ses traces et peut se servir des jetons.

Sans réseau d'administration, la VM est joignable par **tous les postes du LAN**, y compris un poste compromis.
On compense par six règles :

| # | Règle | Moyen |
| --- | --- | --- |
| 1 | La VM n'accepte que des sources connues | Pare-feu local en liste blanche (machine **et** conteneurs) |
| 2 | L'administration ne se fait que depuis 2 ou 3 postes DSI désignés | SSH par clé + filtrage IP ; interface web en double authentification |
| 3 | La VM n'initie que les flux nécessaires | Filtrage sortant local + règle sur le Sophos XGS pour Internet |
| 4 | Les journaux sensibles ne circulent pas en clair | Syslog chiffré (TLS, 6514) pour les serveurs Windows |
| 5 | La VM est elle-même surveillée | Agent HarfangLab, journal d'audit Linux, alertes « source silencieuse » |
| 6 | Une compromission de la VM ne détruit pas les sauvegardes | Sauvegardes chiffrées, **récupérées** par un serveur tiers (la VM ne peut pas les effacer) |

> **Option fortement conseillée, sans matériel supplémentaire** : placer la VM seule dans un **VLAN dédié**
> routé par le Sophos XGS. Ce n'est pas un réseau d'administration complet, mais le XGS filtre et journalise
> alors tous les flux vers et depuis la VM. Un poste du LAN ne peut plus l'atteindre directement, ni usurper une
> adresse sur son segment (ARP). Le reste de ce document s'applique tel quel : le pare-feu local reste une
> seconde barrière.

---

## 1. Inventaire à remplir avant de commencer

| Élément | Valeur (exemple) |
| --- | --- |
| Nom DNS de la VM | `minisoc.mairie.local` |
| IP fixe de la VM / masque / passerelle | `192.168.10.50/24`, passerelle `192.168.10.1` |
| Postes DSI autorisés à administrer (SSH + web) | `192.168.10.21`, `192.168.10.22` (réservations DHCP **obligatoires**) |
| Écran mural | `192.168.10.40` |
| Serveurs analysés par l'agent Trivy (rapports en 443) | serveurs Docker ou Linux à suivre |
| Serveurs DNS / NTP (contrôleurs de domaine) | `192.168.10.2`, `192.168.10.3` |
| Sophos XGS (syslog + API 4444) | `192.168.10.1` |
| Serveurs envoyant leurs journaux Windows (NXLog) | contrôleurs de domaine, serveurs de fichiers |
| Vectra, Varonis (CEF) | IP des appliances |
| Relais SMTP | `192.168.10.8:587` |
| Serveur CrowdSec | `192.168.10.9:8080` |
| Serveur qui récupère les sauvegardes | `192.168.10.60` (NAS, serveur de sauvegarde) |
| Ollama interne (si utilisé) | `192.168.10.30:11434` |

---

## 2. Création de la VM (hyperviseur)

- **Deux disques** :
  - disque 1 : 40 Go (système) ;
  - disque 2 : 500 Go SSD (données Docker, monté sur `/var/lib/docker`).
  
  Un disque de données plein ne bloque alors pas le système, et sa taille s'ajuste séparément.
- 8 vCPU, 16 Go de RAM, **une seule carte réseau**.
- Démarrage sécurisé UEFI (Secure Boot) activé si l'hyperviseur le permet.
- Pas de dossier partagé, de presse-papiers partagé ni de périphérique USB redirigé.
- Accès à la console de la VM limité aux administrateurs de l'hyperviseur, avec des comptes nominatifs.
- Si l'hyperviseur sait chiffrer les disques des VM (vTPM + chiffrement), l'activer : les sauvegardes de la VM
  contiennent alors des données chiffrées.

---

## 2 bis. Installation automatique par l'ISO Mini-SOC

L'ISO est construite sur un poste disposant de Docker, à partir de l'ISO netinst officielle de Debian
(téléchargée et vérifiée par son empreinte SHA-512). Elle ne contient **aucun secret**.

```bash
cp deploy/iso/vm.conf.example deploy/iso/vm.conf     # facultatif : réseau, NTP, proxy, plage Docker
docker run --rm -v "${PWD}:/work" -w /work debian:13-slim sh deploy/iso/build-iso.sh
```

Résultat : `build/iso/minisoc-debian-13.x-amd64-auto-<date>-<heure>-<commit>.iso` (et son empreinte `.sha256`),
suffixé `-modifie` si des changements n'étaient pas commités ; les ISO précédentes de
`build/iso/` sont effacées une fois la nouvelle prête. Une valeur laissée vide
dans `vm.conf` (IP, masque, passerelle, DNS, domaine, mot de passe d'`adminsoc`) est demandée pendant
l'installation. Des clés SSH publiques peuvent être placées dans `deploy/iso/authorized_keys` (une par ligne) ;
sinon `sudo minisoc-setup` les demande ensuite.

**Plage Docker** (`DOCKER_POOL`, défaut `10.255.0.0/16`) : les réseaux internes de Docker y sont pris. Elle doit
être **hors de toute plage utilisée** (LAN, VLAN, sites distants, VPN), sinon la VM ne joint plus les machines de
cette plage. Le premier démarrage vérifie qu'elle ne chevauche ni le réseau de la VM, ni sa passerelle, ses DNS ou
ses serveurs de temps.

**Dans vSphere (VxRail)** :

1. Déposer l'ISO dans le datastore vSAN (Datastore › Fichiers › Charger).
2. Nouvelle VM : système invité *Linux › Debian GNU/Linux 12 (64 bits)* ou plus récent selon la version de vSphere,
   8 vCPU, 16 Go, **disque 1 : 40 Go**, **disque 2 : 500 Go** (provisionnement fin possible), carte **VMXNET3**
   sur le port group du LAN (ou du VLAN dédié), contrôleur PVSCSI ou LSI. Options de démarrage : **EFI** et
   **démarrage sécurisé** cochés. Lecteur CD : l'ISO, « connecter à la mise sous tension ».
3. Démarrer, ouvrir la console, valider l'entrée « Mini-SOC : installation automatique » avec **Entrée** (le menu
   attend volontairement : une VM qui redémarrerait sur le CD ne se réinstalle pas seule). Répondre aux
   questions éventuelles (réseau, mot de passe) : le clavier est déjà en **AZERTY**, pendant l'installation
   comme ensuite sur la console de la VM (chiffres de l'adresse IP : Maj ou pavé numérique).
4. La VM redémarre et termine seule (15 à 30 minutes, journal sur la console et dans
   `/var/log/minisoc-firstboot.log`). Elle vérifie d'abord que les serveurs Internet listés ci-dessous sont
   joignables : sinon elle **se met en pause**, affiche ceux à autoriser sur le XGS (nom et port) et réessaie
   chaque minute (`sudo touch /run/minisoc-firstboot-sans-controle` pour passer outre). Ensuite :
   - disque de données formaté et monté sur `/var/lib/docker` ;
   - Docker (§ 5) et durcissement (§ 4) ;
   - Mini-SOC installé dans `/opt/minisoc`, `.env` créé, certificats syslog TLS générés, application construite
     et démarrée (§ 7) ;
   - pare-feu actif en **mode initial** : seules les plages privées sont acceptées (§ 6) ;
   - sauvegardes chiffrées planifiées (§ 8).
5. Se connecter (console ou `ssh adminsoc@<IP>`) et lancer **`sudo minisoc-setup`** : console de paramétrage en
   menus (postes DSI, écran mural, sources syslog, AD, SMTP, XGS, CrowdSec, ports SaaS, serveur de sauvegarde,
   clés et port SSH, certificat web, compte de secours, jeton de l'écran mural, fichiers à déployer, état de la VM).
   « Appliquer » arme un **retour arrière automatique** de 3 minutes : sans confirmation depuis une nouvelle
   session, l'ancienne configuration du pare-feu et de SSH est rétablie.
6. Retirer l'ISO du lecteur CD de la VM, puis faire un instantané « installation terminée ».

Accès Internet nécessaires pendant l'installation (en 80 et 443) : `deb.debian.org`, `security.debian.org`,
`download.docker.com`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`,
`production.cloudfront.docker.com`, `ghcr.io`, `dl-cdn.alpinelinux.org` (correctifs Alpine des images, en 443),
`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org` et `sum.golang.org` (Caddy
recompilé avec le dernier Go, en 443). Les conteneurs ne sortent qu'en 443 : `deb.debian.org`
doit donc aussi l'être en HTTPS (correctifs Debian de l'image de l'application). Sans accès direct, renseigner `HTTP_PROXY` dans
`vm.conf`. Si le réseau coupe CloudFront (`connection reset by peer` sur `production.cloudfront.docker.com`),
renseigner `DOCKER_MIRROR='https://mirror.gcr.io'` (miroir officiel de Docker Hub chez Google) et autoriser
`mirror.gcr.io`.

Restent manuels : la clé maître et la phrase de passe des sauvegardes à copier dans le coffre-fort (§ 7.1, § 8),
le certificat racine à déployer par GPO (§ 7.2), les agents HarfangLab/NinjaOne (§ 9), les règles du XGS (§ 6.4).

## 3. Installation de Debian 13

1. Image `debian-13.x-amd64-netinst.iso`, installation **en mode texte**.
2. Réseau : **IP fixe** (pas de DHCP), nom d'hôte `minisoc`, domaine `mairie.local`.
3. Mot de passe root : **laisser vide**. Root est alors verrouillé et le premier compte reçoit `sudo`.
4. Premier compte : `adminsoc` (compte nominatif d'administration ; un compte par administrateur si vous êtes
   plusieurs).
5. Partitionnement (manuel) :
   - disque 1 : `/boot/efi` 512 Mo, `/` 30 Go, `/var/log` 8 Go (ext4), échange 2 Go ;
   - disque 2 : une partition ext4 montée sur `/var/lib/docker`.
6. Sélection des logiciels : **uniquement** « serveur SSH » et « utilitaires usuels du système ».
   Ni environnement de bureau, ni serveur web.
7. Dans le DNS de l'AD, créer les enregistrements A et PTR de `minisoc.mairie.local`.

Premier démarrage, depuis la console :

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y curl ca-certificates gnupg chrony auditd audispd-plugins unattended-upgrades \
  apt-listchanges iptables nftables rsync lynis needrestart
```

---

## 4. Durcissement du système

### 4.1 Mises à jour de sécurité automatiques

```bash
sudo dpkg-reconfigure -plow unattended-upgrades     # répondre « Oui »
```

Seules les mises à jour de **sécurité Debian** s'installent seules. Docker et le Mini-SOC se mettent à jour à
la main, après un instantané de la VM (§ 10). Sans redémarrage automatique : `needrestart` signale les services
à relancer.

### 4.2 Heure (indispensable pour corréler les journaux)

`/etc/chrony/sources.d/ad.sources` :

```text
server 192.168.10.2 iburst
server 192.168.10.3 iburst
```

```bash
sudo sed -i 's/^pool /#pool /' /etc/chrony/chrony.conf     # pas de serveur de temps Internet
sudo systemctl restart chrony && chronyc sources
```

### 4.3 SSH : clé uniquement, comptes nommés

Sur **chaque poste DSI autorisé** (PowerShell, OpenSSH est inclus dans Windows 10/11), générer une clé protégée
par une phrase de passe :

```powershell
ssh-keygen -t ed25519 -C "prenom.nom@poste-dsi"
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh adminsoc@192.168.10.50 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Vérifier qu'une **nouvelle** session s'ouvre avec la clé, **puis seulement** créer
`/etc/ssh/sshd_config.d/10-minisoc.conf` :

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers adminsoc@192.168.10.21 adminsoc@192.168.10.22
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/issue.net
```

```bash
echo "Système de la DSI - accès réservé aux administrateurs habilités. Toute connexion est journalisée." | sudo tee /etc/issue.net
sudo sshd -t && sudo systemctl reload ssh
```

Garder la session ouverte et tester une seconde connexion avant de fermer la première.

`AllowUsers` reprend les postes DSI (`ADMINS` du pare-feu, § 6.1) : sur la VM, `minisoc-sshd-config` l'écrit à
chaque « Appliquer » de `sudo minisoc-setup`. Il ne vise que SSH : la **console de la VM** (hyperviseur) reste
ouverte à `adminsoc` avec son mot de passe, même si tous les postes DSI sont hors service. Depuis la console :
`sudo minisoc-setup` › Entrants › Administration, ajouter le poste de remplacement, puis Appliquer.

### 4.4 Paramètres du noyau

`/etc/sysctl.d/90-minisoc.conf` (le routage IP reste actif, Docker en a besoin) :

```text
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
# IPv6 inutilisé sur le LAN : désactivé (sinon il faudrait doubler toutes les règles de pare-feu)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
```

```bash
sudo sysctl --system
```

### 4.5 Journaux et audit

Journal système conservé sur disque, taille bornée (`/etc/systemd/journald.conf.d/minisoc.conf`) :

```text
[Journal]
Storage=persistent
SystemMaxUse=1G
```

Règles d'audit (`/etc/audit/rules.d/minisoc.rules`) : qui modifie les comptes, sudo, SSH, Docker, les secrets ?

```text
-w /etc/passwd -p wa -k identite
-w /etc/shadow -p wa -k identite
-w /etc/group -p wa -k identite
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
-w /home/adminsoc/.ssh/ -p wa -k ssh
-w /etc/docker/ -p wa -k docker
-w /usr/bin/docker -p x -k docker
-w /etc/minisoc/ -p wa -k minisoc
-w /opt/minisoc/.env -p wa -k minisoc-secrets
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
```

```bash
sudo systemctl restart systemd-journald
sudo augenrules --load
sudo ausearch -k minisoc-secrets -i      # exemple de consultation
```

### 4.6 Services inutiles

```bash
sudo ss -tulpn                          # seul sshd doit écouter à ce stade
sudo systemctl disable --now nftables   # IMPORTANT : sa configuration par défaut contient « flush ruleset »,
                                        # qui effacerait les règles de Docker (le pare-feu est géré au § 6)
```

### 4.7 Système, comptes et fail2ban

```bash
sudo apt install -y fail2ban python3-systemd libpam-pwquality apparmor apparmor-utils
```

| Mesure | Fichier |
| --- | --- |
| Protocoles et systèmes de fichiers inutiles, stockage USB et FireWire refusés (`install … /bin/false`) : dccp, sctp, rds, tipc, cramfs, freevxfs, hfs, hfsplus, jffs2, usb-storage, firewire-core | `/etc/modprobe.d/minisoc-blacklist.conf` |
| `/dev/shm` en `nodev,nosuid,noexec` | `/etc/fstab` |
| Pas de fichier `core` | `/etc/security/limits.d/90-minisoc.conf` : `* hard core 0` |
| Mots de passe locaux : 12 caractères, 3 classes | `/etc/security/pwquality.conf` : `minlen = 12`, `minclass = 3` |
| `su` réservé au groupe `sudo` | `/etc/pam.d/su` : `auth required pam_wheel.so group=sudo` |
| AppArmor actif (profils des conteneurs Docker) | `sudo aa-status` |

fail2ban bannit 1 h (durée croissante en cas de récidive) une adresse qui échoue 5 fois en 10 minutes sur SSH,
dans sa propre table nftables (`/etc/fail2ban/jail.d/minisoc.local`) :

```ini
[DEFAULT]
backend = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 1h
bantime.increment = true
findtime = 10m
maxretry = 5

[sshd]
enabled = true
mode = aggressive
```

L'interface web a son propre verrouillage après échecs de connexion ; fail2ban ne la concerne pas.

---

## 5. Docker

Installation depuis le dépôt officiel de Docker (les paquets Debian sont trop anciens) :

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Configuration du démon (`/etc/docker/daemon.json`) :

```json
{
  "log-driver": "local",
  "log-opts": { "max-size": "20m", "max-file": "5" },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "bip": "10.255.255.1/24",
  "default-address-pools": [{ "base": "10.255.0.0/16", "size": 24 }]
}
```

| Option | Effet |
| --- | --- |
| `log-driver` / `log-opts` | Journaux des conteneurs bornés (sinon ils peuvent remplir le disque) |
| `live-restore` | Les conteneurs continuent de tourner pendant une mise à jour de Docker |
| `userland-proxy: false` | Les ports publiés passent par le pare-feu du noyau, donc par les règles du § 6 |
| `no-new-privileges` | Un processus d'un conteneur ne peut pas gagner de privilèges (binaires setuid) |
| `icc: false` | Pas de communication entre conteneurs du réseau par défaut (le Mini-SOC utilise son propre réseau) |
| `bip` / `default-address-pools` | Plage des réseaux Docker choisie (sinon 172.17 à 172.31) : à prendre **hors de toute plage utilisée** sur le réseau, sinon la VM ne joint plus les machines de cette plage |

Réseaux du Mini-SOC (`docker-compose.yml`) : PostgreSQL, Redis et ClickHouse sont sur le réseau `data`, déclaré
`internal` : **aucune sortie** possible, ni vers le LAN ni vers Internet, et joignable seulement par l'API et le
worker. Seuls l'interface web (Caddy : 443, 80 redirigé) et la réception syslog (514, 6514) publient des ports.

```bash
sudo systemctl restart docker
```

> Si un conteneur refuse de démarrer à cause de `no-new-privileges` (message `operation not permitted`),
> retirer cette ligne, relancer Docker et le signaler : on appliquera l'option conteneur par conteneur.

**Ne pas ajouter `adminsoc` au groupe `docker`.** Ce groupe donne l'équivalent des droits root sans mot de passe.
Toutes les commandes Docker se lancent avec `sudo`, ce qui les inscrit au journal.

---

## 6. Pare-feu (le point le plus important)

**Docker contourne UFW** et les règles « classiques » : un port publié par un conteneur est joignable par tout le
LAN, quoi qu'en dise UFW. Le filtrage se fait donc à deux endroits :

- **la machine** (SSH, système), dans une table nftables dédiée ;
- **les conteneurs** (web, syslog), dans la chaîne `DOCKER-USER`, réservée par Docker à cet usage et qu'il ne
  modifie jamais.

Les deux sont générés par un seul script, à partir d'un seul fichier d'adresses.

### 6.1 Fichier des adresses autorisées

`/etc/minisoc/firewall.conf` (adresses ou plages CIDR, séparées par des espaces) :

```sh
# Pare-feu du Mini-SOC : adresses autorisées.
# Après modification : sudo minisoc-setup --relire (SSH, pare-feu et interface web réappliqués)
LAN_IF="ens192"                         # interface réseau de la VM (VMXNET3 sous vSphere ; commande : ip -br link)

# --- Entrant ---
ADMINS="192.168.10.21 192.168.10.22"    # postes DSI : SSH et interface web
WALL="192.168.10.40"                    # écran mural : interface web
TRIVY="192.168.10.70"                   # serveurs équipés de l'agent Trivy : 443, envoi des rapports seul (§ 6.5)
SYSLOG_TCP="192.168.10.1"               # syslog 514/TCP en clair : XGS, Vectra (Varonis seulement s'il est installé sur site)
SYSLOG_TLS="192.168.10.2 192.168.10.3"  # syslog 6514/TCP chiffré : contrôleurs de domaine, serveurs de fichiers
SYSLOG_UDP=""                           # seulement pour un équipement qui ne sait pas envoyer en TCP
BACKUP_SERVER="192.168.10.60"           # serveur qui récupère les sauvegardes (SSH, compte restreint)

# --- Sortant (hôte:port) ---
DNS="192.168.10.2 192.168.10.3"
NTP="192.168.10.2 192.168.10.3"
LAN_OUT="192.168.10.2:636 192.168.10.3:636 192.168.10.8:587 192.168.10.1:4444 192.168.10.9:8080"
#        LDAPS (AD)        LDAPS (AD)        relais SMTP       API du XGS         CrowdSec
# Ollama interne éventuel : ajouter 192.168.10.30:11434 ; Cyberwatch sur le LAN : ajouter son adresse:443
INTERNET_PORTS="443,8443"               # Internet : HarfangLab (8443), Microsoft 365, mises à jour, veille, IA…
```

```bash
sudo mkdir -p /etc/minisoc && sudo chmod 750 /etc/minisoc
sudo nano /etc/minisoc/firewall.conf
```

### 6.2 Script

Le script est dans le dépôt : [`deploy/firewall/minisoc-firewall`](../deploy/firewall/minisoc-firewall). Il crée
la table nftables `inet minisoc_host` (la machine : SSH depuis `ADMINS` et `BACKUP_SERVER`, sorties DNS, NTP et
Internet 80/443) et remplit la chaîne `DOCKER-USER` (les conteneurs : 443 depuis `ADMINS`, `WALL` et `TRIVY`, 80
depuis `ADMINS`, syslog depuis les sources déclarées ; vers le LAN seulement `DNS` et `LAN_OUT`, vers Internet
seulement `INTERNET_PORTS`). Tout refus est journalisé (`minisoc-hote-refus-*`, `minisoc-docker-refus-*`). Il refuse
de s'appliquer si `LAN_IF`, `ADMINS`, `DNS` ou `NTP` est vide, ce qui fermerait l'accès.

Le pare-feu ne voit que des adresses et des ports, pas les pages demandées (le trafic web est chiffré) : le tri par
chemin des serveurs `TRIVY` est fait par l'interface web (§ 6.5).

```bash
sudo install -m 750 deploy/firewall/minisoc-firewall /usr/local/sbin/minisoc-firewall
```

### 6.3 Démarrage automatique, avant Docker

[`deploy/firewall/minisoc-firewall.service`](../deploy/firewall/minisoc-firewall.service) (lancé après le
montage des disques, avant Docker) :

```bash
sudo install -m 644 deploy/firewall/minisoc-firewall.service /etc/systemd/system/
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now minisoc-firewall
sudo systemctl restart docker
```

**Avant de fermer votre session SSH**, ouvrez-en une deuxième pour vérifier que l'accès fonctionne toujours.
En cas d'erreur, la console de l'hyperviseur reste disponible : `sudo nft delete table inet minisoc_host`
rouvre l'accès.

Contrôle :

```bash
sudo nft list table inet minisoc_host
sudo iptables -L DOCKER-USER -nv --line-numbers
sudo journalctl -k | grep minisoc-        # connexions refusées
```

### 6.4 Sur le Sophos XGS : filtrer les sorties Internet par nom

Le pare-feu local autorise les ports 443 et 8443 vers Internet, car il ne connaît que des adresses IP. Le tri
par nom de domaine se fait sur le XGS, par lequel passe toute la sortie Internet :

1. **Hôtes et services › FQDN** : créer le groupe « Mini-SOC - destinations ». Les domaines sont listés dans
   [03-preparation-vm.md § 2](03-preparation-vm.md) : console HarfangLab, `login.microsoftonline.com`,
   `manage.office.com`, `download.maxmind.com`, `www.cisa.gov`, `www.cert.ssi.gouv.fr`, fournisseur d'IA, Teams,
   ntfy. Ajoutez-y aussi les sources de mise à jour : `deb.debian.org`, `security.debian.org`,
   `download.docker.com`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`,
   `production.cloudfront.docker.com`,
   `ghcr.io`, `pkg-containers.githubusercontent.com`.
2. Règle n° 1 : source = IP de la VM, destination = groupe « Mini-SOC - destinations », services HTTPS et
   TCP 8443 → **Accepter**, journalisation activée.
3. Règle n° 2, juste en dessous : source = IP de la VM, destination = toute zone WAN → **Refuser**,
   journalisation activée.

Si la VM est dans le même segment que les postes, le XGS ne voit pas le trafic LAN ↔ VM : seul le pare-feu local
le filtre. C'est l'intérêt du VLAN dédié (§ 0).

### 6.5 Serveurs Trivy : envoi des rapports seul

Les serveurs de la liste `TRIVY` (`sudo minisoc-setup` › Entrants › Serveurs Trivy) ont le 443 ouvert comme les
postes DSI. L'interface web (Caddy, [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile)) ne leur laisse que
`POST /api/ingest/trivy` : la page de connexion, l'interface et le reste de l'API leur répondent **403**. Une adresse
qui figure aussi dans `ADMINS` ou `WALL` garde l'accès complet (une plage `TRIVY` peut donc contenir un poste DSI).
Le tri porte sur l'adresse de la connexion elle-même, jamais sur un en-tête (`X-Forwarded-For`) que le serveur
pourrait écrire.

Caddy reçoit les listes par `/opt/minisoc/.env` : `MINISOC_TRIVY_IPS` (= `TRIVY`) et `MINISOC_WEB_IPS`
(= `ADMINS` et `WALL`). « Appliquer » dans `sudo minisoc-setup`, le retour arrière automatique et `minisoc-update`
les recopient depuis `firewall.conf` et recréent le conteneur `web` si elles ont changé. Après une modification à
la main de `firewall.conf` : `sudo minisoc-setup --relire`.

Le jeton de chaque serveur garde ses propres contrôles (Intégrations › Trivy : révocation, « Adresses
autorisées »).

---

## 7. Installation du Mini-SOC

### 7.1 Copie du projet

Sur le poste de développement, préparer une archive **sans** les secrets ni les fichiers de travail :

```bash
git archive --format=tar.gz -o minisoc.tar.gz HEAD     # une fois le projet versionné
scp minisoc.tar.gz adminsoc@192.168.10.50:/tmp/
```

Sur la VM :

```bash
sudo mkdir -p /opt/minisoc && sudo tar -xzf /tmp/minisoc.tar.gz -C /opt/minisoc && rm /tmp/minisoc.tar.gz
sudo chown -R root:root /opt/minisoc && sudo chmod 750 /opt/minisoc
cd /opt/minisoc
sudo python3 scripts/init_env.py        # crée .env avec des secrets aléatoires
sudo chmod 600 .env
sudo nano .env
```

Dans `.env` :

| Variable | Valeur |
| --- | --- |
| `MINISOC_HOSTNAME` | `minisoc.mairie.local` |
| `MINISOC_PUBLIC_URL` | `https://minisoc.mairie.local` |
| `WEB_BIND` | `192.168.10.50` (IP de la VM, pas `0.0.0.0`) |
| `SYSLOG_BIND` | `192.168.10.50` |
| `COMPOSE_PROFILES` | `syslog-tls` (GeoIP se règle dans l'interface : Intégrations › Géolocalisation) |

> **Clé maître** (`MINISOC_MASTER_KEY`) : elle chiffre tous les jetons saisis dans l'interface. Copiez-la dès
> maintenant dans le coffre-fort de mots de passe de la DSI (KeePass), hors de la VM. Sans elle, une restauration
> oblige à ressaisir tous les secrets.

Reprise de la configuration du poste de développement (HarfangLab déjà réglé, etc.) : voir
[03-preparation-vm.md § 1](03-preparation-vm.md).

### 7.2 Certificat

Deux possibilités, de la meilleure à la plus simple :

1. **Certificat de votre PKI AD** (AD CS) ou wildcard pour le nom du Mini-SOC : copier `minisoc.crt` (avec la
   chaîne) et `minisoc.key` dans `/etc/minisoc/tls/` (droits 600). Dans `.env` : `MINISOC_TLS_DIR=/etc/minisoc/tls` et `MINISOC_TLS=/certs/minisoc.crt /certs/minisoc.key`, puis
   `sudo docker compose up -d`. `sudo minisoc-setup` › Certificat web le fait à partir d'un PFX ou d'un PEM : il
   vérifie que la clé correspond, que le nom est couvert et que la chaîne est complète.

   **Certificat wildcard** (`*.mairie.fr`) : utilisable si le nom de l'interface est dans ce domaine, sur un seul
   niveau (`minisoc.mairie.fr`, avec un enregistrement DNS interne). Sa clé vaut pour tout le domaine : une
   compromission de la VM permettrait d'usurper n'importe quel sous-domaine. Un certificat dédié au seul nom du
   Mini-SOC reste préférable.

   **Pas à pas, sans la console** (mêmes contrôles que `sudo minisoc-setup` › Certificat web). Déposer le
   fichier depuis un poste DSI (`scp wildcard.pfx adminsoc@<IP>:/tmp/`), puis sur la VM :

   ```bash
   sudo -i                                   # tout en root : la clé ne doit être lisible que par root
   umask 077; d=$(mktemp -d); cd "$d"
   # a) PFX/P12 → PEM (mot de passe du PFX demandé ; ajouter -legacy si « unsupported » sur un ancien PFX)
   openssl pkcs12 -in /tmp/wildcard.pfx -nokeys -out crt
   openssl pkcs12 -in /tmp/wildcard.pfx -nocerts -nodes -out key
   awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' crt > chain
   #    Fichiers PEM à la place : cp certificat.crt chain ; cp cle.key key
   #    (.cer binaire : openssl x509 -inform der -in x.cer -out chain ; clé chiffrée : openssl pkey -in x.key -out key)
   # b) Contrôles : les deux empreintes doivent être identiques, le nom couvert, la chaîne présente (2 ou plus)
   openssl x509 -in chain -noout -pubkey | sha256sum; openssl pkey -in key -pubout | sha256sum
   openssl x509 -in chain -noout -checkhost minisoc.mairie.local    # « does match » attendu
   openssl x509 -in chain -noout -subject -ext subjectAltName -enddate
   grep -c 'BEGIN CERTIFICATE' chain
   # c) Installation
   install -d -m 0700 /etc/minisoc/tls
   install -m 0600 chain /etc/minisoc/tls/minisoc.crt
   install -m 0600 key /etc/minisoc/tls/minisoc.key
   cd /opt/minisoc
   grep -q '^MINISOC_TLS_DIR=' .env && sed -i 's|^MINISOC_TLS_DIR=.*|MINISOC_TLS_DIR=/etc/minisoc/tls|' .env || echo 'MINISOC_TLS_DIR=/etc/minisoc/tls' >> .env
   grep -q '^MINISOC_TLS=' .env && sed -i 's|^MINISOC_TLS=.*|MINISOC_TLS=/certs/minisoc.crt /certs/minisoc.key|' .env || echo 'MINISOC_TLS=/certs/minisoc.crt /certs/minisoc.key' >> .env
   docker compose up -d web
   # d) Ménage : rien de la clé ne doit rester hors de /etc/minisoc/tls
   shred -u "$d"/key "$d"/crt /tmp/wildcard.pfx; rm -rf "$d"; exit
   ```

   Si le certificat couvre un autre nom que celui de l'interface (`MINISOC_HOSTNAME` de `.env`), changer aussi
   `MINISOC_HOSTNAME` et `MINISOC_PUBLIC_URL` dans `.env` et créer l'enregistrement DNS correspondant. Vérifier
   depuis un poste DSI : le navigateur n'affiche plus d'avertissement, ou
   `openssl s_client -connect minisoc.mairie.local:443 -servername minisoc.mairie.local </dev/null | openssl x509 -noout -issuer -enddate`.
   Renouvellement : même procédure avec le nouveau fichier.
2. **Autorité interne de Caddy** (`tls internal`, par défaut) : après le premier démarrage, récupérer son
   certificat racine (`sudo docker compose cp web:/data/caddy/pki/authorities/local/root.crt .`) et le
   déployer par **GPO** sur les postes DSI et l'écran mural (Autorités de certification racines de confiance).

### 7.3 Syslog chiffré pour les serveurs Windows

Les journaux Windows contiennent les noms de comptes et des informations de connexion : ils ne doivent pas
circuler en clair sur le LAN.

À faire **avant** le premier démarrage si `COMPOSE_PROFILES` contient `syslog-tls` :

```bash
sudo ./scripts/syslog_cert.sh minisoc.mairie.local 192.168.10.50
```

Le script crée `data/syslog-tls/` :

- `ca.crt` : à installer sur les serveurs émetteurs, qui vérifient ainsi le Mini-SOC ;
- `server.crt` / `server.key` : certificat du récepteur ;
- `ca.key` : à copier dans le coffre-fort de la DSI, puis **supprimer de la VM**. Il ne sert qu'à renouveler le
  certificat, valable 2 ans.

Côté serveurs Windows, NXLog en `om_ssl` vers le port 6514 : voir `deploy/nxlog/nxlog.conf` et le guide de la
fiche « Active Directory » dans Intégrations. Si votre version du Sophos XGS propose le syslog sécurisé (TLS),
l'utiliser aussi et retirer le XGS de `SYSLOG_TCP`.

### 7.4 Démarrage et compte de secours

```bash
sudo docker compose up -d --build
sudo docker compose ps                  # tous les services « running » ou « healthy »
sudo docker compose exec api python -m minisoc.cli create-user --username secours --role admin
```

Le compte `secours` est un **compte local de secours**, utilisable même si l'AD est indisponible. Il a un mot de
passe et une double authentification, tous deux conservés dans le coffre-fort de la DSI. Les comptes du
quotidien viennent de l'AD (Paramètres › Annuaire AD), avec double authentification.

Écran mural : jeton dédié, limité à l'affichage et à l'adresse de l'écran. Le pare-feu (variable `WALL`) le
filtre aussi :

```bash
sudo docker compose exec api python -m minisoc.cli create-display-token --name "Écran DSI" --ip 192.168.10.40
```

Analyse Trivy de la VM : le service `minisoc-trivy` (installé par l'ISO et par `minisoc-update`) analyse les
images de l'application et les paquets Debian chaque lundi matin (`minisoc-trivy.timer`), après chaque mise à
jour et à la demande depuis Intégrations › Trivy (`minisoc-trivy.path`). Il tourne sur l'hôte : chaque image est
exportée puis lue par un conteneur Trivy jetable, sans socket Docker ni privilège. Rapport et état dans
`/var/lib/minisoc/trivy` (lu par le worker), journal : `sudo journalctl -u minisoc-trivy`. Serveurs équipés de
l'agent : jeton par serveur dans Intégrations › Trivy, adresse dans `sudo minisoc-setup` › Entrants › Serveurs
Trivy (variable `TRIVY` du pare-feu, 443/TCP, limité à l'envoi des rapports : § 6.5).

---

## 8. Sauvegardes à l'abri d'une compromission de la VM

Principe : la VM produit chaque nuit une archive **chiffrée**. C'est un serveur tiers qui vient la **chercher**,
avec un compte en lecture seule. Un attaquant maître de la VM ne peut donc ni lire les anciennes sauvegardes
sans la phrase de passe, ni les supprimer.

Sur la VM :

```bash
# Phrase de passe des archives (à conserver aussi dans le coffre-fort de la DSI)
sudo sh -c 'umask 077; openssl rand -base64 32 > /etc/minisoc/backup.pass'
sudo groupadd --system minisoc-backup
sudo useradd --system --gid minisoc-backup --create-home --home-dir /var/lib/minisoc-backup --shell /bin/sh minisoc-backup
sudo install -d -o root -g minisoc-backup -m 750 /var/backups/minisoc     # archives (lecture seule pour le compte)
```

`/etc/cron.d/minisoc-backup` :

```text
0 2 * * * root cd /opt/minisoc && BACKUP_DIR=/var/backups/minisoc BACKUP_PASSPHRASE_FILE=/etc/minisoc/backup.pass ./scripts/backup.sh >> /var/log/minisoc-backup.log 2>&1 && chgrp minisoc-backup /var/backups/minisoc/*.gpg && chmod 640 /var/backups/minisoc/*.gpg
30 2 * * * root rsync -a /var/lib/docker/volumes/minisoc_archives/_data/ /var/backups/minisoc/archives/ && chgrp -R minisoc-backup /var/backups/minisoc/archives && chmod -R g+rX,o-rwx /var/backups/minisoc/archives
```

La seconde ligne recopie les **archives scellées des journaux** (une par jour, empreintes chaînées, manifeste
`manifest.jsonl`) : elles sont déjà compressées et leur intégrité se vérifie sans le Mini-SOC. Le serveur de
sauvegarde les récupère avec le reste.

Compte de récupération : clé SSH du serveur de sauvegarde, limitée à la **lecture** de ce dossier.

```bash
sudo install -d -o minisoc-backup -g minisoc-backup -m 700 /var/lib/minisoc-backup/.ssh
echo 'restrict,command="/usr/bin/rrsync -ro /var/backups/minisoc" ssh-ed25519 AAAA…cle-du-serveur-de-sauvegarde' \
  | sudo tee /var/lib/minisoc-backup/.ssh/authorized_keys
sudo chown minisoc-backup: /var/lib/minisoc-backup/.ssh/authorized_keys
sudo chmod 600 /var/lib/minisoc-backup/.ssh/authorized_keys
```

Dans `/etc/ssh/sshd_config.d/10-minisoc.conf`, compléter :
`AllowUsers adminsoc@192.168.10.21 adminsoc@192.168.10.22 minisoc-backup@192.168.10.60`, puis
`sudo systemctl reload ssh` (sur la VM, `sudo minisoc-setup` › Sauvegarde le fait). Le serveur de sauvegarde ne
peut ainsi ouvrir que le compte `minisoc-backup`, même si le pare-feu lui ouvre le port SSH.

Sur le serveur de sauvegarde (`192.168.10.60`), chaque nuit à 3 h, récupérer les archives de la VM
(`192.168.10.50`) :

```bash
rsync -a minisoc-backup@192.168.10.50:/ /sauvegardes/minisoc/
```

Si le port SSH a été changé (`sudo minisoc-setup`, menu « Port SSH »), l'indiquer à rsync :
`rsync -a -e 'ssh -p 2222' minisoc-backup@192.168.10.50:/ /sauvegardes/minisoc/`.

Le serveur de sauvegarde gère lui-même la conservation des archives (par exemple 90 jours).

En plus :

- un **instantané de la VM** avant chaque mise à jour (§ 10) ;
- un **test de restauration** chaque trimestre, sur une VM de recette, avec `scripts/restore.sh`.

---

## 9. Surveiller la VM elle-même

- **Agent HarfangLab Linux** sur la VM, dans un groupe de politique dédié. Si les performances en souffrent,
  ajouter des exclusions de performance sur `/var/lib/docker/volumes` (bases de données), **sans** exclure les
  binaires.
- **Agent NinjaOne** (facultatif) : correctifs et espace disque visibles dans la même console que le reste du
  parc.
- **Dans le Mini-SOC** : les règles « source silencieuse » préviennent si une source cesse d'envoyer (XGS,
  serveurs Windows, HarfangLab). Un silence soudain de toutes les sources est un signal à traiter.
- **Contrôle mensuel** : `sudo ausearch -k minisoc-secrets -k sudo -k ssh -i --start this-month`.

---

## 10. Mises à jour

| Quoi | Quand | Comment |
| --- | --- | --- |
| Correctifs de sécurité Debian | automatique, chaque nuit | `unattended-upgrades` ; redémarrer si `needrestart` le demande |
| Docker | mensuel | instantané de la VM, puis `sudo apt update && sudo apt upgrade` |
| Mini-SOC et images | à chaque version | instantané de la VM, puis paquet de mise à jour (ci-dessous) |
| Audit de durcissement | trimestriel | `sudo lynis audit system` : traiter les avertissements ; viser un indice ≥ 75 |

**Mise à jour du Mini-SOC.** Chaque construction (`deploy/iso/build-iso.sh`) produit, à côté de l'ISO, un paquet
`build/iso/minisoc-update-<version>.tar.gz` (mêmes fichiers, sans les réglages du site).

Pour produire **le paquet de mise à jour seul**, sans télécharger ni reconstruire l'ISO (ni `vm.conf`, ni clés
SSH nécessaires ; les ISO existantes sont conservées), depuis la racine du projet (PowerShell) :

```powershell
docker run --rm -e MINISOC_SEULEMENT_MAJ=1 -v "${PWD}:/work" -w /work debian:13-slim sh deploy/iso/build-iso.sh
```

(équivalent : `… sh deploy/iso/build-iso.sh --mise-a-jour`). Même version et mêmes fichiers qu'une construction
complète ; le paquet précédent et son `.sha256` sont remplacés. Puis, depuis le poste DSI :

```bash
scp build/iso/minisoc-update-<version>.tar.gz adminsoc@<IP>:/tmp/
```

Puis sur la VM, après un instantané :

```bash
sudo minisoc-update /tmp/minisoc-update-<version>.tar.gz
```

La commande affiche la version installée et la nouvelle, demande confirmation, sauvegarde l'existant
(`/var/backups/minisoc/mises-a-jour/`, 3 dernières gardées), met à jour l'application dans `/opt/minisoc` (`.env`,
`docker-compose.override.yml` et `data/` conservés ; fichiers retirés de l'application supprimés), les scripts du
système (console de paramétrage, pare-feu, SSH, accueil), puis reconstruit et redémarre les conteneurs. Si la
construction échoue, tout est remis dans l'état précédent sans interrompre les conteneurs en service. Journal :
`/var/log/minisoc-update.log`. Version installée : `/etc/minisoc/version` (affichée à la connexion).

**Réception syslog pendant la mise à jour.** Les conteneurs sont reconstruits pendant que tout tourne ; à leur
redémarrage, Vector garde les journaux dans son tampon disque tant que l'API redémarre, et les connecteurs d'API
reprennent à leur point de reprise. Reste le redémarrage de Vector lui-même (port 514 fermé quelques secondes) :
`minisoc-update` démarre alors un **relais** (service `vector-relais` : même image fraîchement reconstruite, même
configuration, publié sur 127.0.0.1 seulement), renvoie vers lui le 514 entrant par une règle DNAT temporaire
(commentaire `minisoc-relais-syslog`), recrée Vector, retire la règle, puis arrête le relais une fois ses envois
transmis. Le filtrage ne change pas (DOCKER-USER : port d'origine 514, sources syslog déclarées). La règle est retirée
quoi qu'il arrive (fin du script, erreur, Ctrl+C) et, à défaut, par `minisoc-firewall`. Le syslog TLS (6514) n'a
pas de relais : NXLog se reconnecte et reprend à sa position dans le journal Windows. Outil `conntrack` installé
par la mise à jour (oubli des flux UDP en cours pour qu'ils suivent le renvoi).

**Recette du relais, sur une VM de test uniquement** (jamais la production pour un premier essai) : déclarer le
poste de test dans les sources syslog UDP et TCP de la VM de test, activer l'intégration « Syslog générique », puis
lancer depuis ce poste, juste avant `sudo minisoc-update …` sur la VM de test :

```bash
python tools/test_relais_syslog.py --host <IP de la VM de test> --duree 600
```

Le script envoie 10 messages numérotés par seconde en UDP et en TCP pendant toute la mise à jour, puis affiche les
recherches à lancer (`<marqueur> udp | count`) et le nombre attendu. Attendu : aucun écart en UDP ; en TCP, au plus
quelques messages au moment des reconnexions. Dans `/var/log/minisoc-update.log` : « Port 514 renvoyé vers le
relais » puis « Relais syslog retiré » ; après coup, `sudo iptables -t nat -S PREROUTING | grep relais` ne renvoie
rien.

VM installée avant l'arrivée de cette commande (première fois seulement) :

```bash
tar -xzf /tmp/minisoc-update-<version>.tar.gz -C /tmp && sudo bash /tmp/minisoc-update/minisoc-update.sh /tmp/minisoc-update-<version>.tar.gz
```

Changement de comportement géré à la mise à jour : les intégrations sont désormais désactivées par défaut ; sur une
installation existante, celles qui fonctionnaient (données reçues, veille, GeoIP) restent actives.

**Versions des composants** : chaque paquet embarque la dernière version stable des images (PostgreSQL, Redis,
ClickHouse, Vector, Caddy, Python, Node), vérifiée avant livraison. Une montée de version majeure de PostgreSQL
(16 → 18…) est faite par `minisoc-update` : export de la base depuis l'ancienne version, import dans la nouvelle,
sur un **nouveau volume** (`minisoc_pgdata18`…) ; l'ancien volume reste intact (retour arrière automatique en cas
d'échec). Une fois tout vérifié : `sudo docker volume rm minisoc_pgdata`.

---

## 11. Vérifications de fin d'installation

Depuis un **poste ordinaire du LAN** (non autorisé) :

```bash
nmap -Pn -p 22,80,443,514,6514,5432,6379,8000,8123,9000 192.168.10.50
```

Attendu : tous les ports « filtered ».

Depuis un **poste DSI autorisé** :

- [ ] `ssh adminsoc@192.168.10.50` fonctionne ; `ssh -o PubkeyAuthentication=no adminsoc@…` est refusé
- [ ] `https://minisoc.mairie.local` : certificat reconnu, connexion avec double authentification
- [ ] Écran mural : affichage OK ; depuis un autre poste, l'adresse ne répond pas
- [ ] Serveur Trivy : `curl -sk -o /dev/null -w "%{http_code}" https://minisoc.mairie.local/` lancé depuis ce serveur
      répond `403` ; son agent envoie bien son rapport (`sudo minisoc-trivy-agent run`)

Sur la VM :

- [ ] `sudo ss -tulpn` : seuls sshd et docker (80, 443, 514, 6514) écoutent
- [ ] `sudo docker compose ps` : aucun port publié pour postgres, redis, clickhouse
- [ ] `sudo iptables -L DOCKER-USER -nv` : les compteurs des règles autorisées augmentent avec le syslog
- [ ] `sudo journalctl -k | grep minisoc-` : pas de refus inattendu (sinon, compléter `firewall.conf`)
- [ ] Syslog : une source non déclarée est refusée (ligne `minisoc-docker-refus-entree` dans le journal)
- [ ] Sorties : sur le XGS, aucune connexion refusée vers une destination légitime pendant 24 h
- [ ] Sauvegarde : une archive `.gpg` est présente le lendemain et a bien été récupérée par le serveur de
      sauvegarde
- [ ] `sudo lynis audit system` : indice relevé et noté dans le suivi du projet

---

## 12. Risques résiduels (sans réseau d'administration)

| Risque | Mesure en place | Pour aller plus loin |
| --- | --- | --- |
| Un poste du LAN usurpe l'adresse d'un poste DSI ou d'une source syslog (ARP, IP) | SSH par clé, web en double authentification, syslog TCP/TLS (pas d'UDP) | VLAN dédié derrière le XGS (§ 0) ; protection ARP sur les commutateurs |
| Faux journaux envoyés en syslog clair (514) | Seules les IP déclarées sont acceptées | Syslog TLS partout où l'équipement le permet |
| Vol de la clé SSH ou de la session d'un poste DSI | Clé protégée par phrase de passe, HarfangLab sur les postes DSI | Poste d'administration dédié, sans messagerie ni navigation |
| Compromission de la VM | Pare-feu sortant, agent EDR, audit, sauvegardes non effaçables | Revue mensuelle des journaux d'audit |
| Panne ou perte de la VM | Sauvegardes chiffrées hors VM, instantanés | Restauration testée chaque trimestre |
