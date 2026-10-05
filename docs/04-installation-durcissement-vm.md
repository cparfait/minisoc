# Installation et durcissement de la VM Mini-SOC (sur le LAN, sans réseau d'administration)

Ce document décrit l'installation pas à pas de la VM et son durcissement. Il complète
[03-preparation-vm.md](03-preparation-vm.md) (dimensionnement, flux réseau, comptes à préparer).

Référence : **Debian 12** (les commandes sont identiques sous Ubuntu 24.04, sauf mention contraire).
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

## 3. Installation de Debian 12

1. Image `debian-12.x-amd64-netinst.iso`, installation **en mode texte**.
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
AllowUsers adminsoc
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
  "icc": false
}
```

| Option | Effet |
| --- | --- |
| `log-driver` / `log-opts` | Journaux des conteneurs bornés (sinon ils peuvent remplir le disque) |
| `live-restore` | Les conteneurs continuent de tourner pendant une mise à jour de Docker |
| `userland-proxy: false` | Les ports publiés passent par le pare-feu du noyau, donc par les règles du § 6 |
| `no-new-privileges` | Un processus d'un conteneur ne peut pas gagner de privilèges (binaires setuid) |
| `icc: false` | Pas de communication entre conteneurs du réseau par défaut (le Mini-SOC utilise son propre réseau) |

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

`/etc/minisoc/firewall.conf` (adresses séparées par des espaces) :

```sh
# Pare-feu du Mini-SOC : adresses autorisées. Après modification : sudo systemctl restart minisoc-firewall
LAN_IF="ens18"                          # interface réseau de la VM (commande : ip -br link)

# --- Entrant ---
ADMINS="192.168.10.21 192.168.10.22"    # postes DSI : SSH et interface web
WALL="192.168.10.40"                    # écran mural : interface web
SYSLOG_TCP="192.168.10.1"               # syslog 514/TCP en clair : XGS, Vectra, Varonis
SYSLOG_TLS="192.168.10.2 192.168.10.3"  # syslog 6514/TCP chiffré : contrôleurs de domaine, serveurs de fichiers
SYSLOG_UDP=""                           # seulement pour un équipement qui ne sait pas envoyer en TCP
BITDEFENDER_PROXY=""                    # reverse proxy en DMZ, seulement si Bitdefender est raccordé
BACKUP_SERVER="192.168.10.60"           # serveur qui récupère les sauvegardes (SSH, compte restreint)

# --- Sortant (hôte:port) ---
DNS="192.168.10.2 192.168.10.3"
NTP="192.168.10.2 192.168.10.3"
LAN_OUT="192.168.10.2:636 192.168.10.3:636 192.168.10.8:587 192.168.10.1:4444 192.168.10.9:8080"
#        LDAPS (AD)        LDAPS (AD)        relais SMTP       API du XGS         CrowdSec
# Ollama interne éventuel : ajouter 192.168.10.30:11434
INTERNET_PORTS="443,8443"               # Internet : HarfangLab (8443), Microsoft 365, mises à jour, veille, IA…
```

```bash
sudo mkdir -p /etc/minisoc && sudo chmod 750 /etc/minisoc
sudo nano /etc/minisoc/firewall.conf
```

### 6.2 Script

`/usr/local/sbin/minisoc-firewall` :

```sh
#!/bin/sh
# Pare-feu de la VM Mini-SOC : la machine (table nftables inet minisoc_host) et les conteneurs (chaîne
# DOCKER-USER). Lancé au démarrage avant Docker ; relancer après modification de /etc/minisoc/firewall.conf.
set -eu
. /etc/minisoc/firewall.conf
IPT="iptables -w"
csv() { echo "$*" | tr -s ' ' ',' | sed 's/^,//; s/,$//'; }

# ---------- 1. La machine (SSH, NTP, DNS, mises à jour) ----------
nft -f - <<EOF
table inet minisoc_host
delete table inet minisoc_host
table inet minisoc_host {
  set admins { type ipv4_addr; elements = { $(csv $ADMINS) } }
  set dns { type ipv4_addr; elements = { $(csv $DNS) } }
  set ntp { type ipv4_addr; elements = { $(csv $NTP) } }
  chain input {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept
    ip saddr @admins tcp dport 22 ct state new accept
    ${BACKUP_SERVER:+ip saddr $BACKUP_SERVER tcp dport 22 ct state new accept}
    limit rate 6/minute log prefix "minisoc-hote-refus-entree " level info
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif lo accept
    ct state established,related accept
    ip daddr @dns meta l4proto { tcp, udp } th dport 53 accept
    ip daddr @ntp udp dport 123 accept
    ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport { 80, 443 } accept
    oifname != "$LAN_IF" accept
    limit rate 6/minute log prefix "minisoc-hote-refus-sortie " level info
  }
}
EOF

# ---------- 2. Les conteneurs (chaîne DOCKER-USER) ----------
$IPT -N DOCKER-USER 2>/dev/null || true
$IPT -F DOCKER-USER
$IPT -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

allow_in() {  # allow_in <port> <tcp|udp> <sources…> : port publié par un conteneur
  port=$1; proto=$2; shift 2
  for src in "$@"; do
    $IPT -A DOCKER-USER -i "$LAN_IF" -s "$src" -p "$proto" \
      -m conntrack --ctstate NEW --ctorigdstport "$port" --ctdir ORIGINAL -j RETURN
  done
}
allow_in 443 tcp $ADMINS $WALL $BITDEFENDER_PROXY
allow_in 80 tcp $ADMINS                       # redirection vers HTTPS
allow_in 514 tcp $SYSLOG_TCP
allow_in 6514 tcp $SYSLOG_TLS
allow_in 514 udp $SYSLOG_UDP
$IPT -A DOCKER-USER -i "$LAN_IF" -m limit --limit 6/min -j LOG --log-prefix "minisoc-docker-refus-entree "
$IPT -A DOCKER-USER -i "$LAN_IF" -j DROP

for d in $DNS; do
  $IPT -A DOCKER-USER -o "$LAN_IF" -d "$d" -p udp --dport 53 -j RETURN
  $IPT -A DOCKER-USER -o "$LAN_IF" -d "$d" -p tcp --dport 53 -j RETURN
done
for hp in $LAN_OUT; do
  $IPT -A DOCKER-USER -o "$LAN_IF" -d "${hp%:*}" -p tcp --dport "${hp##*:}" -m conntrack --ctstate NEW -j RETURN
done
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do   # le reste du réseau interne : refusé
  $IPT -A DOCKER-USER -o "$LAN_IF" -d "$net" -m limit --limit 6/min -j LOG --log-prefix "minisoc-docker-refus-lan "
  $IPT -A DOCKER-USER -o "$LAN_IF" -d "$net" -j DROP
done
$IPT -A DOCKER-USER -o "$LAN_IF" -p tcp -m multiport --dports "$INTERNET_PORTS" -m conntrack --ctstate NEW -j RETURN
$IPT -A DOCKER-USER -o "$LAN_IF" -m limit --limit 6/min -j LOG --log-prefix "minisoc-docker-refus-sortie "
$IPT -A DOCKER-USER -o "$LAN_IF" -j DROP
$IPT -A DOCKER-USER -j RETURN                  # trafic entre conteneurs : inchangé
echo "Pare-feu Mini-SOC appliqué."
```

```bash
sudo chmod 750 /usr/local/sbin/minisoc-firewall
```

### 6.3 Démarrage automatique, avant Docker

`/etc/systemd/system/minisoc-firewall.service` :

```ini
[Unit]
Description=Pare-feu Mini-SOC (machine et conteneurs)
After=local-fs.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/minisoc-firewall

[Install]
WantedBy=multi-user.target
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
   `manage.office.com`, `updates.maxmind.com`, `www.cisa.gov`, `www.cert.ssi.gouv.fr`, fournisseur d'IA, Teams,
   ntfy. Ajoutez-y aussi les sources de mise à jour : `deb.debian.org`, `security.debian.org`,
   `download.docker.com`, `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com`,
   `ghcr.io`, `pkg-containers.githubusercontent.com`.
2. Règle n° 1 : source = IP de la VM, destination = groupe « Mini-SOC - destinations », services HTTPS et
   TCP 8443 → **Accepter**, journalisation activée.
3. Règle n° 2, juste en dessous : source = IP de la VM, destination = toute zone WAN → **Refuser**,
   journalisation activée.

Si la VM est dans le même segment que les postes, le XGS ne voit pas le trafic LAN ↔ VM : seul le pare-feu local
le filtre. C'est l'intérêt du VLAN dédié (§ 0).

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
| `MINISOC_BITDEFENDER_ALLOWED_IPS` | IP du reverse proxy DMZ, si Bitdefender est raccordé |
| `COMPOSE_PROFILES` | `syslog-tls` (et `geoip` si MaxMind est utilisé : `geoip,syslog-tls`) |

> **Clé maître** (`MINISOC_MASTER_KEY`) : elle chiffre tous les jetons saisis dans l'interface. Copiez-la dès
> maintenant dans le coffre-fort de mots de passe de la DSI (KeePass), hors de la VM. Sans elle, une restauration
> oblige à ressaisir tous les secrets.

Reprise de la configuration du poste de développement (HarfangLab déjà réglé, etc.) : voir
[03-preparation-vm.md § 1](03-preparation-vm.md).

### 7.2 Certificat

Deux possibilités, de la meilleure à la plus simple :

1. **Certificat de votre PKI AD** (AD CS) pour `minisoc.mairie.local` : copier `minisoc.crt` (avec la chaîne)
   et `minisoc.key` dans `/etc/minisoc/tls/` (droits 600). Créer `/opt/minisoc/docker-compose.override.yml` :

   ```yaml
   services:
     web:
       volumes:
         - /etc/minisoc/tls:/certs:ro
   ```

   Dans `deploy/caddy/Caddyfile`, remplacer `tls internal` par `tls /certs/minisoc.crt /certs/minisoc.key`.
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
`AllowUsers adminsoc minisoc-backup@192.168.10.60`, puis `sudo systemctl reload ssh`.

Sur le serveur de sauvegarde (`192.168.10.60`), chaque nuit à 3 h, récupérer les archives de la VM
(`192.168.10.50`) :

```bash
rsync -a minisoc-backup@192.168.10.50:/ /sauvegardes/minisoc/
```

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
| Mini-SOC et images | à chaque version | instantané, nouvelle archive dans `/opt/minisoc` (garder `.env` et `docker-compose.override.yml`), puis `sudo docker compose pull && sudo docker compose up -d --build` |
| Audit de durcissement | trimestriel | `sudo lynis audit system` : traiter les avertissements ; viser un indice ≥ 75 |

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
