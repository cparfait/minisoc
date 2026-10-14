#!/bin/bash
# Premier démarrage de la VM Mini-SOC, sans aucune question : disque de données, Docker, durcissement
# (doc 04 § 4 à 6), application Mini-SOC (§ 7) et sauvegardes (§ 8). Le pare-feu démarre en mode initial
# (plages privées) ; sudo minisoc-setup le resserre ensuite avec les adresses du site.
# Relançable sans risque (sudo /usr/local/sbin/minisoc-firstboot) : chaque étape vérifie si elle est déjà faite.
set -euo pipefail
exec > >(tee -a /var/log/minisoc-firstboot.log) 2>&1

SRC=/usr/local/lib/minisoc-install
. /etc/minisoc-firstboot/site.env
if [ -n "${HTTP_PROXY:-}" ]; then
  export http_proxy="$HTTP_PROXY" https_proxy="$HTTP_PROXY"
fi
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -y -o DPkg::Lock::Timeout=600"
PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
WARNINGS=""
APP_OK=1
step() { echo; echo "=== Mini-SOC, premier démarrage : $* ==="; }
warn() { echo "ATTENTION : $*"; WARNINGS="$WARNINGS- $*"$'\n'; }

iface=$(ip -o route show default | awk '{print $5; exit}')
vm_ip=$(ip -4 -o addr show dev "$iface" scope global | awk '{print $4; exit}' | cut -d/ -f1)
gateway=$(ip -o route show default | awk '{print $3; exit}')
dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | tr '\n' ' ' | sed 's/ $//')
ntp=${VM_NTP:-$dns}      # dans un domaine AD, les contrôleurs servent aussi l'heure
fqdn=$(hostname -f 2>/dev/null || hostname)

install -D -m 0644 "$SRC/banner.txt" /usr/local/share/minisoc/banner.txt
printf '\e[1;32m'; cat /usr/local/share/minisoc/banner.txt; printf '\e[0m'

# ---------- Paquets complémentaires ----------
step "paquets"
dpkg --configure -a          # reprise d'une installation interrompue (coupure pendant un premier démarrage)
$APT install fail2ban python3-systemd libpam-pwquality apparmor apparmor-utils whiptail

# ---------- Disque de données sur /var/lib/docker (avant Docker) ----------
step "disque de données"
if findmnt -n /var/lib/docker >/dev/null; then
  echo "déjà monté"
elif grep -q 'LABEL=minisoc-data' /etc/fstab; then
  mount /var/lib/docker
else
  root_disk=/dev/$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")
  candidates=()
  while read -r dev type rm; do
    [ "$type" = disk ] && [ "$rm" = 0 ] && [ "$dev" != "$root_disk" ] || continue
    [ "$(lsblk -no NAME "$dev" | wc -l)" = 1 ] || continue     # déjà partitionné
    blkid -p "$dev" >/dev/null 2>&1 && continue                 # contient déjà un système de fichiers
    candidates+=("$dev")
  done < <(lsblk -dnpo NAME,TYPE,RM)
  if [ "${#candidates[@]}" = 1 ]; then
    dev=${candidates[0]}
    echo "formatage de $dev ($(lsblk -dno SIZE "$dev"))"
    mkfs.ext4 -q -L minisoc-data -m 1 "$dev"
    mkdir -p /var/lib/docker
    echo 'LABEL=minisoc-data /var/lib/docker ext4 defaults 0 2' >> /etc/fstab
    systemctl daemon-reload
    mount /var/lib/docker
  else
    warn "disque de données non trouvé (${#candidates[@]} disque(s) vide(s)) : Docker est sur le disque système"
  fi
fi

# ---------- Docker (§ 5), plage d'adresses choisie ----------
step "Docker"
pool=${DOCKER_POOL:-10.255.0.0/16}
# Chevauchement avec le réseau de la VM (carte LAN, pas les ponts Docker), sa passerelle, ses DNS ou ses NTP ?
conflict=$(python3 - "$pool" "$(ip -4 -o addr show dev "$iface" scope global | awk '{print $4}' | tr '\n' ' ')" $gateway $dns $ntp <<'EOF'
import ipaddress, sys
pool = ipaddress.ip_network(sys.argv[1])
print(" ".join(a for a in " ".join(sys.argv[2:]).split() if ipaddress.ip_network(a, strict=False).overlaps(pool)))
EOF
)
if [ -n "$conflict" ]; then
  warn "la plage Docker $pool chevauche $conflict : application non démarrée. Changer DOCKER_POOL dans /etc/minisoc-firstboot/site.env puis relancer sudo minisoc-firstboot"
  APP_OK=0
fi
bip=$(python3 -c "import ipaddress,sys; n=list(ipaddress.ip_network(sys.argv[1]).subnets(new_prefix=24))[-1]; print(f'{n[1]}/24')" "$pool")
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "local",
  "log-opts": { "max-size": "20m", "max-file": "5" },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "bip": "$bip",
  "default-address-pools": [{ "base": "$pool", "size": 24 }]
}
EOF
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
  $APT update
  $APT install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl restart docker
docker info --format 'Docker {{.ServerVersion}}, données : {{.DockerRootDir}}'

# ---------- Mises à jour de sécurité automatiques (§ 4.1) ----------
step "mises à jour automatiques"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable --now unattended-upgrades

# ---------- Heure (§ 4.2) ----------
step "heure"
: > /etc/chrony/sources.d/ad.sources
for s in $ntp; do echo "server $s iburst" >> /etc/chrony/sources.d/ad.sources; done
sed -i 's/^pool /#pool /' /etc/chrony/chrony.conf
systemctl restart chrony
[ -n "${VM_NTP:-}" ] || echo "serveurs de temps : DNS ($ntp), à corriger dans sudo minisoc-setup si ce ne sont pas des contrôleurs de domaine"

# ---------- Noyau (§ 4.4) ----------
step "paramètres du noyau"
cat > /etc/sysctl.d/90-minisoc.conf <<'EOF'
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
EOF
sysctl --system >/dev/null

# ---------- Système : modules, mémoire partagée, comptes (§ 4.7) ----------
step "système"
cat > /etc/modprobe.d/minisoc-blacklist.conf <<'EOF'
# Protocoles réseau et systèmes de fichiers inutiles, stockage USB et FireWire : chargement refusé
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install usb-storage /bin/false
install firewire-core /bin/false
EOF
grep -q '^tmpfs /dev/shm' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' >> /etc/fstab
mount -o remount,nodev,nosuid,noexec /dev/shm
echo '* hard core 0' > /etc/security/limits.d/90-minisoc.conf
# Mots de passe locaux : 12 caractères minimum, 3 classes ; su réservé au groupe sudo
sed -i 's/^#\? *minlen *=.*/minlen = 12/; s/^#\? *minclass *=.*/minclass = 3/' /etc/security/pwquality.conf
grep -q '^auth *required *pam_wheel.so' /etc/pam.d/su || sed -i '0,/^# *auth *required *pam_wheel.so$/s//auth       required   pam_wheel.so group=sudo/' /etc/pam.d/su
aa-status --enabled && echo "AppArmor actif" || warn "AppArmor inactif"

# ---------- SSH (§ 4.3) et fail2ban ----------
step "SSH et fail2ban"
echo "Système de la DSI - accès réservé aux administrateurs habilités. Toute connexion est journalisée." > /etc/issue.net
install -m 0750 "$SRC/minisoc-sshd-config.sh" /usr/local/sbin/minisoc-sshd-config
/usr/local/sbin/minisoc-sshd-config
sshd -t
systemctl reload ssh
[ -s /home/adminsoc/.ssh/authorized_keys ] || warn "aucune clé SSH : connexion par mot de passe active jusqu'à sudo minisoc-setup"
cat > /etc/fail2ban/jail.d/minisoc.local <<'EOF'
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
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# ---------- Journaux et audit (§ 4.5) ----------
step "journaux et audit"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/minisoc.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=1G
EOF
systemctl restart systemd-journald
# Les chemins surveillés doivent exister pour que les règles se chargent.
install -d -m 0750 /etc/minisoc /opt/minisoc
install -d -m 0700 -o adminsoc -g adminsoc /home/adminsoc/.ssh
cat > /etc/audit/rules.d/minisoc.rules <<'EOF'
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
EOF
augenrules --load
echo "$(auditctl -l | grep -c -- '-k ') règles d'audit actives"

# ---------- Services inutiles (§ 4.6) ----------
step "services"
# Sa configuration par défaut contient « flush ruleset », qui effacerait les règles de Docker (pare-feu : § 6).
systemctl disable --now nftables

# ---------- Application Mini-SOC (§ 7) ----------
step "application Mini-SOC"
cd /opt/minisoc
if [ ! -f docker-compose.yml ]; then
  tar -xzf "$SRC/minisoc.tar.gz" -C /opt/minisoc
  chown -R root:root /opt/minisoc
  chmod 750 /opt/minisoc
fi
[ -f .env ] || python3 scripts/init_env.py
chmod 600 .env
setenv() { if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }
setenv MINISOC_HOSTNAME "$fqdn"
setenv MINISOC_PUBLIC_URL "https://$fqdn"
setenv WEB_BIND "$vm_ip"
setenv SYSLOG_BIND "$vm_ip"
setenv COMPOSE_PROFILES syslog-tls
[ -f data/syslog-tls/server.crt ] || sh scripts/syslog_cert.sh "$fqdn" "$vm_ip"
if [ "$APP_OK" = 1 ]; then
  docker compose up -d --build
  for _ in $(seq 60); do
    pending=$(docker compose ps --format '{{.Service}} {{.Health}}' | awk '$2 != "" && $2 != "healthy"' | wc -l)
    [ "$pending" = 0 ] && break
    sleep 10
  done
  docker compose ps --format 'table {{.Service}}\t{{.Status}}'
  [ "$pending" = 0 ] || warn "certains services ne sont pas « healthy » : sudo docker compose -f /opt/minisoc/docker-compose.yml ps"
fi

# ---------- Pare-feu (§ 6), mode initial ----------
step "pare-feu"
install -m 0750 "$SRC/minisoc-firewall" /usr/local/sbin/minisoc-firewall
install -m 0644 "$SRC/minisoc-firewall.service" /etc/systemd/system/minisoc-firewall.service
if [ ! -f /etc/minisoc/firewall.conf ]; then
  cat > /etc/minisoc/firewall.conf <<EOF
# Pare-feu du Mini-SOC : adresses autorisées (adresses ou plages CIDR, séparées par des espaces).
# Après modification : sudo systemctl restart minisoc-firewall. Assistant : sudo minisoc-setup
# MODE INITIAL écrit au premier démarrage : toutes les plages privées sont acceptées. À RESTREINDRE.
LAN_IF="$iface"

# --- Entrant ---
ADMINS="$PRIVATE"
WALL=""
SYSLOG_TCP="$PRIVATE"
SYSLOG_TLS="$PRIVATE"
SYSLOG_UDP=""
BACKUP_SERVER=""

# --- Sortant (hôte:port) ---
DNS="$dns"
NTP="$ntp"
LAN_OUT=""
INTERNET_PORTS="443,8443"
EOF
  chmod 640 /etc/minisoc/firewall.conf
fi
systemctl daemon-reload
systemctl enable minisoc-firewall
systemctl restart minisoc-firewall
systemctl restart docker
grep -q 'MODE INITIAL' /etc/minisoc/firewall.conf && warn "pare-feu en mode initial (plages privées) : à resserrer avec sudo minisoc-setup"

# ---------- Sauvegardes (§ 8) ----------
step "sauvegardes"
[ -f /etc/minisoc/backup.pass ] || (umask 077; openssl rand -base64 32 > /etc/minisoc/backup.pass)
getent group minisoc-backup >/dev/null || groupadd --system minisoc-backup
id minisoc-backup >/dev/null 2>&1 || useradd --system --gid minisoc-backup --create-home \
  --home-dir /var/lib/minisoc-backup --shell /bin/sh minisoc-backup
install -d -o root -g minisoc-backup -m 750 /var/backups/minisoc /var/backups/minisoc/archives
install -d -o minisoc-backup -g minisoc-backup -m 700 /var/lib/minisoc-backup/.ssh
cat > /etc/cron.d/minisoc-backup <<'EOF'
0 2 * * * root cd /opt/minisoc && BACKUP_DIR=/var/backups/minisoc BACKUP_PASSPHRASE_FILE=/etc/minisoc/backup.pass ./scripts/backup.sh >> /var/log/minisoc-backup.log 2>&1 && chgrp minisoc-backup /var/backups/minisoc/*.gpg && chmod 640 /var/backups/minisoc/*.gpg
30 2 * * * root rsync -a /var/lib/docker/volumes/minisoc_archives/_data/ /var/backups/minisoc/archives/ && chgrp -R minisoc-backup /var/backups/minisoc/archives && chmod -R g+rX,o-rwx /var/backups/minisoc/archives
EOF
chmod 644 /etc/cron.d/minisoc-backup
warn "phrase de passe des sauvegardes (/etc/minisoc/backup.pass) et clé maître (MINISOC_MASTER_KEY de /opt/minisoc/.env) à copier dans le coffre-fort de la DSI"

# ---------- Console de paramétrage et écran d'accueil de la console vSphere ----------
install -m 0750 "$SRC/minisoc-setup.sh" /usr/local/sbin/minisoc-setup
{
  cat /usr/local/share/minisoc/banner.txt
  echo
  echo '  \n.\o  ·  \4  ·  \s \r'
  echo '  Paramétrage : sudo minisoc-setup'
  echo
} > /etc/issue

# ---------- Fin ----------
step "terminé"
{
  echo "Mini-SOC : VM installée le $(date '+%d/%m/%Y %H:%M'). $fqdn ($vm_ip), interface $iface."
  echo "Étape suivante : sudo minisoc-setup (pare-feu, SSH, sauvegarde, compte de secours, écran mural)."
  [ -z "$WARNINGS" ] || printf 'Points d’attention :\n%s' "$WARNINGS"
} | tee /etc/motd
if [ "$APP_OK" = 1 ]; then
  touch /var/lib/minisoc-firstboot.done
  systemctl disable minisoc-firstboot.service
fi
