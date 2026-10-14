#!/bin/bash
# Mise à jour d'une VM Mini-SOC déjà installée, à partir du paquet produit avec l'ISO par build-iso.sh :
#   scp build/iso/minisoc-update-<version>.tar.gz adminsoc@<IP>:/tmp/      (depuis le poste DSI)
#   sudo minisoc-update /tmp/minisoc-update-<version>.tar.gz              (sur la VM)
# Première fois (VM installée avant cette commande) :
#   tar -xzf /tmp/minisoc-update-<version>.tar.gz -C /tmp
#   sudo bash /tmp/minisoc-update/minisoc-update.sh /tmp/minisoc-update-<version>.tar.gz
# Sauvegarde l'existant, met à jour l'application (/opt/minisoc, sans toucher à .env ni aux données) et les scripts
# du système (console, pare-feu, SSH, accueil), reconstruit puis redémarre les conteneurs. Si la construction
# échoue, l'application précédente est remise en place (les conteneurs en service n'ont pas été arrêtés).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "À lancer avec sudo."; exit 1; }
BUNDLE=${1:-}
YES=${2:-}
[ -f "$BUNDLE" ] || { echo "Usage : sudo minisoc-update /tmp/minisoc-update-<version>.tar.gz [--oui]"; exit 1; }
APP=/opt/minisoc
LIB=/usr/local/lib/minisoc-install
BACKUPS=/var/backups/minisoc/mises-a-jour
G=$'\e[1;32m' Y=$'\e[1;33m' R=$'\e[1;31m' N=$'\e[0m'
step() { echo; echo "${G}=== Mise à jour Mini-SOC : $* ===${N}"; }

# Toujours exécuter la version de ce script fournie dans le paquet (la mise à jour peut le modifier)
if [ -z "${MINISOC_UPDATE_DIR:-}" ]; then
  work=$(mktemp -d)
  tar -xzf "$BUNDLE" -C "$work"
  [ -f "$work/minisoc-update/VERSION" ] || { echo "Paquet de mise à jour invalide : $BUNDLE"; rm -rf "$work"; exit 1; }
  MINISOC_UPDATE_DIR="$work/minisoc-update" exec bash "$work/minisoc-update/minisoc-update.sh" "$@"
fi
B=$MINISOC_UPDATE_DIR
trap 'rm -rf "$(dirname "$B")"' EXIT
exec > >(tee -a /var/log/minisoc-update.log) 2>&1

NEW=$(cat "$B/VERSION")
OLD=$(cat /etc/minisoc/version 2>/dev/null || echo "inconnue (installée avant les mises à jour)")
[ -f "$APP/docker-compose.yml" ] || { echo "${R}Mini-SOC introuvable dans $APP : installer d'abord avec l'ISO.${N}"; exit 1; }
echo "Version installée : $OLD"
echo "Nouvelle version  : $NEW"
if [ "$YES" != "--oui" ]; then
  read -r -p "${Y}Mettre à jour maintenant ? Interruption de l'interface web : 1 à 2 minutes. [o/N] ${N}" answer
  case "$answer" in o|O|oui|OUI) ;; *) echo "Abandon."; exit 0 ;; esac
fi

# ---------- Sauvegarde de l'existant ----------
step "sauvegarde"
stamp=$(date +%Y%m%d-%H%M%S)
bk="$BACKUPS/$stamp"
install -d -m 0700 "$BACKUPS" "$bk"
tar -czf "$bk/opt-minisoc.tar.gz" -C /opt --exclude=minisoc/data/geoip minisoc
tar -czf "$bk/systeme.tar.gz" --ignore-failed-read -P /usr/local/sbin/minisoc-setup /usr/local/sbin/minisoc-sshd-config \
  /usr/local/sbin/minisoc-firewall /usr/local/sbin/minisoc-firstboot /usr/local/sbin/minisoc-update \
  /etc/systemd/system/minisoc-firewall.service /etc/update-motd.d/05-minisoc /usr/local/share/minisoc "$LIB" \
  2>/dev/null || true
echo "Sauvegarde : $bk"
ls -1dt "$BACKUPS"/*/ 2>/dev/null | tail -n +4 | xargs -r rm -rf   # on garde les 3 dernières

restore_app() {
  echo "${R}Échec : remise en place de l'application précédente.${N}"
  rm -rf "$APP.echec" && mv "$APP" "$APP.echec" && tar -xzf "$bk/opt-minisoc.tar.gz" -C /opt \
    && cp -a "$APP.echec/data/geoip" "$APP/data/" 2>/dev/null || true
  rm -rf "$APP.echec"
  tar -xzf "$bk/systeme.tar.gz" -P 2>/dev/null || true   # scripts du système de la version précédente
  /usr/local/sbin/minisoc-sshd-config && sshd -t && systemctl reload ssh || true
  systemctl daemon-reload; systemctl restart minisoc-firewall || true
}

# ---------- Application (/opt/minisoc) : .env et données conservés ----------
step "application"
manifest="$APP/.minisoc-fichiers"
tar -tzf "$B/minisoc.tar.gz" | grep -v '/$' | sort > "$B/fichiers"
if [ -f "$manifest" ]; then
  # Fichiers retirés de l'application depuis la version précédente
  comm -23 "$manifest" "$B/fichiers" | while read -r f; do
    case "$f" in ""|/*|*..*|.env|data/*) continue ;; esac
    rm -f "$APP/$f"
  done
fi
tar -xzf "$B/minisoc.tar.gz" -C "$APP"
cp "$B/fichiers" "$manifest"
chown -R root:root "$APP"
chmod 750 "$APP"
chmod 600 "$APP/.env"
missing=$(comm -13 <(grep -oE '^[A-Z_]+=' "$APP/.env" | sort -u) <(grep -oE '^#?[A-Z_]+=' "$APP/.env.example" | tr -d '#' | sort -u) || true)
[ -z "$missing" ] || echo "${Y}Réglages nouveaux dans .env.example, absents de .env (valeurs par défaut utilisées) :${N} $(echo $missing | tr -d '=')"

# ---------- Scripts du système ----------
step "scripts du système"
install -d -m 0700 "$LIB"
for f in minisoc.tar.gz minisoc-firewall minisoc-firewall.service minisoc-sshd-config.sh minisoc-setup.sh banner.txt \
         minisoc-motd minisoc-update.sh VERSION; do
  [ -f "$B/$f" ] && install -m 0600 "$B/$f" "$LIB/$f"
done
install -m 0700 "$B/firstboot.sh" /usr/local/sbin/minisoc-firstboot
install -m 0750 "$B/minisoc-setup.sh" /usr/local/sbin/minisoc-setup
install -m 0750 "$B/minisoc-sshd-config.sh" /usr/local/sbin/minisoc-sshd-config
install -m 0750 "$B/minisoc-firewall" /usr/local/sbin/minisoc-firewall
install -m 0644 "$B/minisoc-firewall.service" /etc/systemd/system/minisoc-firewall.service
install -m 0750 "$B/minisoc-update.sh" /usr/local/sbin/minisoc-update
install -D -m 0644 "$B/banner.txt" /usr/local/share/minisoc/banner.txt
install -m 0755 "$B/minisoc-motd" /etc/update-motd.d/05-minisoc
[ ! -x /etc/update-motd.d/10-uname ] || chmod -x /etc/update-motd.d/10-uname
if grep -qs 'Mini-SOC : VM installée' /etc/motd; then   # ancien accueil figé : remplacé par l'accueil calculé
  cp /etc/motd /etc/minisoc/installation.txt
  : > /etc/motd
fi
if [ -f /etc/fail2ban/jail.d/minisoc.local ] && ! grep -q banaction_allports /etc/fail2ban/jail.d/minisoc.local; then
  sed -i '/^mode = aggressive$/a banaction = %(banaction_allports)s' /etc/fail2ban/jail.d/minisoc.local
  systemctl restart fail2ban
fi
/usr/local/sbin/minisoc-sshd-config
if sshd -t; then systemctl reload ssh; else echo "${R}Configuration SSH refusée par sshd -t : SSH non rechargé.${N}"; fi
systemctl daemon-reload
if ! systemctl restart minisoc-firewall; then
  echo "${R}Pare-feu : nouvelle version en échec, retour à la précédente.${N}"
  tar -xzf "$bk/systeme.tar.gz" -P /usr/local/sbin/minisoc-firewall 2>/dev/null || true
  systemctl restart minisoc-firewall
fi

# ---------- Conteneurs ----------
step "construction des conteneurs"
cd "$APP"
retry() { for n in 1 2 3; do "$@" && return 0; echo "Échec (essai $n/3) : $*"; [ "$n" = 3 ] || sleep 20; done; return 1; }
if ! { retry docker compose pull --ignore-buildable && retry docker compose build; }; then
  restore_app
  echo "${R}Mise à jour abandonnée : les conteneurs en service n'ont pas été touchés. Journal : /var/log/minisoc-update.log${N}"
  exit 1
fi
step "redémarrage"
docker compose up -d --remove-orphans
pending=0
for _ in $(seq 30); do
  pending=$(docker compose ps --format '{{.Service}} {{.Health}}' | awk '$2 != "" && $2 != "healthy"' | wc -l)
  [ "$pending" = 0 ] && break
  sleep 10
done
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
echo "$NEW" > /etc/minisoc/version
echo
if [ "$pending" = 0 ]; then
  echo "${G}Mise à jour terminée : version $NEW.${N}"
else
  echo "${Y}Version $NEW installée, mais des services ne sont pas « healthy » : sudo docker compose -f $APP/docker-compose.yml ps${N}"
fi
echo "Retour à la version précédente si besoin :"
echo "  sudo tar -xzf $bk/opt-minisoc.tar.gz -C /opt && sudo docker compose -f $APP/docker-compose.yml up -d --build"
