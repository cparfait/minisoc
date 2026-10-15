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
  /usr/local/sbin/minisoc-trivy /etc/systemd/system/minisoc-trivy.service /etc/systemd/system/minisoc-trivy.timer \
  /etc/systemd/system/minisoc-trivy.path \
  2>/dev/null || true
echo "Sauvegarde : $bk"
ls -1dt "$BACKUPS"/*/ 2>/dev/null | tail -n +4 | xargs -r rm -rf   # on garde les 3 dernières
# Anciens paquets de mise à jour déposés à côté de celui-ci (/tmp) : effacés, seul le paquet en cours reste
bundle_dir=$(dirname "$(readlink -f "$BUNDLE")")
for old_bundle in "$bundle_dir"/minisoc-update-*.tar.gz; do
  [ -f "$old_bundle" ] && [ "$(readlink -f "$old_bundle")" != "$(readlink -f "$BUNDLE")" ] || continue
  rm -f "$old_bundle" "$old_bundle.sha256" && echo "Ancien paquet de mise à jour effacé : ${old_bundle##*/}"
done

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
# Console de paramétrage : dialog (Échap, formulaires, couleurs) ; sans Internet, elle l'installera à son lancement
command -v dialog >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -q dialog >/dev/null 2>&1   || echo "${Y}dialog non installé (dépôts Debian injoignables ?) : sudo apt install dialog${N}"
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
# Analyse Trivy de la VM (deploy/trivy) : service, minuterie hebdomadaire, demande depuis l'interface
install -m 0750 "$APP/deploy/trivy/minisoc-trivy.sh" /usr/local/sbin/minisoc-trivy
for u in service timer path; do install -m 0644 "$APP/deploy/trivy/minisoc-trivy.$u" /etc/systemd/system/; done
install -d -m 0750 /var/lib/minisoc/trivy
grep -q '^TRIVY_DIR=' "$APP/.env" || echo 'TRIVY_DIR=/var/lib/minisoc/trivy' >> "$APP/.env"
systemctl daemon-reload
systemctl enable --now minisoc-trivy.timer minisoc-trivy.path >/dev/null 2>&1 \
  || echo "${Y}Minuterie de l'analyse Trivy non activée : sudo systemctl enable --now minisoc-trivy.timer minisoc-trivy.path${N}"
if ! systemctl restart minisoc-firewall; then
  echo "${R}Pare-feu : nouvelle version en échec, retour à la précédente.${N}"
  tar -xzf "$bk/systeme.tar.gz" -P /usr/local/sbin/minisoc-firewall 2>/dev/null || true
  systemctl restart minisoc-firewall
fi

# ---------- Conteneurs ----------
step "construction des conteneurs"
cd "$APP"
retry() { for n in 1 2 3; do "$@" && return 0; echo "Échec (essai $n/3) : $*"; [ "$n" = 3 ] || sleep 20; done; return 1; }
# Construction sans cache, sur les dernières images de base : les correctifs Alpine/Debian publiés depuis la
# précédente mise à jour sont appliqués (deploy/images/alpine-patch.Dockerfile, Dockerfiles de l'application)
if ! { retry docker compose pull --ignore-buildable && retry docker compose --profile outils build --pull --no-cache; }; then
  restore_app
  echo "${R}Mise à jour abandonnée : les conteneurs en service n'ont pas été touchés. Journal : /var/log/minisoc-update.log${N}"
  exit 1
fi
# ---------- PostgreSQL : changement de version majeure (export de l'ancienne, import dans la nouvelle) ----------
# Chaque version majeure a son propre volume (pgdata18…) : l'ancien reste intact, d'où un retour arrière simple.
# MIGRATION-PG-DEBUT
pg_major_migration() {
  local running target project dump ready old_vol
  running=$(docker compose exec -T postgres postgres -V 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\)\.[0-9].*/\1/p' || true)
  target=$(docker compose config --images 2>/dev/null | sed -n 's/^\(minisoc-\)\{0,1\}postgres:\([0-9][0-9]*\).*/\2/p' | head -1)
  [ -n "$running" ] && [ -n "$target" ] && [ "$running" != "$target" ] || return 0
  project=$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
  old_vol=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}' \
    "$(docker compose ps -q postgres)" 2>/dev/null || true)
  step "PostgreSQL $running → $target : migration des données"
  pg_back() {
    echo "${R}Migration de PostgreSQL en échec : retour à PostgreSQL $running et à l'application précédente.${N}"
    docker compose rm -sf postgres >/dev/null 2>&1 || true
    docker volume rm "${project}_pgdata$target" >/dev/null 2>&1 || true
    restore_app
    (cd "$APP" && docker compose up -d) || true
    echo "Journal : /var/log/minisoc-update.log"
    exit 1
  }
  # Place disponible : l'export (dans la sauvegarde) et la nouvelle base, chacun de la taille de la base actuelle
  local size need free_bk free_docker
  size=$(docker compose exec -T postgres psql -U minisoc -d minisoc -At -c "SELECT pg_database_size('minisoc')")
  need=$(( ${size:-0} * 2 / 1024 + 512000 ))   # Kio : deux fois la base, plus 500 Mio de marge
  free_bk=$(df -Pk "$bk" | awk 'NR==2 {print $4}')
  free_docker=$(df -Pk /var/lib/docker | awk 'NR==2 {print $4}')
  if [ "${free_bk:-0}" -lt "$need" ] || [ "${free_docker:-0}" -lt "$need" ]; then
    echo "${R}Place insuffisante pour migrer PostgreSQL : $((need / 1024)) Mio nécessaires (sauvegarde et Docker).${N}"
    restore_app
    echo "Mise à jour abandonnée avant toute modification de la base. Libérer de la place puis relancer."
    exit 1
  fi
  docker compose stop api worker                                   # plus aucune écriture pendant l'export
  # Nombre de lignes de chaque table, comparé après l'import
  count_rows() {
    printf '%s\n%s\n' \
      "SELECT format('SELECT %L, count(*) FROM %I.%I', table_schema || '.' || table_name, table_schema, table_name) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1" \
      '\gexec' | docker compose exec -T postgres psql -U minisoc -d minisoc -At -F '|' 2>/dev/null | sort
  }
  local before after
  before=$(count_rows)
  dump="$bk/postgres-$running.dump"
  docker compose exec -T postgres pg_dump -U minisoc -d minisoc -Fc > "$dump" && [ -s "$dump" ] || pg_back
  echo "Base exportée : $dump ($(du -h "$dump" | cut -f1)), $(echo "$before" | grep -c .) table(s)"
  docker compose up -d postgres || pg_back                          # nouvelle version, nouveau volume vide
  ready=0
  for _ in $(seq 90); do
    # En TCP : pendant l'initialisation, le serveur temporaire de l'image n'écoute que sur le socket local
    if docker compose exec -T postgres pg_isready -h 127.0.0.1 -U minisoc -d minisoc >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 2
  done
  [ "$ready" = 1 ] || pg_back
  docker compose exec -T postgres pg_restore -U minisoc -d minisoc --no-owner --exit-on-error < "$dump" || pg_back
  after=$(count_rows)
  if [ -z "$before" ] || [ "$before" != "$after" ]; then
    echo "${R}Contrôle après import : le nombre de lignes diffère.${N}"
    diff <(echo "$before") <(echo "$after") | head -20
    pg_back
  fi
  echo "${G}Données importées dans PostgreSQL $target et vérifiées ($(echo "$after" | grep -c .) table(s), même nombre de lignes). Ancien volume conservé : ${old_vol:-?}${N}"
  echo "  (à supprimer quand tout est vérifié : sudo docker volume rm ${old_vol:-<ancien volume>})"
}
# MIGRATION-PG-FIN
pg_major_migration

step "redémarrage"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)  # contrôle de la réception syslog : journaux de l'API depuis ce moment
# Listes du pare-feu reprises par l'interface web (serveurs Trivy limités à l'envoi de leurs rapports), recopiées dans
# .env depuis /etc/minisoc/firewall.conf : aussi pour une VM paramétrée avant que l'interface web ne les lise
/usr/local/sbin/minisoc-setup --acces-web \
  || echo "${Y}Accès web des serveurs Trivy non recopié : sudo minisoc-setup --acces-web${N}"
docker compose up -d --remove-orphans
pending=0
for _ in $(seq 30); do
  pending=$(docker compose ps --format '{{.Service}} {{.Health}}' | awk '$2 != "" && $2 != "healthy"' | wc -l)
  [ "$pending" = 0 ] && break
  sleep 10
done
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
echo "$NEW" > /etc/minisoc/version

# ---------- Réception syslog : Vector → API ----------
# Une version de Vector peut changer de comportement sans erreur de configuration (0.59 : jeton plus remplacé, tout
# refusé par l'API). Pendant 2 minutes au plus, les envois de Vector à l'API sont lus dans le journal de l'API.
syslog_refused=0 syslog_ok=0
if docker compose ps --services --status running 2>/dev/null | grep -qx vector; then
  step "contrôle de la réception syslog (2 min au plus)"
  for _ in $(seq 12); do
    sent=$(docker compose logs --no-log-prefix --since "$started" api 2>/dev/null | grep '/api/ingest/syslog' || true)
    syslog_refused=$(printf '%s\n' "$sent" | grep -cE 'HTTP/[0-9.]+" 40[13]' || true)
    syslog_ok=$(printf '%s\n' "$sent" | grep -cE 'HTTP/[0-9.]+" 20[0-9]' || true)
    [ "$syslog_refused" -gt 0 ] || [ "$syslog_ok" -gt 0 ] && break
    sleep 10
  done
  if [ "$syslog_refused" -gt 0 ]; then
    echo "${R}Réception syslog COUPÉE : l'API refuse les envois de Vector ($syslog_refused refus, jeton d'ingestion).${N}"
    echo "${R}Pare-feu, VPN, Vectra… ne sont plus reçus. Revenir à la version précédente (commande ci-dessous).${N}"
  elif [ "$syslog_ok" -gt 0 ]; then
    echo "${G}Réception syslog : $syslog_ok envoi(s) de Vector acceptés par l'API.${N}"
  else
    echo "${Y}Réception syslog : aucun envoi de Vector en 2 min (normal si aucun équipement n'envoie de journaux ;"
    echo "sinon vérifier : sudo docker logs --since 5m minisoc-vector-1).${N}"
  fi
fi
echo
if [ "$syslog_refused" -gt 0 ]; then
  echo "${R}Version $NEW installée, mais la réception syslog est coupée : revenir à la version précédente.${N}"
elif [ "$pending" = 0 ]; then
  echo "${G}Mise à jour terminée : version $NEW.${N}"
  # Paquet appliqué (la sauvegarde ci-dessous permet le retour arrière) et images Docker devenues inutiles
  rm -f "$BUNDLE" "$BUNDLE.sha256"
  docker image prune -f >/dev/null 2>&1 || true
  # Images reconstruites : nouvelle analyse Trivy en tâche de fond (Intégrations › Trivy, page Vulnérabilités)
  systemctl start --no-block minisoc-trivy.service && echo "Analyse Trivy des nouvelles images lancée en tâche de fond."
else
  echo "${Y}Version $NEW installée, mais des services ne sont pas « healthy » : sudo docker compose -f $APP/docker-compose.yml ps${N}"
fi
echo "Retour à la version précédente si besoin :"
echo "  sudo tar -xzf $bk/opt-minisoc.tar.gz -C /opt && sudo docker compose -f $APP/docker-compose.yml up -d --build"
