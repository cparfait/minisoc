#!/bin/bash
# Agent Trivy du Mini-SOC pour un serveur Linux : analyse chaque semaine les images Docker en service et les
# paquets du système, puis envoie le rapport au Mini-SOC (HTTPS, jeton propre à ce serveur).
#   Installation (root) : bash minisoc-trivy-agent.sh install <JETON> [fichier de l'autorité du Mini-SOC (PEM)]
#   Analyse immédiate   : minisoc-trivy-agent run
#   Désinstallation     : minisoc-trivy-agent uninstall
# Prérequis : Trivy installé (paquet « trivy » du dépôt d'Aqua Security) ou Docker (image aquasec/trivy).
# Le jeton se crée dans le Mini-SOC : Intégrations › Trivy › Configuration › Serveurs. Le serveur doit pouvoir
# joindre le Mini-SOC en 443 (sudo minisoc-setup › Entrants › Serveurs Trivy) et la base des failles (ghcr.io).
set -euo pipefail
MINISOC_URL_DEFAULT="{{MINISOC_URL}}"
TRIVY_IMAGE_DEFAULT="aquasec/trivy:0.76.0"
CONF=/etc/minisoc-trivy-agent.conf
BIN=/usr/local/sbin/minisoc-trivy-agent
CRON=/etc/cron.d/minisoc-trivy-agent

die() { echo "minisoc-trivy-agent : $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "à lancer en root (sudo)."

install_agent() {
  local token=${1:-} ca=${2:-}
  [ -n "$token" ] || die "jeton manquant : bash $0 install <JETON> [autorite.pem]"
  if [ -n "$ca" ]; then
    [ -f "$ca" ] || die "fichier d'autorité introuvable : $ca"
    install -D -m 0644 "$ca" /etc/minisoc-trivy-agent/ca.pem
    ca=/etc/minisoc-trivy-agent/ca.pem
  fi
  install -D -m 0750 "$0" "$BIN"
  umask 077
  cat > "$CONF" <<EOF
# Agent Trivy du Mini-SOC ($BIN), lu en root seulement
MINISOC_URL="$MINISOC_URL_DEFAULT"
TOKEN="$token"
# Autorité du certificat du Mini-SOC (PEM), si elle n'est pas dans le magasin du système
CA_FILE="$ca"
# Images à analyser : running (conteneurs en service) | all (toutes les images présentes) | none
IMAGES="running"
# Paquets du système (dpkg, rpm, apk) : yes | no
SYSTEM="yes"
# Sans binaire trivy, l'image utilisée avec Docker
TRIVY_IMAGE="$TRIVY_IMAGE_DEFAULT"
EOF
  chmod 600 "$CONF"
  umask 022
  # Chaque semaine, à une heure tirée au hasard (les serveurs n'envoient pas tous en même temps)
  if [ -d "$(dirname "$CRON")" ]; then
    printf '# Agent Trivy du Mini-SOC\n%d %d * * %d root %s run >/var/log/minisoc-trivy-agent.log 2>&1\n' \
      $((RANDOM % 60)) $((1 + RANDOM % 5)) $((1 + RANDOM % 5)) "$BIN" > "$CRON"
    echo "Agent installé : $BIN (réglages $CONF, planification $CRON). Première analyse :"
  else
    echo "Agent installé : $BIN (réglages $CONF). ATTENTION : pas de $(dirname "$CRON") sur ce serveur, planifier"
    echo "« $BIN run » une fois par semaine (cron, minuterie systemd). Première analyse :"
  fi
  run_scan
}

run_trivy() {  # run_trivy <arguments trivy…> : binaire local, sinon Docker
  if command -v trivy >/dev/null 2>&1; then
    trivy "$@"
  elif command -v docker >/dev/null 2>&1; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v minisoc-trivy-cache:/root/.cache \
      -v /:/host:ro "$TRIVY_IMAGE" "$@"
  else
    die "ni trivy ni docker sur ce serveur : installer Trivy (https://trivy.dev, dépôt apt/yum d'Aqua Security)."
  fi
}

run_scan() {
  [ -f "$CONF" ] || die "agent non installé ($CONF absent)."
  # shellcheck source=/dev/null
  . "$CONF"
  local n=0 root=/ img
  work=$(mktemp -d)   # globale : effacée à la sortie du script, après la fonction
  trap 'rm -rf "$work"' EXIT
  command -v trivy >/dev/null 2>&1 || root=/host
  run_trivy image --quiet --download-db-only
  if [ "${IMAGES:-running}" != none ] && command -v docker >/dev/null 2>&1; then
    if [ "$IMAGES" = all ]; then
      docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort -u > "$work/images"
    else
      docker ps --format '{{.Image}}' | sort -u > "$work/images"
    fi
    while read -r img; do
      [ -n "$img" ] || continue
      n=$((n + 1))
      run_trivy image --quiet --skip-db-update --scanners vuln --format json "$img" > "$work/r$n.json" \
        || { echo "Échec de l'analyse de $img"; rm -f "$work/r$n.json"; }
    done < "$work/images"
  fi
  if [ "${SYSTEM:-yes}" = yes ]; then
    n=$((n + 1))
    run_trivy rootfs --quiet --skip-db-update --scanners vuln --pkg-types os --format json \
      --skip-dirs "$root/proc,$root/sys,$root/dev,$root/run,$root/var/lib/docker,$root/var/lib/containerd" \
      "$root" > "$work/r$n.json" || { echo "Échec de l'analyse du système"; rm -f "$work/r$n.json"; }
  fi
  ls "$work"/r*.json >/dev/null 2>&1 || die "aucune analyse réussie : rien à envoyer."
  # Paquet envoyé : {"agent", "host", "scanned_at", "reports": [<JSON Trivy>, …]}, compressé
  {
    printf '{"agent":"minisoc-trivy-agent/1","host":"%s","scanned_at":"%s","reports":[' \
      "$(hostname -f 2>/dev/null || hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local first=1 f
    for f in "$work"/r*.json; do
      [ "$first" = 1 ] || printf ','
      first=0
      cat "$f"
    done
    printf ']}'
  } | gzip -c > "$work/bundle.json.gz"
  # Jeton dans un fichier d'en-têtes (jamais sur la ligne de commande, visible des autres comptes)
  printf 'Authorization: Bearer %s\n' "$TOKEN" > "$work/headers"
  chmod 600 "$work/headers"
  curl -fsS --max-time 300 --retry 3 --retry-delay 30 ${CA_FILE:+--cacert "$CA_FILE"} -H @"$work/headers" \
    -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary @"$work/bundle.json.gz" \
    "$MINISOC_URL/api/ingest/trivy"
  echo
  echo "Rapport envoyé au Mini-SOC ($(date '+%d/%m/%Y %H:%M'))."
}

case "${1:-}" in
  install) install_agent "${2:-}" "${3:-}" ;;
  run) run_scan ;;
  uninstall) rm -f "$CRON" "$BIN" "$CONF"; rm -rf /etc/minisoc-trivy-agent; echo "Agent retiré (révoquer aussi son jeton dans le Mini-SOC)." ;;
  *) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
