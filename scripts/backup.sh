#!/usr/bin/env bash
# Sauvegarde du Mini-SOC (S-13) : base PostgreSQL (alertes, comptes, paramètres, audit), paramètres et règles,
# et en option les événements ClickHouse. À planifier chaque nuit (cron) depuis le dossier du projet :
#   0 2 * * *  cd /opt/minisoc && ./scripts/backup.sh >> /var/log/minisoc-backup.log 2>&1
#
# Variables : BACKUP_DIR (défaut ./backups), RETENTION_DAYS (14), WITH_EVENTS=1 pour inclure les événements,
# BACKUP_PASSPHRASE_FILE pour chiffrer l'archive (gpg symétrique, AES-256) — fortement conseillé : l'archive
# contient le fichier .env et donc la clé maître.
set -euo pipefail
cd "$(dirname "$0")/.."

BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$BACKUP_DIR"

echo "[$(date -Is)] sauvegarde $STAMP"
docker compose exec -T postgres pg_dump -U minisoc -d minisoc -Fc > "$WORK/postgres.dump"
cp .env "$WORK/env"
tar -C backend -cf "$WORK/rules.tar" rules

if [[ "${WITH_EVENTS:-0}" == "1" ]]; then
  CH_PASSWORD="$(grep '^CLICKHOUSE_PASSWORD=' .env | cut -d= -f2-)"
  docker compose exec -T clickhouse clickhouse-client --user minisoc --password "$CH_PASSWORD" \
    --query "SELECT * FROM minisoc.events FORMAT Native" | gzip -1 > "$WORK/events.native.gz"
fi

ARCHIVE="$BACKUP_DIR/minisoc-$STAMP.tar.gz"
tar -C "$WORK" -czf "$ARCHIVE" .
if [[ -n "${BACKUP_PASSPHRASE_FILE:-}" ]]; then
  gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase-file "$BACKUP_PASSPHRASE_FILE" \
    -o "$ARCHIVE.gpg" "$ARCHIVE"
  rm -f "$ARCHIVE"
  ARCHIVE="$ARCHIVE.gpg"
else
  echo "ATTENTION : archive non chiffrée (contient la clé maître) ; définir BACKUP_PASSPHRASE_FILE"
fi
chmod 600 "$ARCHIVE"
find "$BACKUP_DIR" -name 'minisoc-*.tar.gz*' -mtime +"$RETENTION_DAYS" -delete
echo "[$(date -Is)] terminé : $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1)) — copier hors du serveur (S-13)"
