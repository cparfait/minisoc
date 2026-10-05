#!/usr/bin/env bash
# Restauration d'une sauvegarde : ./scripts/restore.sh backups/minisoc-AAAAMMJJ-HHMMSS.tar.gz[.gpg]
# Remplace la base PostgreSQL et les règles ; restaure le fichier .env d'origine (clé maître) s'il est absent.
# À tester chaque trimestre sur une machine de recette (S-13).
set -euo pipefail
cd "$(dirname "$0")/.."
ARCHIVE="${1:?usage : restore.sh <archive>}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$ARCHIVE" == *.gpg ]]; then
  gpg --batch --decrypt ${BACKUP_PASSPHRASE_FILE:+--passphrase-file "$BACKUP_PASSPHRASE_FILE"} "$ARCHIVE" \
    | tar -C "$WORK" -xzf -
else
  tar -C "$WORK" -xzf "$ARCHIVE"
fi

read -r -p "Remplacer la base actuelle par cette sauvegarde ? Taper OUI : " answer
[[ "$answer" == "OUI" ]] || { echo "Annulé."; exit 1; }

if [[ ! -f .env ]]; then
  cp "$WORK/env" .env && chmod 600 .env && echo ".env restauré"
elif ! cmp -s .env "$WORK/env"; then
  echo "ATTENTION : .env actuel différent de celui de la sauvegarde ; la clé maître doit être celle de la"
  echo "sauvegarde pour relire les secrets (MFA, mots de passe). Copie disponible : $WORK/env (supprimée à la fin)."
  cp "$WORK/env" ".env.sauvegarde-$(date +%Y%m%d%H%M%S)" && chmod 600 .env.sauvegarde-*
fi

docker compose stop api worker
docker compose exec -T postgres pg_restore -U minisoc -d minisoc --clean --if-exists --no-owner < "$WORK/postgres.dump"
tar -C backend -xf "$WORK/rules.tar"
if [[ -f "$WORK/events.native.gz" ]]; then
  CH_PASSWORD="$(grep '^CLICKHOUSE_PASSWORD=' .env | cut -d= -f2-)"
  gunzip -c "$WORK/events.native.gz" | docker compose exec -T clickhouse clickhouse-client --user minisoc \
    --password "$CH_PASSWORD" --query "INSERT INTO minisoc.events FORMAT Native"
fi
docker compose up -d --build api worker
echo "Restauration terminée."
