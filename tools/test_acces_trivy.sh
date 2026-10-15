#!/bin/bash
# Serveurs Trivy limités à l'envoi de leurs rapports (deploy/caddy/Caddyfile, § 6.5 de la doc 04) : contrôle avant
# livraison, depuis la racine du dépôt :   bash tools/test_acces_trivy.sh
#   1. syntaxe de minisoc-setup et minisoc-update (bash -n) ;
#   2. recopie des listes du pare-feu dans .env (web_access_env de minisoc-setup), sur des fichiers temporaires ;
#   3. caddy validate puis réponses réelles de Caddy selon l'adresse source, dans un conteneur sans réseau
#      (--network none : aucun réseau Docker créé ; adresses 127.0.0.x de la boucle locale du conteneur).
# Image : minisoc-web:latest si elle existe (même Caddy que la VM), sinon caddy:2-alpine. Sortie 1 au premier écart.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
ok() { printf 'ok     %s\n' "$*"; }
ko() { printf 'ÉCHEC  %s\n' "$*"; fail=1; }

# ---------- 1. Syntaxe ----------
for f in deploy/iso/minisoc-setup.sh deploy/iso/minisoc-update.sh; do
  if bash -n "$f"; then ok "syntaxe $f"; else ko "syntaxe $f"; fi
done

# ---------- 2. Recopie dans .env ----------
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
eval "$(sed -n '/^web_access_env() {/,/^}/p' deploy/iso/minisoc-setup.sh)"
APP=$tmp FW=$tmp/firewall.conf
printf 'POSTGRES_PASSWORD=x\nMINISOC_HOSTNAME=minisoc.local\n' > "$APP/.env"
fw() { printf 'ADMINS="%s"\nWALL="%s"\nTRIVY="%s"\n' "$1" "$2" "$3" > "$FW"; }
envline() { grep "^$1=" "$APP/.env" || echo "(absente)"; }
expect() {  # expect <description> <code attendu 0|1> <ligne TRIVY attendue> <ligne WEB attendue>
  local rc=0; web_access_env || rc=$?
  local t w; t=$(envline MINISOC_TRIVY_IPS); w=$(envline MINISOC_WEB_IPS)
  if [ "$rc" = "$2" ] && [ "$t" = "$3" ] && [ "$w" = "$4" ] && [ "$(grep -c '^MINISOC_TRIVY_IPS=' "$APP/.env")" = 1 ]; then
    ok "$1"
  else
    ko "$1 : code $rc, $t / $w"
  fi
}
fw "192.168.10.21  192.168.10.22" "" "192.168.10.70 192.168.20.0/24"
expect ".env complété" 0 "MINISOC_TRIVY_IPS=192.168.10.70 192.168.20.0/24" "MINISOC_WEB_IPS=192.168.10.21 192.168.10.22"
expect "relance sans changement : rien à redémarrer" 1 "MINISOC_TRIVY_IPS=192.168.10.70 192.168.20.0/24" "MINISOC_WEB_IPS=192.168.10.21 192.168.10.22"
fw "192.168.10.21" "192.168.10.40" ""
expect "écran ajouté, plus de serveur Trivy" 0 "MINISOC_TRIVY_IPS=" "MINISOC_WEB_IPS=192.168.10.21 192.168.10.40"
grep -q '^MINISOC_HOSTNAME=minisoc.local$' "$APP/.env" && ok "autres réglages de .env conservés" || ko "autres réglages de .env modifiés"

# ---------- 3. Caddy ----------
image=minisoc-web:latest
docker image inspect "$image" >/dev/null 2>&1 || image=caddy:2-alpine
mkdir -p "$tmp/srv"
echo '<!doctype html><title>Mini-SOC</title>' > "$tmp/srv/index.html"
cat > "$tmp/essai.sh" <<'EOF'
# Rôles : .2 serveur Trivy, .3 poste DSI, .4 dans les deux listes, .10 dans une plage Trivy, .9 dans cette plage mais
# écran mural, .5 dans aucune liste (le pare-feu le refuse en amont). 502 : requête transmise à l'API (absente ici).
export MINISOC_HOSTNAME=localhost MINISOC_IP=127.0.0.1
export MINISOC_TRIVY_IPS="${T-127.0.0.2 127.0.0.4 127.0.0.8/29}" MINISOC_WEB_IPS="${W-127.0.0.3 127.0.0.4 127.0.0.9}"
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/tmp/v 2>&1 || { cat /tmp/v; echo "ÉCHEC  caddy validate"; exit 1; }
echo "ok     caddy validate (TRIVY='$MINISOC_TRIVY_IPS', WEB='$MINISOC_WEB_IPS')"
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/tmp/log 2>&1 &
for i in $(seq 60); do curl -sk -o /dev/null --resolve localhost:443:127.0.0.1 https://localhost/ && break; sleep 0.25; done
fail=0
check() {  # check <attendu> <ip source> <méthode> <url> [en-tête]
  want=$1; shift
  got=$(curl -sk -o /dev/null -w '%{http_code}' --interface "$1" -X "$2" --resolve localhost:443:127.0.0.1 ${4:+-H "$4"} "$3")
  if [ "$got" = "$want" ]; then r="ok    "; else r="ÉCHEC "; fail=1; fi
  echo "$r $got  $1 $2 $3 ${4:-}"
}
H=https://localhost
if [ "${T-x}" = "" ]; then
  check 200 127.0.0.2 GET $H/
else
  check 403 127.0.0.2 GET $H/
  check 403 127.0.0.2 GET $H/login
  check 403 127.0.0.2 GET $H/api/health
  check 403 127.0.0.2 POST $H/api/auth/login
  check 403 127.0.0.2 GET $H/api/ingest/trivy
  check 403 127.0.0.2 POST $H/api/ingest/syslog
  check 403 127.0.0.2 POST $H/api/ingest/trivy/x
  check 403 127.0.0.2 GET $H/ "X-Forwarded-For: 127.0.0.3"
  check 502 127.0.0.2 POST $H/api/ingest/trivy
  check 403 127.0.0.2 GET https://127.0.0.1/
  check 403 127.0.0.10 GET $H/
  check 502 127.0.0.10 POST $H/api/ingest/trivy
  check 200 127.0.0.9 GET $H/
  check 200 127.0.0.4 GET $H/
  check 502 127.0.0.4 GET $H/api/health
  check 200 127.0.0.3 GET $H/login
  check 502 127.0.0.3 GET $H/api/health
  check 404 127.0.0.3 GET $H/api/docs
  check 308 127.0.0.3 GET https://127.0.0.1/
  check 200 127.0.0.5 GET $H/
fi
exit $fail
EOF
run_caddy() {
  MSYS_NO_PATHCONV=1 docker run --rm --network none "$@" \
    -v "$(pwd -W 2>/dev/null || pwd)/deploy/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
    -v "$(cd "$tmp" && (pwd -W 2>/dev/null || pwd))/srv:/srv:ro" \
    -v "$(cd "$tmp" && (pwd -W 2>/dev/null || pwd))/essai.sh:/essai.sh:ro" \
    --entrypoint sh "$image" /essai.sh
}
echo "Caddy : image $image"
run_caddy || fail=1
echo "Listes vides (VM pas encore paramétrée) : aucune restriction"
run_caddy -e T= -e W= || fail=1

[ "$fail" = 0 ] && echo "Tout est conforme." || echo "Écarts : voir les lignes ÉCHEC."
exit $fail
