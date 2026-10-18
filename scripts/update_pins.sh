#!/usr/bin/env bash
# Relève les dernières versions publiées et fige le build sur elles : empreinte (sha256) des images de base,
# versions et empreintes des dépendances Python (backend/requirements*.lock), version de golang.org/x/net.
# La VM reconstruit ses images à chaque mise à jour : sans ce verrou, elle installerait des versions jamais testées
# (ou une version piégée publiée entre-temps sur PyPI ou sous le même tag Docker).
#
# À lancer sur le poste DSI (Docker requis) depuis le dossier du projet, avant chaque paquet de mise à jour :
#   ./scripts/update_pins.sh && git diff
# puis tests (docker build --target test backend), construction, essai bout en bout, commit.
#
# Restent volontairement hors verrou : les correctifs Debian et Alpine (apt-get upgrade, apk upgrade) appliqués à
# chaque construction, depuis des dépôts signés.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1  # Git Bash : ne pas réécrire les chemins passés à docker

digest() {  # empreinte de l'index multi-architecture
  local d
  d=$(docker buildx imagetools inspect "$1" | awk '/^Digest:/ && !d {d = $2} END {print d}')
  [[ $d =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Empreinte introuvable pour $1" >&2; exit 1; }
  echo "$d"
}

pin() {  # pin <fichier> <image> <avant> <après> : remplace <avant><image>[@sha256:…]<après> par l'empreinte du jour
  local file=$1 ref=$2 before=$3 after=$4 esc d
  esc=$(printf '%s' "$ref" | sed 's/[.]/\\./g')
  d=$(digest "$ref")
  sed -i -E "s|${before}${esc}(@sha256:[0-9a-f]{64})?${after}|${before#^}${ref}@${d}${after}|" "$file"
  echo "  $ref@${d:0:19}…"
}

echo "Images de base :"
for file in backend/Dockerfile frontend/Dockerfile; do
  # FROM <image>:<tag> AS <étape> (les FROM d'une étape précédente n'ont pas de tag)
  for ref in $(sed -nE 's/^FROM ([^ @$]+:[^ @]+)(@sha256:[0-9a-f]{64})? AS .*/\1/p' "$file" | sort -u); do
    pin "$file" "$ref" "^FROM " " AS "
  done
done
for ref in $(sed -nE 's/.*BASE: "([^"@]+)(@sha256:[0-9a-f]{64})?".*/\1/p' docker-compose.yml | sort -u); do
  pin docker-compose.yml "$ref" 'BASE: "' '"'
done

xnet=$(curl -fsS https://proxy.golang.org/golang.org/x/net/@latest | sed -E 's/.*"Version":"([^"]+)".*/\1/')
[[ $xnet =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Version de golang.org/x/net illisible : $xnet" >&2; exit 1; }
sed -i -E "s|^ARG XNET_VERSION=.*|ARG XNET_VERSION=$xnet|" frontend/Dockerfile
echo "golang.org/x/net : $xnet"

# Résolution dans l'image Python du backend (même version, même plateforme que la VM). pip-compile garde les
# empreintes de tous les fichiers publiés pour chaque version. Le verrou d'exécution reprend les versions du verrou
# de test, pour que les tests portent sur exactement les mêmes paquets.
python_image=$(sed -nE 's/^FROM (python:[^ ]+) AS base/\1/p' backend/Dockerfile)
backend=$(cd backend && { pwd -W 2>/dev/null || pwd; })
echo "Dépendances Python (dans $python_image) :"
docker run --rm -v "$backend:/src" -w /src "$python_image" sh -euc '
  pip install -q --root-user-action=ignore pip-tools
  pip-compile -q --upgrade --generate-hashes --strip-extras --extra dev -o requirements-dev.lock pyproject.toml
  sed -nE "s/^([A-Za-z0-9._-]+==[^ ]+).*/\1/p" requirements-dev.lock > /tmp/versions.txt
  pip-compile -q --upgrade --generate-hashes --strip-extras -c /tmp/versions.txt -o requirements.lock pyproject.toml
  echo "  $(grep -c "==" requirements.lock) paquets en exécution, $(grep -c "==" requirements-dev.lock) avec les outils de test"
'
