#!/bin/bash
# Analyse Trivy de la VM Mini-SOC : images Docker de l'application et paquets Debian de la VM. Le rapport est
# déposé dans /var/lib/minisoc/trivy, où le worker le lit (backend/minisoc/trivy.py, page Vulnérabilités).
# Lancé chaque semaine (minisoc-trivy.timer), après chaque mise à jour (minisoc-update) et à la demande
# (Intégrations › Trivy › « Analyser maintenant » : fichier scan-now, minisoc-trivy.path).
# Chaque image est exportée (docker save) puis analysée par un conteneur Trivy jetable : pas de socket Docker,
# système de fichiers en lecture seule, aucun privilège ; sa seule sortie est la base des failles (ghcr.io).
set -euo pipefail
APP=${MINISOC_APP:-/opt/minisoc}
DIR=${TRIVY_DIR:-/var/lib/minisoc/trivy}
CACHE=minisoc-trivy-cache   # volume Docker : base des failles, mise à jour à chaque analyse
exec 9>/run/minisoc-trivy.lock
flock -n 9 || { echo "Analyse Trivy déjà en cours."; exit 0; }
rm -f "$DIR/scan-now"
compose() { docker compose -f "$APP/docker-compose.yml" --profile outils "$@"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
started=$(now)
status() {  # status <état> <message> [cibles] [erreurs…]
  local state=$1 message=$2 targets=${3:-0}; shift 3 || shift $#
  python3 - "$DIR/status.json" "$state" "$message" "$targets" "$started" "$(now)" "${TRIVY_VERSION:-}" "$@" <<'EOF'
import json, os, sys
path, state, message, targets, started, at, version, *errors = sys.argv[1:]
data = {"state": state, "message": message, "targets": int(targets), "started": started, "trivy": version,
        "errors": errors[:20], ("updated" if state == "running" else "finished"): at}
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False)
os.replace(path + ".tmp", path)
EOF
}

# Dossier d'échange : propriété du compte du worker (il efface le rapport lu et dépose les demandes d'analyse)
install -d -m 0750 "$DIR"
uid=$(docker run --rm --entrypoint id "$(compose config --format json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["services"]["worker"]["image"])')" -u 2>/dev/null || echo 0)
chown "$uid:0" "$DIR"
TRIVY_IMG=$(compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["trivy"]["image"])')
TRIVY_VERSION=${TRIVY_IMG##*:}
trap 'status error "analyse interrompue (sudo journalctl -u minisoc-trivy)" 0' ERR
status running "préparation" 0
docker image inspect "$TRIVY_IMG" >/dev/null 2>&1 || compose build -q trivy

# Disque de données (racine de Docker) : exports de plusieurs centaines de Mo
WORK=${TRIVY_WORK:-"$(docker info -f '{{.DockerRootDir}}')/minisoc-trivy"}
rm -rf "$WORK"
install -d -m 0700 "$WORK"
trap 'rm -rf "$WORK"' EXIT
trivy() {
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 \
    -v "$CACHE:/root/.cache" -v "$WORK:/work:ro" "$@"
}
status running "mise à jour de la base des failles" 0
trivy "$TRIVY_IMG" image --quiet --download-db-only

# Images de l'application présentes sur la VM (dont celle de Trivy), puis paquets de la VM
mapfile -t images < <(compose config --images | sort -u)
errors=() n=0 i=0
for img in "${images[@]}"; do
  i=$((i + 1))
  docker image inspect "$img" >/dev/null 2>&1 || continue
  status running "analyse de $img ($i/${#images[@]})" "$n"
  tar="$WORK/image-$i.tar"
  if docker save -o "$tar" "$img" && trivy "$TRIVY_IMG" image --quiet --skip-db-update --scanners vuln \
      --format json --input "/work/image-$i.tar" > "$WORK/image-$i.json.part"; then
    printf '%s\n' "$img" > "$WORK/image-$i.name"
    mv "$WORK/image-$i.json.part" "$WORK/image-$i.json"
    n=$((n + 1))
  else
    errors+=("$img : analyse en échec")
  fi
  rm -f "$tar" "$WORK/image-$i.json.part"
done
status running "analyse des paquets de la VM" "$n"
if docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    -v "$CACHE:/root/.cache" -v /var/lib/dpkg:/host/var/lib/dpkg:ro \
    -v /usr/lib/os-release:/host/etc/os-release:ro -v /usr/lib/os-release:/host/usr/lib/os-release:ro \
    "$TRIVY_IMG" rootfs --quiet --skip-db-update --scanners vuln --pkg-types os --format json /host \
    > "$WORK/vm.json.part"; then
  echo "VM $(hostname -s) (Debian)" > "$WORK/vm.name"
  mv "$WORK/vm.json.part" "$WORK/vm.json"
  n=$((n + 1))
else
  errors+=("paquets de la VM : analyse en échec")
fi

# Rapport pour le worker : écrit à côté puis renommé (jamais lu à moitié écrit)
python3 - "$WORK" "$DIR/report.json" "$(hostname -f 2>/dev/null || hostname)" "$(now)" <<'EOF'
import glob, json, os, sys
work, out, host, at = sys.argv[1:]
reports = []
for path in sorted(glob.glob(os.path.join(work, "*.json"))):
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    with open(path[:-5] + ".name", encoding="utf-8") as f:
        report["ArtifactName"] = f.read().strip()  # nom de l'image au lieu du fichier exporté
    reports.append(report)
with open(out + ".tmp", "w", encoding="utf-8") as f:
    json.dump({"agent": "minisoc-trivy/1", "host": host, "scanned_at": at, "reports": reports}, f)
os.replace(out + ".tmp", out)
EOF
chown "$uid:0" "$DIR/report.json"
chmod 0640 "$DIR/report.json"
trap - ERR
if [ "$n" = 0 ]; then
  status error "aucune cible analysée" 0 "${errors[@]}"
  exit 1
fi
status ok "$n cible(s) analysée(s)" "$n" "${errors[@]}"
echo "Analyse Trivy terminée : $n cible(s), rapport déposé dans $DIR (lu par le worker dans les 15 secondes)."
[ ${#errors[@]} = 0 ] || printf 'Échec : %s\n' "${errors[@]}"
