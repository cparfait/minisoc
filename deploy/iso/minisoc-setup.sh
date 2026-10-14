#!/bin/bash
# Console de paramétrage de la VM Mini-SOC (relançable) : pare-feu, SSH, sauvegarde, certificat web, comptes.
# Les réponses précédentes sont proposées par défaut ; rien n'est appliqué avant « Appliquer ».
#   sudo minisoc-setup              menu
#   sudo minisoc-setup --rollback   retour à la configuration précédente (lancé seul si non confirmée)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "À lancer avec sudo."; exit 1; }

FW=/etc/minisoc/firewall.conf
SETUP=/etc/minisoc/setup.conf
SSHD=/etc/ssh/sshd_config.d/10-minisoc.conf
KEYS=/home/adminsoc/.ssh/authorized_keys
BACKUP_KEYS=/var/lib/minisoc-backup/.ssh/authorized_keys
BANNER=/usr/local/share/minisoc/banner.txt
APP=/opt/minisoc
CONFIRM_DELAY=180
PRIVATE="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

apply_all() {
  /usr/local/sbin/minisoc-sshd-config
  sshd -t
  systemctl reload ssh
  systemctl restart minisoc-firewall
}

if [ "${1:-}" = "--rollback" ]; then
  for f in "$FW" "$SSHD" "$BACKUP_KEYS" "$KEYS"; do
    if [ -f "$f.prev" ]; then cp -p "$f.prev" "$f"; fi
  done
  apply_all
  logger -t minisoc-setup "configuration non confirmée : retour à la configuration précédente"
  exit 0
fi

# ---------- Habillage : vert phosphore sur noir ----------
export NEWT_COLORS='
root=green,black
border=green,black
window=green,black
shadow=black,black
title=brightgreen,black
button=black,green
actbutton=black,brightgreen
compactbutton=green,black
checkbox=green,black
actcheckbox=black,green
entry=brightgreen,black
disentry=gray,black
label=green,black
listbox=green,black
sellistbox=brightgreen,black
actlistbox=black,green
actsellistbox=black,brightgreen
textbox=green,black
acttextbox=black,green
emptyscale=,black
fullscale=,green
helpline=black,green
roottext=brightgreen,black
'
G=$'\e[1;32m' D=$'\e[0;32m' Y=$'\e[1;33m' R=$'\e[1;31m' W=$'\e[1;37m' N=$'\e[0m'
HOST=$(hostname -f 2>/dev/null || hostname)
BT="MINI-SOC ▌ $HOST ▌ console de paramétrage"

banner() {
  clear
  printf '%s' "$G"
  [ -f "$BANNER" ] && cat "$BANNER"
  printf '%s\n' "$N"
}
section() { printf '\n%s┌─[ %s ]%s\n' "$G" "$*" "$N"; }
line() { printf '%s│%s %s\n' "$G" "$N" "$*"; }
ok() { printf '%s│ ✔%s %s\n' "$G" "$N" "$*"; }
ko() { printf '%s│ ✘%s %s\n' "$R" "$N" "$*"; }
end() { printf '%s└──────────────────────────────────────────────────────────%s\n' "$G" "$N"; }
pause() { read -r -p "${D}  [Entrée] pour revenir au menu${N} " _; }

# whiptail : la réponse sort sur stderr ; Annuler = code 1
wt() { whiptail --backtitle "$BT" "$@" 3>&1 1>&2 2>&3; }
boxh() {  # hauteur de boîte adaptée au texte (lignes + 7), entre 10 et 26
  local h
  h=$(( $(printf '%b\n' "$1" | wc -l) + 7 ))
  [ "$h" -lt 10 ] && h=10
  [ "$h" -gt 26 ] && h=26
  echo "$h"
}
msg() { wt --title "$1" --msgbox "$2" "$(boxh "$2")" 76; }
confirm() { wt --title "$1" --yesno "$2" "$(boxh "$2")" 76; }

valid_addrs() {  # adresses IPv4 ou plages CIDR, séparées par des espaces
  [ -z "$1" ] || python3 -c 'import ipaddress,sys; [ipaddress.ip_network(a, strict=False) for a in sys.argv[1:]]' $1 2>/dev/null
}
valid_hostports() {
  local hp
  for hp in $1; do
    [[ "$hp" == *:* ]] && valid_addrs "${hp%:*}" && [[ "${hp##*:}" =~ ^[0-9]+$ ]] || return 1
  done
}
norm() { echo "$1" | tr -s ' ,;' ' ' | sed 's/^ //; s/ $//'; }
# input <variable> <titre> <texte> <addrs|hostports|text> [obligatoire]
input() {
  local var=$1 title=$2 text=$3 kind=$4 required=${5:-} answer
  while :; do
    answer=$(wt --title "$title" --inputbox "$text" 14 76 "${!var:-}") || return 1
    answer=$(norm "$answer")
    if [ -n "$required" ] && [ -z "$answer" ]; then msg "$title" "Valeur obligatoire."; continue; fi
    case $kind in
      addrs) valid_addrs "$answer" || { msg "$title" "Adresse ou plage invalide : $answer"; continue; } ;;
      hostports) valid_hostports "$answer" || { msg "$title" "Format attendu : adresse:port (ex. 192.168.10.8:587)"; continue; } ;;
    esac
    printf -v "$var" '%s' "$answer"
    return 0
  done
}
with_port() { local a; for a in $1; do printf '%s:%s ' "$a" "$2"; done; }
envget() { grep "^$1=" "$APP/.env" 2>/dev/null | cut -d= -f2- || true; }
envset() { if grep -q "^$1=" "$APP/.env"; then sed -i "s|^$1=.*|$1=$2|" "$APP/.env"; else echo "$1=$2" >> "$APP/.env"; fi; }

# ---------- État courant ----------
load_state() {
  ADMINS="" WALL="" SYSLOG_TCP="" SYSLOG_TLS="" SYSLOG_UDP="" BACKUP_SERVER="" DNS="" NTP="" LAN_OUT=""
  INTERNET_PORTS="443,8443" LAN_IF=""
  DCS="" SMTP="" XGS_API="" CROWDSEC="" OTHER_OUT=""
  . "$FW"
  [ -f "$SETUP" ] && . "$SETUP"
  INITIAL=0
  grep -q 'MODE INITIAL' "$FW" && INITIAL=1
  for v in ADMINS SYSLOG_TCP SYSLOG_TLS; do [ "${!v}" = "$PRIVATE" ] && printf -v "$v" ''; done
  DCS=${DCS:-$DNS}
  NEW_KEYS="" BACKUP_KEY="" PENDING=0
}
VM_IP=$(envget WEB_BIND)

# ---------- Sections ----------
s_inbound() {
  input ADMINS "Accès entrants ▸ administration" \
    "Postes DSI autorisés à administrer (SSH + interface web).\n2 ou 3 postes, avec réservation DHCP. Adresses ou plages CIDR, séparées par des espaces." addrs 1 || return 0
  input WALL "Accès entrants ▸ écran mural" "Adresse de l'écran mural (interface web seule). Vide si aucun." addrs || return 0
  input SYSLOG_TCP "Accès entrants ▸ syslog 514/TCP" \
    "Sources syslog en clair, 514/TCP :\nSophos XGS, Vectra, Varonis installé sur site." addrs || return 0
  input SYSLOG_TLS "Accès entrants ▸ syslog 6514/TCP chiffré" \
    "Sources syslog chiffré (TLS), 6514/TCP :\ncontrôleurs de domaine et serveurs de fichiers (NXLog)." addrs || return 0
  input SYSLOG_UDP "Accès entrants ▸ syslog 514/UDP" \
    "Sources syslog en UDP : seulement pour un équipement qui ne sait pas envoyer en TCP." addrs || return 0
  PENDING=1
}
s_outbound() {
  input DNS "Accès sortants ▸ DNS" "Serveurs DNS de la VM." addrs 1 || return 0
  input NTP "Accès sortants ▸ heure" "Serveurs de temps (en général les contrôleurs de domaine)." addrs 1 || return 0
  input DCS "Accès sortants ▸ annuaire" "Contrôleurs de domaine joints en LDAPS (636/TCP)." addrs || return 0
  input SMTP "Accès sortants ▸ messagerie" "Relais SMTP (adresse:port, ex. 192.168.10.8:587)." hostports || return 0
  input XGS_API "Accès sortants ▸ Sophos XGS" "Interface d'API du XGS (4444/TCP) : lecture des règles, blocage d'IP." addrs || return 0
  input CROWDSEC "Accès sortants ▸ CrowdSec" "Serveur CrowdSec (adresse:port, ex. 192.168.10.9:8080)." hostports || return 0
  input OTHER_OUT "Accès sortants ▸ autres (LAN)" \
    "Autres destinations du LAN (adresse:port) : Ollama 11434, Cyberwatch 443…" hostports || return 0
  input INTERNET_PORTS "Accès sortants ▸ SaaS / Internet" \
    "Ports Internet autorisés aux connecteurs SaaS (séparés par des virgules).\n443 : Microsoft 365, Varonis, Bitdefender, IA, veille. 8443 : HarfangLab.\nLe tri par nom de domaine se fait sur le XGS (doc 04 § 6.4)." text 1 || return 0
  INTERNET_PORTS=$(echo "$INTERNET_PORTS" | tr ' ' ',')
  PENDING=1
}
s_backup() {
  input BACKUP_SERVER "Sauvegarde ▸ serveur" \
    "Serveur qui vient récupérer les sauvegardes chiffrées (rsync, lecture seule).\nVide pour configurer plus tard." addrs || return 0
  if [ -n "$BACKUP_SERVER" ]; then
    local cur="aucune"
    [ -s "$BACKUP_KEYS" ] && cur="$(awk '{print $(NF-1)}' "$BACKUP_KEYS" | cut -c1-24)…"
    BACKUP_KEY=$(wt --title "Sauvegarde ▸ clé du serveur" --inputbox \
      "Clé publique SSH du serveur de sauvegarde (ssh-ed25519 AAAA…).\nClé actuelle : $cur\nVide pour garder l'actuelle." 14 76 "") || return 0
  fi
  PENDING=1
}
s_keys() {
  local nb k
  while :; do
    nb=$( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0)
    k=$(wt --title "Clés SSH ▸ adminsoc" --inputbox \
      "$nb clé(s) enregistrée(s), $(printf '%s' "$NEW_KEYS" | grep -c . || true) en attente.\nColler une clé publique (ssh-ed25519 AAAA… prenom.nom@poste), vide pour terminer.\n\nDès qu'une clé existe, la connexion par mot de passe est désactivée." 16 76 "") || return 0
    [ -n "$k" ] || return 0
    if [[ "$k" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)\ [A-Za-z0-9+/=]+ ]]; then
      NEW_KEYS+="$k"$'\n'
      PENDING=1
    else
      msg "Clés SSH" "Format non reconnu : clé ignorée."
    fi
  done
}
lan_out() { norm "$(with_port "$DCS" 636) $SMTP $(with_port "$XGS_API" 4444) $CROWDSEC $OTHER_OUT"; }
summary() {  # appelée dans $(…) : ne modifie aucune variable
  cat <<EOF
ENTRANT
  Administration (SSH, web) : $ADMINS
  Écran mural               : ${WALL:-aucun}
  Syslog 514/TCP            : ${SYSLOG_TCP:-aucune}
  Syslog 6514/TCP (TLS)     : ${SYSLOG_TLS:-aucune}
  Syslog 514/UDP            : ${SYSLOG_UDP:-aucune}
  Sauvegarde (SSH, rsync)   : ${BACKUP_SERVER:-non configurée}
SORTANT
  DNS / NTP                 : $DNS / $NTP
  LAN                       : $(lan_out)
  Internet (SaaS)           : ports $INTERNET_PORTS
SSH
  Clés adminsoc             : $( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0) + $(printf '%s' "$NEW_KEYS" | grep -c . || true) nouvelle(s)
EOF
}
s_apply() {
  if [ -z "$ADMINS" ]; then msg "Appliquer" "Renseigner d'abord les postes DSI (Entrants)."; return 0; fi
  LAN_OUT=$(lan_out)
  confirm "Appliquer ▸ récapitulatif" "$(summary)\n\nAppliquer ? Retour arrière automatique dans $((CONFIRM_DELAY / 60)) min sans confirmation." || return 0
  for f in "$FW" "$SSHD" "$BACKUP_KEYS" "$KEYS"; do if [ -f "$f" ]; then cp -p "$f" "$f.prev"; fi; done
  cat > "$FW" <<EOF
# Pare-feu du Mini-SOC : adresses autorisées. Écrit par sudo minisoc-setup le $(date '+%d/%m/%Y %H:%M').
# Après modification à la main : sudo systemctl restart minisoc-firewall
LAN_IF="$LAN_IF"

# --- Entrant ---
ADMINS="$ADMINS"
WALL="$WALL"
SYSLOG_TCP="$SYSLOG_TCP"
SYSLOG_TLS="$SYSLOG_TLS"
SYSLOG_UDP="$SYSLOG_UDP"
BACKUP_SERVER="$BACKUP_SERVER"

# --- Sortant (hôte:port) ---
DNS="$DNS"
NTP="$NTP"
LAN_OUT="$LAN_OUT"
INTERNET_PORTS="$INTERNET_PORTS"
EOF
  chmod 640 "$FW"
  cat > "$SETUP" <<EOF
# Réponses de sudo minisoc-setup, proposées au prochain lancement
DCS="$DCS"
SMTP="$SMTP"
XGS_API="$XGS_API"
CROWDSEC="$CROWDSEC"
OTHER_OUT="$OTHER_OUT"
EOF
  if [ -n "$NEW_KEYS" ]; then
    printf '%s' "$NEW_KEYS" >> "$KEYS"
    chown adminsoc:adminsoc "$KEYS"
    chmod 600 "$KEYS"
  fi
  if [ -n "$BACKUP_KEY" ]; then
    echo "restrict,command=\"/usr/bin/rrsync -ro /var/backups/minisoc\" $BACKUP_KEY" > "$BACKUP_KEYS"
    chown minisoc-backup:minisoc-backup "$BACKUP_KEYS"
    chmod 600 "$BACKUP_KEYS"
  fi
  : > /etc/chrony/sources.d/ad.sources
  for s in $NTP; do echo "server $s iburst" >> /etc/chrony/sources.d/ad.sources; done
  systemctl restart chrony

  banner
  section "APPLICATION"
  systemctl stop minisoc-rollback.timer 2>/dev/null || true
  systemctl reset-failed minisoc-rollback.service minisoc-rollback.timer 2>/dev/null || true
  systemd-run --quiet --on-active="$CONFIRM_DELAY" --unit minisoc-rollback /usr/local/sbin/minisoc-setup --rollback
  ok "filet de sécurité armé : retour arrière dans $((CONFIRM_DELAY / 60)) min"
  if apply_all; then ok "SSH et pare-feu appliqués"; else ko "échec : retour arrière"; /usr/local/sbin/minisoc-setup --rollback; pause; return 0; fi
  line ""
  line "${W}Depuis un poste DSI, ouvrir une NOUVELLE session :${N}"
  line "   ssh adminsoc@$VM_IP        https://$(envget MINISOC_HOSTNAME)"
  end
  local confirmed=""
  read -r -t "$CONFIRM_DELAY" -p "${Y}  ▶ Tout fonctionne ? Taper OUI pour conserver : ${N}" confirmed || true
  systemctl stop minisoc-rollback.timer 2>/dev/null || true
  if [ "$confirmed" = "OUI" ]; then
    printf '%s  ✔ Configuration conservée.%s\n' "$G" "$N"
    sed -i '/pare-feu en mode initial/d; /aucune clé SSH/d' /etc/motd
    load_state
  else
    printf '%s  ✘ Non confirmé : retour à la configuration précédente.%s\n' "$R" "$N"
    /usr/local/sbin/minisoc-setup --rollback
    load_state
  fi
  pause
}
s_cert() {
  local web_name cert_in key_in="" tmp pfx_pass legacy current
  web_name=$(envget MINISOC_HOSTNAME)
  current="autorité interne de Caddy"
  [[ "$(envget MINISOC_TLS)" == /certs* ]] && current="certificat importé, expire le $(openssl x509 -in /etc/minisoc/tls/minisoc.crt -noout -enddate | cut -d= -f2)"
  confirm "Certificat web" "Interface : https://$web_name\nActuellement : $current\n\nImporter un certificat (PKI interne, wildcard *.domaine) ?\nDéposer d'abord le fichier sur la VM :\n  scp certificat.pfx adminsoc@$VM_IP:/tmp/" || return 0
  cert_in=$(wt --title "Certificat web ▸ fichier" --inputbox "Fichier PFX/P12, ou certificat PEM avec sa chaîne :" 10 76 "/tmp/") || return 0
  [ -f "$cert_in" ] || { msg "Certificat web" "Fichier introuvable : $cert_in"; return 0; }
  tmp=$(mktemp -d)
  case "$cert_in" in
    *.pfx|*.p12|*.PFX|*.P12)
      pfx_pass=$(wt --title "Certificat web ▸ mot de passe" --passwordbox "Mot de passe du fichier PFX :" 10 76) || { rm -rf "$tmp"; return 0; }
      for legacy in "" "-legacy"; do
        if PFX_PASS=$pfx_pass openssl pkcs12 $legacy -in "$cert_in" -passin env:PFX_PASS -nokeys -out "$tmp/crt" 2>/dev/null \
          && PFX_PASS=$pfx_pass openssl pkcs12 $legacy -in "$cert_in" -passin env:PFX_PASS -nocerts -nodes -out "$tmp/key" 2>/dev/null; then
          break
        fi
      done
      pfx_pass=""
      ;;
    *)
      key_in=$(wt --title "Certificat web ▸ clé" --inputbox "Clé privée PEM (non chiffrée) :" 10 76 "/tmp/") || { rm -rf "$tmp"; return 0; }
      cp "$cert_in" "$tmp/crt"
      cp "$key_in" "$tmp/key" 2>/dev/null || true
      ;;
  esac
  if [ ! -s "$tmp/crt" ] || [ ! -s "$tmp/key" ]; then
    rm -rf "$tmp"; msg "Certificat web" "Lecture impossible (mot de passe ou fichier ?)."; return 0
  fi
  awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$tmp/crt" > "$tmp/chain"
  if [ "$(openssl x509 -in "$tmp/chain" -noout -pubkey | sha256sum)" != "$(openssl pkey -in "$tmp/key" -pubout | sha256sum)" ]; then
    shred -u "$tmp/key"; rm -rf "$tmp"; msg "Certificat web" "La clé privée ne correspond pas au certificat."; return 0
  fi
  local notes="Noms couverts : $(openssl x509 -in "$tmp/chain" -noout -ext subjectAltName | tail -n +2 | tr -d ' ')\nExpire le : $(openssl x509 -in "$tmp/chain" -noout -enddate | cut -d= -f2)"
  openssl x509 -in "$tmp/chain" -noout -checkend 2592000 >/dev/null || notes+="\n⚠ expire dans moins de 30 jours"
  [ "$(grep -c 'BEGIN CERTIFICATE' "$tmp/chain")" -gt 1 ] || notes+="\n⚠ pas de certificat intermédiaire (chaîne incomplète)"
  while ! openssl x509 -in "$tmp/chain" -noout -checkhost "$web_name" | grep -q 'does match'; do
    web_name=$(wt --title "Certificat web ▸ nom" --inputbox \
      "$notes\n\nLe certificat ne couvre pas $web_name (un wildcard ne couvre qu'un niveau).\nNom de l'interface web couvert par le certificat (enregistrement DNS interne à créer) :" 16 76 "$web_name") \
      || { shred -u "$tmp/key"; rm -rf "$tmp"; return 0; }
  done
  confirm "Certificat web ▸ installation" "$notes\n\nInstaller pour https://$web_name ?\nLa clé d'un wildcard vaut pour tout le domaine : elle reste lisible par root seul." \
    || { shred -u "$tmp/key"; rm -rf "$tmp"; return 0; }
  install -d -m 0700 /etc/minisoc/tls
  install -m 0600 "$tmp/chain" /etc/minisoc/tls/minisoc.crt
  install -m 0600 "$tmp/key" /etc/minisoc/tls/minisoc.key
  shred -u "$tmp/key"; rm -rf "$tmp"
  envset MINISOC_HOSTNAME "$web_name"
  envset MINISOC_PUBLIC_URL "https://$web_name"
  envset MINISOC_TLS_DIR /etc/minisoc/tls
  envset MINISOC_TLS "/certs/minisoc.crt /certs/minisoc.key"
  banner; section "CERTIFICAT"
  (cd "$APP" && docker compose up -d 2>&1 | sed "s/^/${G}│${N} /")
  ok "certificat installé pour $web_name"
  end
  if [[ "$cert_in" == /tmp/* ]] && confirm "Certificat web" "Effacer $cert_in${key_in:+ et $key_in} de /tmp ?"; then
    shred -u "$cert_in" ${key_in:+"$key_in"} 2>/dev/null || true
  fi
  pause
}
s_accounts() {
  local choice
  choice=$(wt --title "Comptes de l'application" --menu "" 14 76 3 \
    "secours" "compte local de secours (mot de passe + double authentification)" \
    "ecran" "jeton de l'écran mural${WALL:+ ($WALL)}" \
    "retour" "") || return 0
  banner
  case $choice in
    secours)
      section "COMPTE DE SECOURS"
      line "Mot de passe et QR code de double authentification : à conserver dans le coffre-fort de la DSI."
      end
      (cd "$APP" && docker compose exec api python -m minisoc.cli create-user --username secours --role admin) || true
      pause ;;
    ecran)
      if [ -z "$WALL" ]; then msg "Écran mural" "Renseigner d'abord l'adresse de l'écran (Entrants)."; return 0; fi
      section "ÉCRAN MURAL"
      (cd "$APP" && docker compose exec api python -m minisoc.cli create-display-token --name "Écran DSI" --ip "${WALL%% *}") || true
      pause ;;
  esac
}
s_files() {
  local out=/home/adminsoc/a-recuperer
  install -d -o adminsoc -g adminsoc -m 0700 "$out"
  cp "$APP/data/syslog-tls/ca.crt" "$out/minisoc-syslog-ca.crt"
  [[ "$(envget MINISOC_TLS)" == /certs* ]] || (cd "$APP" && docker compose cp web:/data/caddy/pki/authorities/local/root.crt "$out/minisoc-web-root.crt") >/dev/null 2>&1 || true
  chown -R adminsoc:adminsoc "$out"
  banner; section "FICHIERS À DÉPLOYER"
  ok "minisoc-syslog-ca.crt   → serveurs NXLog (vérification du Mini-SOC en 6514)"
  [ -f "$out/minisoc-web-root.crt" ] && ok "minisoc-web-root.crt    → GPO : autorités de certification racines de confiance"
  line "Récupération depuis un poste DSI :  ${W}scp -r adminsoc@$VM_IP:a-recuperer .${N}"
  end
  if [ -f "$APP/data/syslog-tls/ca.key" ]; then
    printf '%s  ⚠ L’autorité du syslog (ca.key) ne sert qu’au renouvellement : la garder dans le coffre-fort, pas sur la VM.%s\n' "$Y" "$N"
    printf '    sudo cat %s\n' "$APP/data/syslog-tls/ca.key"
    if confirm "Autorité du syslog" "ca.key est-elle copiée dans le coffre-fort de la DSI ?\nOui = l'effacer de la VM."; then
      shred -u "$APP/data/syslog-tls/ca.key"; ok "ca.key effacée"
    fi
  fi
  pause
}
s_status() {
  banner
  local nb running total banned
  section "ÉTAT DE LA VM"
  line "$HOST  ·  $VM_IP  ·  $(. /etc/os-release; echo "$PRETTY_NAME")  ·  en service depuis $(uptime -p | sed 's/^up //')"
  if [ "$INITIAL" = 1 ]; then ko "pare-feu en MODE INITIAL (plages privées) → Entrants puis Appliquer"
  elif systemctl is-active -q minisoc-firewall; then ok "pare-feu actif : $(echo "$ADMINS" | wc -w) poste(s) d'administration"
  else ko "pare-feu inactif"; fi
  nb=$( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0)
  if [ "$nb" -gt 0 ]; then ok "SSH par clé uniquement ($nb clé(s))"; else ko "SSH par mot de passe (aucune clé)"; fi
  banned=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/ {gsub(/[[:space:]]/,"",$2); print $2}' || true)
  ok "fail2ban : ${banned:-0} adresse(s) bannie(s)"
  aa-status --enabled 2>/dev/null && ok "AppArmor actif" || ko "AppArmor inactif"
  ok "audit : $(auditctl -l 2>/dev/null | grep -c -- '-k ') règles"
  total=$(cd "$APP" && docker compose ps -q 2>/dev/null | wc -l || true)
  running=$(cd "$APP" && docker compose ps --status running -q 2>/dev/null | wc -l || true)
  if [ "$total" -gt 0 ] && [ "$running" = "$total" ]; then ok "Mini-SOC : $running/$total conteneurs en marche"; else ko "Mini-SOC : $running/$total conteneurs en marche"; fi
  [[ "$(envget MINISOC_TLS)" == /certs* ]] && ok "certificat web importé" || line "  certificat web : autorité interne de Caddy"
  if [ -n "$BACKUP_SERVER" ] && [ -s "$BACKUP_KEYS" ]; then ok "sauvegarde récupérée par $BACKUP_SERVER"; else ko "serveur de sauvegarde non configuré"; fi
  local last; last=$(ls -1t /var/backups/minisoc/*.gpg 2>/dev/null | head -1 || true)
  [ -n "$last" ] && ok "dernière sauvegarde : $(date -r "$last" '+%d/%m/%Y %H:%M')" || line "  aucune sauvegarde encore (chaque nuit à 2 h)"
  line "disque données : $(df -h --output=used,size,pcent /var/lib/docker | tail -1 | awk '{print $1" / "$2" ("$3")"}')"
  end
  pause
}

# ---------- Menu ----------
load_state
banner
printf '%s  Initialisation de la console…%s\n' "$D" "$N"
sleep 1
if [ "$INITIAL" = 1 ] && confirm "Bienvenue" "Première configuration : le pare-feu est en mode initial (toutes les plages privées sont acceptées).\n\nLancer l'assistant complet ?\n  accès entrants → accès sortants → sauvegarde → clés SSH → appliquer"; then
  s_inbound; s_outbound; s_backup; s_keys; s_apply
fi
while :; do
  flag=""; [ "$PENDING" = 1 ] && flag="  ● modifications non appliquées"
  choice=$(wt --title "[ MINI-SOC ]" --cancel-button "Quitter" --menu "Hôte $HOST · $VM_IP$flag\nUne lettre ou les flèches, puis Entrée." 22 78 11 \
    "E" "Entrants          postes DSI, écran mural, sources syslog" \
    "S" "Sortants          DNS, NTP, AD, SMTP, XGS, CrowdSec, SaaS" \
    "B" "Sauvegarde        serveur de récupération et sa clé" \
    "K" "Clés SSH          administrateurs (coupe le mot de passe)" \
    "A" "▶ APPLIQUER       pare-feu + SSH, retour arrière auto" \
    "C" "Certificat web    PKI interne ou wildcard" \
    "U" "Comptes           secours, jeton de l'écran mural" \
    "F" "Fichiers          autorités à déployer, ca.key" \
    "T" "Tableau de bord   état de la VM, conteneurs, sauvegardes" \
    "Q" "Quitter") || choice=Q
  case $choice in
    E) s_inbound ;; S) s_outbound ;; B) s_backup ;; K) s_keys ;; A) s_apply ;;
    C) s_cert ;; U) s_accounts ;; F) s_files ;; T) s_status ;;
    Q)
      if [ "$PENDING" = 1 ] && confirm "Quitter" "Des modifications ne sont pas appliquées. Les appliquer maintenant ?"; then
        s_apply; continue
      fi
      clear; printf '%s' "$G"; [ -f "$BANNER" ] && cat "$BANNER"; printf '%s  Fin de session.%s\n' "$N" ""; exit 0 ;;
  esac
done
