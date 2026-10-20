#!/bin/bash
# Console de paramétrage de la VM Mini-SOC (relançable) : pare-feu, SSH, sauvegarde, certificat web, comptes.
# Les réponses précédentes sont proposées par défaut ; rien n'est appliqué avant « Appliquer ».
#   sudo minisoc-setup              menu
#   sudo minisoc-setup --rollback   retour à la configuration précédente (lancé seul si non confirmée)
#   sudo minisoc-setup --relire     firewall.conf modifié à la main : SSH, pare-feu et interface web réappliqués
#   sudo minisoc-setup --acces-web  listes du pare-feu recopiées pour l'interface web seule (lancé par minisoc-update)
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

# Le pare-feu ouvre le 443 aux serveurs Trivy comme aux postes DSI ; Caddy (deploy/caddy/Caddyfile) ne laisse aux
# serveurs Trivy que l'envoi de leurs rapports (POST /api/ingest/trivy), sauf adresse aussi déclarée en
# administration ou en écran mural. Il reçoit les listes par .env : MINISOC_TRIVY_IPS = TRIVY, MINISOC_WEB_IPS =
# ADMINS et WALL. Renvoie 1 si .env n'a pas changé.
web_access_env() {
  local env="$APP/.env" v val changed=1
  [ -f "$env" ] && [ -f "$FW" ] || return 1
  for v in MINISOC_TRIVY_IPS MINISOC_WEB_IPS; do
    if [ "$v" = MINISOC_TRIVY_IPS ]; then val=$(. "$FW"; echo ${TRIVY:-}); else val=$(. "$FW"; echo ${ADMINS:-} ${WALL:-}); fi
    [ "$(grep "^$v=" "$env" || true)" = "$v=$val" ] && continue
    if grep -q "^$v=" "$env"; then sed -i "s|^$v=.*|$v=$val|" "$env"; else echo "$v=$val" >> "$env"; fi
    changed=0
  done
  return $changed
}
# Puis conteneur web recréé s'il est en service : Caddy ne lit ses variables qu'au démarrage
web_access() {
  web_access_env || return 0
  [ -n "$(cd "$APP" && docker compose ps -q --status running web 2>/dev/null)" ] || return 0
  (cd "$APP" && docker compose up -d --no-deps web)
}

if [ "${1:-}" = "--rollback" ]; then
  for f in "$FW" "$SSHD" "$BACKUP_KEYS" "$KEYS" /etc/minisoc/firewall-notes.conf; do
    if [ -f "$f.prev" ]; then cp -p "$f.prev" "$f"; fi
  done
  apply_all
  web_access || logger -t minisoc-setup "retour arrière : conteneur web non recréé (accès des serveurs Trivy)"
  logger -t minisoc-setup "configuration non confirmée : retour à la configuration précédente"
  exit 0
fi
if [ "${1:-}" = "--acces-web" ]; then
  web_access
  exit 0
fi
if [ "${1:-}" = "--relire" ]; then
  apply_all
  web_access
  echo "SSH, pare-feu et interface web réappliqués depuis $FW."
  exit 0
fi

# ---------- Habillage : dialog, fond noir, texte gris, accent vert ----------
# dialog plutôt que whiptail : Échap immédiat, formulaires à plusieurs champs, couleurs réglables.
if ! command -v dialog >/dev/null 2>&1; then
  echo "Installation de dialog (console de paramétrage)…"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q dialog >/dev/null 2>&1 \
    || { echo "dialog est nécessaire : sudo apt install dialog"; exit 1; }
fi
export ESCDELAY=25   # Échap pris en compte tout de suite (sinon une seconde d'attente)
export NCURSES_NO_UTF8_ACS=1   # cadres en caractères Unicode : PuTTY (UTF-8) affiche sinon « lqqqk » et « x »
DIALOGRC=$(mktemp)
export DIALOGRC
trap 'rm -f "$DIALOGRC"' EXIT
cat > "$DIALOGRC" <<'EOF'
use_shadow = OFF
use_colors = ON
screen_color = (WHITE,BLACK,OFF)
shadow_color = (BLACK,BLACK,OFF)
dialog_color = (WHITE,BLACK,OFF)
title_color = (GREEN,BLACK,ON)
border_color = (WHITE,BLACK,OFF)
border2_color = (WHITE,BLACK,OFF)
button_active_color = (BLACK,GREEN,OFF)
button_inactive_color = (WHITE,BLACK,OFF)
button_key_active_color = (BLACK,GREEN,OFF)
button_key_inactive_color = (GREEN,BLACK,ON)
button_label_active_color = (BLACK,GREEN,OFF)
button_label_inactive_color = (WHITE,BLACK,ON)
inputbox_color = (WHITE,BLACK,ON)
inputbox_border_color = (WHITE,BLACK,OFF)
inputbox_border2_color = (WHITE,BLACK,OFF)
searchbox_color = (WHITE,BLACK,OFF)
searchbox_title_color = (GREEN,BLACK,ON)
searchbox_border_color = (WHITE,BLACK,OFF)
searchbox_border2_color = (WHITE,BLACK,OFF)
position_indicator_color = (GREEN,BLACK,OFF)
menubox_color = (WHITE,BLACK,OFF)
menubox_border_color = (BLACK,BLACK,ON)
menubox_border2_color = (BLACK,BLACK,ON)
item_color = (WHITE,BLACK,OFF)
item_selected_color = (BLACK,GREEN,OFF)
tag_color = (WHITE,BLACK,ON)
tag_selected_color = (BLACK,GREEN,OFF)
tag_key_color = (GREEN,BLACK,ON)
tag_key_selected_color = (BLACK,GREEN,OFF)
check_color = (WHITE,BLACK,OFF)
check_selected_color = (BLACK,GREEN,OFF)
uarrow_color = (GREEN,BLACK,ON)
darrow_color = (GREEN,BLACK,ON)
itemhelp_color = (WHITE,BLACK,OFF)
form_active_text_color = (BLACK,GREEN,OFF)
form_text_color = (BLACK,WHITE,OFF)
form_item_readonly_color = (WHITE,BLACK,OFF)
gauge_color = (GREEN,BLACK,OFF)
bindkey formfield TAB FORM_NEXT
bindkey formfield BTAB FORM_PREV
bindkey formbox TAB FORM_NEXT
bindkey formbox BTAB FORM_PREV
EOF
G=$'\e[1;32m' C=$'\e[1;32m' D=$'\e[0;37m' Y=$'\e[1;33m' R=$'\e[1;31m' W=$'\e[1;37m' N=$'\e[0m'
HOST=$(hostname -f 2>/dev/null || hostname)
BT="MINI-SOC ▌ $HOST ▌ console de paramétrage"

banner() {
  clear
  printf '%s' "$C"
  [ -f "$BANNER" ] && cat "$BANNER"
  printf '%s\n' "$N"
}
section() { printf '\n%s┌─[ %s ]%s\n' "$C" "$*" "$N"; }
line() { printf '%s│%s %s\n' "$C" "$N" "$*"; }
ok() { printf '%s│ [OK]%s %s\n' "$G" "$N" "$*"; }
ko() { printf '%s│ [!!]%s %s\n' "$R" "$N" "$*"; }
end() { printf '%s└──────────────────────────────────────────────────────────%s\n' "$C" "$N"; }
pause() { read -r -p "${D}  [Entrée] pour revenir au menu${N} " _; }

# dialog : la réponse sort sur stderr ; Annuler = code 1, Échap = 255 (traités pareil : on revient en arrière)
wt() {
  dialog --backtitle "$BT" --colors --ok-label "Valider" --cancel-label "Retour" --yes-label "Oui" \
    --no-label "Non" --exit-label "Fermer" "$@" 3>&1 1>&2 2>&3
}
boxh() {  # hauteur de boîte adaptée au texte (lignes + 7), entre 10 et 26
  local h
  h=$(( $(printf '%b\n' "$1" | wc -l) + 7 ))
  [ "$h" -lt 10 ] && h=10
  [ "$h" -gt 26 ] && h=26
  echo "$h"
}
msg() { wt --title "$1" --ok-label "OK" --msgbox "$2" "$(boxh "$2")" 76 || true; }
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

# ---------- Listes d'adresses, chacune avec sa description ----------
# Descriptions pour la DSI (le pare-feu ne les lit pas) : une ligne LISTE|adresse|description
NOTES_FILE=/etc/minisoc/firewall-notes.conf
NOTE_LISTS="ADMINS WALL TRIVY SYSLOG_TCP SYSLOG_TLS SYSLOG_UDP DNS NTP DCS SMTP XGS_API CROWDSEC OTHER_OUT"
declare -A NOTES=()
load_notes() {
  NOTES=()
  [ -f "$NOTES_FILE" ] || return 0
  local v a d
  while IFS='|' read -r v a d; do
    [ -n "$v" ] && [ "${v:0:1}" != "#" ] && [ -n "$a" ] || continue
    NOTES["$v|$a"]=$d
  done < "$NOTES_FILE"
}
note() { printf '%s' "${NOTES["$1|$2"]:-}"; }
clean_note() { printf '%s' "$1" | tr -d '|"`$\\' | tr -s '\t\r\n' '   ' | sed 's/^ *//; s/ *$//' | cut -c1-60; }
described() {  # « 192.168.3.1 (PC DSI) 192.168.2.253 (Sophos XGS) »
  local a d out=""
  for a in ${!1:-}; do d=$(note "$1" "$a"); out+="$a${d:+ ($d)} "; done
  printf '%s' "${out% }"
}
count() { local n=0 a; for a in ${!1:-}; do n=$((n + 1)); done; printf '%2d' "$n"; }
save_notes() {
  local v a d
  {
    echo "# Descriptions des adresses du pare-feu, écrites par sudo minisoc-setup : LISTE|adresse|description"
    for v in $NOTE_LISTS; do
      for a in ${!v:-}; do d=$(note "$v" "$a"); [ -z "$d" ] || printf '%s|%s|%s\n' "$v" "$a" "$d"; done
    done
  } > "$NOTES_FILE"
  chmod 640 "$NOTES_FILE"
}
# menu_size <texte> <nombre d'entrées> : « hauteur largeur lignes » d'un menu, liste à la taille de son contenu
menu_size() {
  local rows=$2 text_lines
  [ "$rows" -lt 3 ] && rows=3
  [ "$rows" -gt 12 ] && rows=12
  text_lines=$(printf '%b\n' "$1" | wc -l)
  echo "$(( rows + text_lines + 9 )) 78 $rows"
}
# Modifications faites dans un menu : rien n'est actif avant « Appliquer », on le propose en sortant
offer_apply() {
  [ "$PENDING" = 1 ] || return 0
  confirm "Appliquer ?" "Les modifications sont enregistrées dans la console mais \\Zbpas encore actives\\ZB sur le pare-feu.\n\nLes appliquer maintenant ?\n(Non : elles restent en attente, menu « > APPLIQUER » plus tard.)" \
    && s_apply
  return 0
}
# form_entry <titre> <texte> <adresse> <description> : les deux champs sur un même écran → FORM_ADDR, FORM_DESC
form_entry() {
  local out
  out=$(wt --title "$1" --ok-label "Enregistrer" --cancel-label "Annuler" \
    --form "$2\n\\ZbTab\\ZB : champ suivant   \\ZbEntrée\\ZB : enregistrer   \\ZbÉchap\\ZB : annuler" 11 78 2 \
    "Adresse     " 1 2 "$3" 1 16 32 43 \
    "Description " 2 2 "$4" 2 16 58 60) || return 1
  FORM_ADDR=$(norm "$(sed -n 1p <<< "$out")")
  FORM_DESC=$(clean_note "$(sed -n 2p <<< "$out")")
}
# check_entry <titre> <addrs|hostports> <variable> <adresse> <ancienne adresse>
check_entry() {
  local title=$1 kind=$2 var=$3 a=$4 old=$5
  [ -n "$a" ] || { msg "$title" "L'adresse est obligatoire."; return 1; }
  [[ "$a" != *" "* ]] || { msg "$title" "Une seule adresse par ligne : $a"; return 1; }
  case $kind in
    addrs) valid_addrs "$a" || { msg "$title" "Adresse ou plage invalide : $a"; return 1; } ;;
    hostports) valid_hostports "$a" || { msg "$title" "Format attendu : adresse:port (ex. 192.168.10.8:587)"; return 1; } ;;
  esac
  if [ "$a" != "$old" ] && [[ " ${!var} " == *" $a "* ]]; then msg "$title" "$a est déjà dans la liste."; return 1; fi
}
# edit_list <variable> <titre> <texte> <addrs|hostports> [obligatoire] : ajouter, modifier, retirer
edit_list() {
  local var=$1 title=$2 text=$3 kind=$4 required=${5:-} choice a d old action x rest example
  local -a items
  example="IPv4 ou plage CIDR, ex. 192.168.3.1"
  [ "$kind" = hostports ] && example="adresse:port, ex. 192.168.10.8:587"
  while :; do
    items=()
    for a in ${!var}; do d=$(note "$var" "$a"); items+=("$a" "${d:-· sans description ·}"); done
    items+=("+" "Ajouter une adresse")
    if ! choice=$(wt --title "$title" --ok-label "Choisir" --cancel-label "Terminé" --menu \
      "$text\n\n\\Zb$(count "$var") adresse(s)\\ZB   Entrée : modifier ou retirer   Échap : terminer" \
      $(menu_size "$text" $(( ${#items[@]} / 2 ))) "${items[@]}"); then
      if [ -n "$required" ] && [ -z "${!var}" ]; then msg "$title" "Au moins une adresse est obligatoire."; continue; fi
      return 0
    fi
    if [ "$choice" = "+" ]; then
      a="" d=""
      while :; do
        form_entry "$title > ajouter" "Nouvelle adresse ($example).\nLa description aide à reconnaître le poste ou l'équipement." \
          "$a" "$d" || continue 2
        a=$FORM_ADDR d=$FORM_DESC
        check_entry "$title" "$kind" "$var" "$a" "" && break
      done
      printf -v "$var" '%s' "$(norm "${!var} $a")"
      NOTES["$var|$a"]=$d
      PENDING=1
      continue
    fi
    old=$choice
    action=$(wt --title "$title > $old" --ok-label "Choisir" --menu "\\Zb$old\\ZB  $(note "$var" "$old")" 11 76 2 \
      "M" "Modifier l'adresse ou la description" "R" "Retirer cette adresse") || continue
    case $action in
      M)
        a=$old d=$(note "$var" "$old")
        while :; do
          form_entry "$title > modifier" "Adresse ($example) et description." "$a" "$d" || continue 2
          a=$FORM_ADDR d=$FORM_DESC
          check_entry "$title" "$kind" "$var" "$a" "$old" && break
        done
        rest=""
        for x in ${!var}; do if [ "$x" = "$old" ]; then rest+="$a "; else rest+="$x "; fi; done
        printf -v "$var" '%s' "$(norm "$rest")"
        NOTES["$var|$old"]=""
        NOTES["$var|$a"]=$d
        PENDING=1
        ;;
      R)
        if [ -n "$required" ] && [ "$(count "$var")" -le 1 ]; then
          msg "$title" "Dernière adresse de la liste : ajouter d'abord la nouvelle, puis retirer celle-ci."; continue
        fi
        confirm "$title" "Retirer $old ($(note "$var" "$old")) de la liste ?" || continue
        rest=""
        for x in ${!var}; do [ "$x" = "$old" ] || rest+="$x "; done
        printf -v "$var" '%s' "$(norm "$rest")"
        NOTES["$var|$old"]=""
        PENDING=1
        ;;
    esac
  done
}

# ---------- État courant ----------
load_state() {
  ADMINS="" WALL="" TRIVY="" SYSLOG_TCP="" SYSLOG_TLS="" SYSLOG_UDP="" BACKUP_SERVER="" DNS="" NTP="" LAN_OUT=""
  INTERNET_PORTS="443,8443" LAN_IF="" SSH_PORT="22"
  DCS="" SMTP="" XGS_API="" CROWDSEC="" OTHER_OUT=""
  . "$FW"
  [ -f "$SETUP" ] && . "$SETUP"
  INITIAL=0
  grep -q 'MODE INITIAL' "$FW" && INITIAL=1
  for v in ADMINS SYSLOG_TCP SYSLOG_TLS; do [ "${!v}" = "$PRIVATE" ] && printf -v "$v" ''; done
  DCS=${DCS:-$DNS}
  NEW_KEYS="" BACKUP_KEY="" PENDING=0
  load_notes
}
VM_IP=$(envget WEB_BIND)

# ---------- Sections ----------
s_inbound() {
  local c
  while :; do
    c=$(wt --title "Accès entrants" --cancel-label "Retour" --menu \
      "Adresses autorisées à joindre la VM, chacune avec sa description.\nEntrée : ouvrir une liste   Échap : revenir au menu" 14 78 6 \
      "1" "Administration   $(count ADMINS) adr.  SSH, web, ping (postes DSI)" \
      "2" "Écran mural      $(count WALL) adr.  interface web seule" \
      "3" "Syslog 514/TCP   $(count SYSLOG_TCP) adr.  pare-feu, Vectra, Varonis sur site" \
      "4" "Syslog 6514/TLS  $(count SYSLOG_TLS) adr.  NXLog (DC, serveurs de fichiers)" \
      "5" "Syslog 514/UDP   $(count SYSLOG_UDP) adr.  équipement sans TCP" \
      "6" "Serveurs Trivy   $(count TRIVY) adr.  envoi des rapports seul (443)") || return 0
    case $c in
      1) edit_list ADMINS "Accès entrants > administration" \
           "Postes DSI autorisés à administrer (SSH, interface web, ping).\nLes autres adresses n'ont aucune réponse, pas même au ping.\n2 ou 3 postes, avec réservation DHCP." addrs 1 ;;
      2) edit_list WALL "Accès entrants > écran mural" "Écran mural (interface web seule)." addrs ;;
      3) edit_list SYSLOG_TCP "Accès entrants > syslog 514/TCP" \
           "Sources syslog en clair, 514/TCP : pare-feu (Sophos XGS ou autre), Vectra, Varonis sur site." addrs ;;
      4) edit_list SYSLOG_TLS "Accès entrants > syslog 6514/TCP chiffré" \
           "Sources syslog chiffré (TLS), 6514/TCP : contrôleurs de domaine et serveurs de fichiers (NXLog)." addrs ;;
      5) edit_list SYSLOG_UDP "Accès entrants > syslog 514/UDP" \
           "Sources syslog en UDP : seulement pour un équipement qui ne sait pas envoyer en TCP." addrs ;;
      6) edit_list TRIVY "Accès entrants > serveurs Trivy" \
           "Serveurs équipés de l'agent Trivy du Mini-SOC : 443/TCP, limité à l'envoi de leurs rapports\n(interface et reste de l'API refusés, sauf adresse aussi en administration ou écran mural).\nJeton propre à chaque serveur, créé dans Intégrations › Trivy." addrs ;;
    esac
  done
}
s_outbound() {
  local c
  while :; do
    c=$(wt --title "Accès sortants" --cancel-label "Retour" --menu \
      "Destinations que la VM et les conteneurs peuvent joindre, chacune avec sa description.\nEntrée : ouvrir une liste   Échap : revenir au menu" 16 78 8 \
      "1" "DNS              $(count DNS) adr." \
      "2" "Heure (NTP)      $(count NTP) adr.  en général les contrôleurs de domaine" \
      "3" "Annuaire LDAPS   $(count DCS) adr.  contrôleurs de domaine, 636/TCP" \
      "4" "Messagerie       $(count SMTP) adr.  relais SMTP (adresse:port)" \
      "5" "Sophos XGS API   $(count XGS_API) adr.  4444/TCP : règles, blocage d'IP" \
      "6" "CrowdSec         $(count CROWDSEC) adr.  serveur (adresse:port)" \
      "7" "Autres (LAN)     $(count OTHER_OUT) adr.  Ollama, Cyberwatch, Vectra, WordPress…" \
      "8" "SaaS / Internet  ports $INTERNET_PORTS") || return 0
    case $c in
      1) edit_list DNS "Accès sortants > DNS" "Serveurs DNS de la VM." addrs 1 ;;
      2) edit_list NTP "Accès sortants > heure" "Serveurs de temps (en général les contrôleurs de domaine)." addrs 1 ;;
      3) edit_list DCS "Accès sortants > annuaire" "Contrôleurs de domaine joints en LDAPS (636/TCP)." addrs ;;
      4) edit_list SMTP "Accès sortants > messagerie" "Relais SMTP (adresse:port, ex. 192.168.10.8:587)." hostports ;;
      5) edit_list XGS_API "Accès sortants > Sophos XGS" \
           "Interface d'API du XGS (4444/TCP) : lecture des règles, blocage d'IP." addrs ;;
      6) edit_list CROWDSEC "Accès sortants > CrowdSec" "Serveur CrowdSec (adresse:port, ex. 192.168.10.9:8080)." hostports ;;
      7) edit_list OTHER_OUT "Accès sortants > autres (LAN)" \
           "Autres destinations du LAN (adresse:port) : Ollama 11434, Cyberwatch 443, Brain Vectra 443…" hostports ;;
      8)
        input INTERNET_PORTS "Accès sortants > SaaS / Internet" \
          "Ports Internet autorisés aux connecteurs SaaS (séparés par des virgules).\n443 : Microsoft 365, Varonis, Bitdefender, IA, veille. 8443 : HarfangLab.\nLe tri par nom de domaine se fait sur le XGS (doc 04 § 6.4)." text 1 || continue
        INTERNET_PORTS=$(echo "$INTERNET_PORTS" | tr ' ' ',')
        PENDING=1
        ;;
    esac
  done
}
s_backup() {
  input BACKUP_SERVER "Sauvegarde > serveur" \
    "Serveur qui vient récupérer les sauvegardes chiffrées (rsync, lecture seule).\nVide pour configurer plus tard." addrs || return 0
  if [ -n "$BACKUP_SERVER" ]; then
    local cur="aucune"
    [ -s "$BACKUP_KEYS" ] && cur="$(awk '{print $(NF-1)}' "$BACKUP_KEYS" | cut -c1-24)…"
    BACKUP_KEY=$(wt --title "Sauvegarde > clé du serveur" --inputbox \
      "Clé publique SSH du serveur de sauvegarde (ssh-ed25519 AAAA…).\nClé actuelle : $cur\nVide pour garder l'actuelle." 14 76 "") || return 0
  fi
  PENDING=1
}
s_keys() {
  local nb k
  while :; do
    nb=$( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0)
    k=$(wt --title "Clés SSH > adminsoc" --inputbox \
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
s_ssh_port() {
  local p used
  while :; do
    p=$(wt --title "SSH > port" --inputbox \
      "Port d'écoute du serveur SSH (22 par défaut).\nUn autre port limite le bruit des scans, sans remplacer le pare-feu ni les clés.\nAprès « Appliquer » : ssh -p <port> adminsoc@$VM_IP" 12 76 "$SSH_PORT") || return 0
    p=$(norm "$p")
    if ! [[ "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then msg "SSH > port" "Port invalide : $p (1 à 65535)."; continue; fi
    case $p in 80|443|514|6514) msg "SSH > port" "Le port $p est réservé au Mini-SOC (web, syslog)."; continue ;; esac
    used=$(ss -Hltnp "sport = :$p" 2>/dev/null | grep -v '"sshd"' || true)
    if [ -n "$used" ]; then msg "SSH > port" "Le port $p est déjà utilisé :\n$used"; continue; fi
    [ "$p" = "$SSH_PORT" ] || PENDING=1
    SSH_PORT=$p
    return 0
  done
}
ssh_cmd() { if [ "$SSH_PORT" = 22 ]; then echo "ssh adminsoc@$VM_IP"; else echo "ssh -p $SSH_PORT adminsoc@$VM_IP"; fi; }
lan_out() { norm "$(with_port "$DCS" 636) $SMTP $(with_port "$XGS_API" 4444) $CROWDSEC $OTHER_OUT"; }
summary() {  # appelée dans $(…) : ne modifie aucune variable
  cat <<EOF
ENTRANT
  Administration (SSH, web) : $(described ADMINS)
  Écran mural               : $(w=$(described WALL); echo "${w:-aucun}")
  Serveurs Trivy (envoi)    : $(w=$(described TRIVY); echo "${w:-aucun}")
  Syslog 514/TCP            : $(w=$(described SYSLOG_TCP); echo "${w:-aucune}")
  Syslog 6514/TCP (TLS)     : $(w=$(described SYSLOG_TLS); echo "${w:-aucune}")
  Syslog 514/UDP            : $(w=$(described SYSLOG_UDP); echo "${w:-aucune}")
  Sauvegarde (SSH, rsync)   : ${BACKUP_SERVER:-non configurée}
SORTANT
  DNS / NTP                 : $DNS / $NTP
  LAN                       : $(lan_out)
  Internet (SaaS)           : ports $INTERNET_PORTS
SSH
  Port                      : $SSH_PORT
  Clés adminsoc             : $( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0) + $(printf '%s' "$NEW_KEYS" | grep -c . || true) nouvelle(s)
EOF
}
s_apply() {
  if [ -z "$ADMINS" ]; then msg "Appliquer" "Renseigner d'abord les postes DSI (Entrants)."; return 0; fi
  LAN_OUT=$(lan_out)
  confirm "Appliquer > récapitulatif" "$(summary)\n\nAppliquer ? Retour arrière automatique dans $((CONFIRM_DELAY / 60)) min sans confirmation." || return 0
  for f in "$FW" "$SSHD" "$BACKUP_KEYS" "$KEYS" "$NOTES_FILE"; do if [ -f "$f" ]; then cp -p "$f" "$f.prev"; fi; done
  cat > "$FW" <<EOF
# Pare-feu du Mini-SOC : adresses autorisées. Écrit par sudo minisoc-setup le $(date '+%d/%m/%Y %H:%M').
# Après modification à la main : sudo minisoc-setup --relire (SSH, pare-feu, interface web)
# Description de chaque adresse : /etc/minisoc/firewall-notes.conf
LAN_IF="$LAN_IF"

# --- Entrant ---
ADMINS="$ADMINS"
WALL="$WALL"
TRIVY="$TRIVY"
SYSLOG_TCP="$SYSLOG_TCP"
SYSLOG_TLS="$SYSLOG_TLS"
SYSLOG_UDP="$SYSLOG_UDP"
BACKUP_SERVER="$BACKUP_SERVER"
SSH_PORT="$SSH_PORT"

# --- Sortant (hôte:port) ---
DNS="$DNS"
NTP="$NTP"
LAN_OUT="$LAN_OUT"
INTERNET_PORTS="$INTERNET_PORTS"
EOF
  chmod 640 "$FW"
  save_notes
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
  local trivy_msg="aucun serveur Trivy"
  [ -z "$TRIVY" ] || trivy_msg="serveurs Trivy limités à l'envoi de leurs rapports"
  if web_access 2>&1 | sed "s/^/${G}│${N} /"; then ok "interface web : $trivy_msg"
  else ko "interface web non redémarrée : sudo minisoc-setup --acces-web"; fi
  line ""
  line "${W}Depuis un poste DSI, ouvrir une NOUVELLE session :${N}"
  line "   $(ssh_cmd)        https://$(envget MINISOC_HOSTNAME)"
  end
  local confirmed=""
  read -r -t "$CONFIRM_DELAY" -p "${Y}  > Tout fonctionne ? Taper OUI pour conserver : ${N}" confirmed || true
  systemctl stop minisoc-rollback.timer 2>/dev/null || true
  if [ "$confirmed" = "OUI" ]; then
    printf '%s  [OK] Configuration conservée.%s\n' "$G" "$N"
    load_state
  else
    printf '%s  [!!] Non confirmé : retour à la configuration précédente.%s\n' "$R" "$N"
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
  cert_in=$(wt --title "Certificat web > fichier" --inputbox "Fichier PFX/P12, ou certificat PEM avec sa chaîne :" 10 76 "/tmp/") || return 0
  [ -f "$cert_in" ] || { msg "Certificat web" "Fichier introuvable : $cert_in"; return 0; }
  tmp=$(mktemp -d)
  case "$cert_in" in
    *.pfx|*.p12|*.PFX|*.P12)
      pfx_pass=$(wt --title "Certificat web > mot de passe" --insecure --passwordbox "Mot de passe du fichier PFX :" 10 76) || { rm -rf "$tmp"; return 0; }
      for legacy in "" "-legacy"; do
        if PFX_PASS=$pfx_pass openssl pkcs12 $legacy -in "$cert_in" -passin env:PFX_PASS -nokeys -out "$tmp/crt" 2>/dev/null \
          && PFX_PASS=$pfx_pass openssl pkcs12 $legacy -in "$cert_in" -passin env:PFX_PASS -nocerts -nodes -out "$tmp/key" 2>/dev/null; then
          break
        fi
      done
      pfx_pass=""
      ;;
    *)
      key_in=$(wt --title "Certificat web > clé" --inputbox "Clé privée PEM (non chiffrée) :" 10 76 "/tmp/") || { rm -rf "$tmp"; return 0; }
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
  openssl x509 -in "$tmp/chain" -noout -checkend 2592000 >/dev/null || notes+="\n[!] expire dans moins de 30 jours"
  [ "$(grep -c 'BEGIN CERTIFICATE' "$tmp/chain")" -gt 1 ] || notes+="\n[!] pas de certificat intermédiaire (chaîne incomplète)"
  while ! openssl x509 -in "$tmp/chain" -noout -checkhost "$web_name" | grep -q 'does match'; do
    web_name=$(wt --title "Certificat web > nom" --inputbox \
      "$notes\n\nLe certificat ne couvre pas $web_name (un wildcard ne couvre qu'un niveau).\nNom de l'interface web couvert par le certificat (enregistrement DNS interne à créer) :" 16 76 "$web_name") \
      || { shred -u "$tmp/key"; rm -rf "$tmp"; return 0; }
  done
  confirm "Certificat web > installation" "$notes\n\nInstaller pour https://$web_name ?\nLa clé d'un wildcard vaut pour tout le domaine : elle reste lisible par root seul." \
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
  ok "minisoc-syslog-ca.crt   -> serveurs NXLog (vérification du Mini-SOC en 6514)"
  [ -f "$out/minisoc-web-root.crt" ] && ok "minisoc-web-root.crt    -> GPO : autorités de certification racines de confiance"
  line "Récupération depuis un poste DSI :  ${W}scp -r adminsoc@$VM_IP:a-recuperer .${N}"
  end
  if [ -f "$APP/data/syslog-tls/ca.key" ]; then
    printf '%s  [!] L’autorité du syslog (ca.key) ne sert qu’au renouvellement : la garder dans le coffre-fort, pas sur la VM.%s\n' "$Y" "$N"
    printf '    sudo cat %s\n' "$APP/data/syslog-tls/ca.key"
    if confirm "Autorité du syslog" "ca.key est-elle copiée dans le coffre-fort de la DSI ?\nOui = l'effacer de la VM."; then
      shred -u "$APP/data/syslog-tls/ca.key"; ok "ca.key effacée"
    fi
  fi
  if [ ! -e /etc/minisoc/coffre-fort.fait ]; then
    printf '\n%s  [!] Secrets à copier dans le coffre-fort de la DSI (indispensables pour restaurer une sauvegarde) :%s\n' "$Y" "$N"
    printf '    phrase de passe des sauvegardes : sudo cat /etc/minisoc/backup.pass\n'
    printf '    clé maître de l’application     : sudo grep MINISOC_MASTER_KEY %s/.env\n' "$APP"
    if confirm "Coffre-fort" "La phrase de passe des sauvegardes et la clé maître sont-elles copiées dans le coffre-fort de la DSI ?\nOui = ne plus le rappeler à la connexion."; then
      touch /etc/minisoc/coffre-fort.fait; ok "rappel du coffre-fort retiré"
    fi
  fi
  pause
}
s_status() {
  banner
  local nb running total banned
  section "ÉTAT DE LA VM"
  line "$HOST  ·  $VM_IP  ·  $(. /etc/os-release; echo "$PRETTY_NAME")  ·  en service depuis $(uptime -p | sed 's/^up //')"
  if [ "$INITIAL" = 1 ]; then ko "pare-feu en MODE INITIAL (plages privées) -> Entrants puis Appliquer"
  elif systemctl is-active -q minisoc-firewall; then ok "pare-feu actif : $(echo "$ADMINS" | wc -w) poste(s) d'administration"
  else ko "pare-feu inactif"; fi
  nb=$( [ -s "$KEYS" ] && grep -c . "$KEYS" || echo 0)
  if [ "$nb" -gt 0 ]; then ok "SSH par clé uniquement ($nb clé(s)), port $SSH_PORT"; else ko "SSH par mot de passe (aucune clé), port $SSH_PORT"; fi
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
if [ "$INITIAL" = 1 ] && confirm "Bienvenue" "Première configuration : le pare-feu est en mode initial (toutes les plages privées sont acceptées).\n\nLancer l'assistant complet ?\n  accès entrants -> accès sortants -> sauvegarde -> clés et port SSH -> appliquer"; then
  s_inbound; s_outbound; s_backup; s_keys; s_ssh_port; s_apply
fi
while :; do
  flag=""; [ "$PENDING" = 1 ] && flag="  * modifications non appliquées"
  choice=$(wt --title "[ MINI-SOC ]" --ok-label "Ouvrir" --cancel-label "Quitter" --menu "Hôte \Zb$HOST\ZB · $VM_IP\Z3$flag\Zn\nUne lettre ou les flèches, puis Entrée. Échap : quitter." 19 78 11 \
    "E" "Entrants          postes DSI, écran mural, sources syslog" \
    "S" "Sortants          DNS, NTP, AD, SMTP, XGS, CrowdSec, SaaS" \
    "B" "Sauvegarde        serveur de récupération et sa clé" \
    "K" "Clés SSH          administrateurs (coupe le mot de passe)" \
    "P" "Port SSH          actuellement $SSH_PORT" \
    "A" "> APPLIQUER       pare-feu + SSH, retour arrière auto" \
    "C" "Certificat web    PKI interne ou wildcard" \
    "U" "Comptes           secours, jeton de l'écran mural" \
    "F" "Fichiers          autorités à déployer, secrets du coffre-fort" \
    "T" "Tableau de bord   état de la VM, conteneurs, sauvegardes" \
    "Q" "Quitter") || choice=Q
  case $choice in
    E) s_inbound; offer_apply ;; S) s_outbound; offer_apply ;; B) s_backup ;; K) s_keys ;; P) s_ssh_port ;; A) s_apply ;;
    C) s_cert ;; U) s_accounts ;; F) s_files ;; T) s_status ;;
    Q)
      if [ "$PENDING" = 1 ] && confirm "Quitter" "Des modifications ne sont pas appliquées. Les appliquer maintenant ?"; then
        s_apply; continue
      fi
      clear; printf '%s' "$C"; [ -f "$BANNER" ] && cat "$BANNER"; printf '%s  Fin de session.%s\n' "$N" ""; exit 0 ;;
  esac
done
