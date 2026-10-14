#!/bin/sh
# Construit l'ISO d'installation automatique de la VM Mini-SOC à partir de l'ISO netinst officielle de Debian.
# À lancer dans un conteneur Debian, depuis la racine du projet (PowerShell ou Git Bash) :
#   docker run --rm -v "${PWD}:/work" -w /work debian:13-slim sh deploy/iso/build-iso.sh
# Entrées : deploy/iso/vm.conf (copie de vm.conf.example) et, si présent, deploy/iso/authorized_keys.
# Sortie : build/iso/minisoc-<version>-amd64-auto.iso
set -eu
HERE=deploy/iso
OUT=${MINISOC_ISO_OUT:-build/iso}
CACHE=build/iso/debian
MIRROR=https://cdimage.debian.org/debian-cd/current/amd64/iso-cd
CONF=${MINISOC_VM_CONF:-$HERE/vm.conf}
KEYS=${MINISOC_AUTHORIZED_KEYS:-$HERE/authorized_keys}
# Menu de démarrage : -1 = attendre Entrée (évite une réinstallation si la VM redémarre sur le CD).
TIMEOUT=${MINISOC_ISO_TIMEOUT:--1}

[ -f "$CONF" ] || { echo "Fichier $CONF absent : copier $HERE/vm.conf.example en $HERE/vm.conf"; exit 1; }
. "./$CONF"

if ! command -v xorriso >/dev/null || ! command -v curl >/dev/null || ! command -v git >/dev/null; then
  apt-get update -qq && apt-get install -y -qq --no-install-recommends xorriso curl ca-certificates git >/dev/null
fi

# ---------- ISO officielle, vérifiée par son empreinte SHA-512 ----------
mkdir -p "$CACHE" "$OUT"
curl -fsSL "$MIRROR/SHA512SUMS" -o "$CACHE/SHA512SUMS"
iso=$(awk '$2 ~ /^debian-[0-9.]+-amd64-netinst\.iso$/ {print $2}' "$CACHE/SHA512SUMS")
[ -n "$iso" ] || { echo "ISO netinst introuvable dans SHA512SUMS"; exit 1; }
if ! (cd "$CACHE" && grep " $iso\$" SHA512SUMS | sha512sum -c --status 2>/dev/null); then
  echo "Téléchargement de $iso"
  curl -fL --progress-bar "$MIRROR/$iso" -o "$CACHE/$iso"
  (cd "$CACHE" && grep " $iso\$" SHA512SUMS | sha512sum -c)
fi
version=$(echo "$iso" | sed 's/^debian-\([0-9.]*\)-.*/\1/')

# ---------- Fichiers ajoutés ----------
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/minisoc"

{
  echo "# Généré par build-iso.sh à partir de $CONF"
  [ -z "$VM_HOSTNAME" ] || printf 'd-i netcfg/get_hostname string %s\nd-i netcfg/hostname string %s\n' "$VM_HOSTNAME" "$VM_HOSTNAME"
  [ -z "$VM_DOMAIN" ] || printf 'd-i netcfg/get_domain string %s\n' "$VM_DOMAIN"
  if [ -n "$VM_IP" ]; then
    printf 'd-i netcfg/get_ipaddress string %s\n' "$VM_IP"
    printf 'd-i netcfg/get_netmask string %s\n' "$VM_NETMASK"
    printf 'd-i netcfg/get_gateway string %s\n' "$VM_GATEWAY"
    printf 'd-i netcfg/get_nameservers string %s\n' "$VM_DNS"
  fi
  printf 'd-i mirror/http/proxy string %s\n' "$HTTP_PROXY"
  [ -z "$ADMIN_PASSWORD_HASH" ] || printf 'd-i passwd/user-password-crypted password %s\n' "$ADMIN_PASSWORD_HASH"
} > "$work/site.cfg"

printf "VM_NTP='%s'\nHTTP_PROXY='%s'\nDOCKER_POOL='%s'\n" "$VM_NTP" "$HTTP_PROXY" "${DOCKER_POOL:-10.255.0.0/16}" \
  > "$work/minisoc/site.env"
cp "$HERE/choose-disk.sh" "$HERE/late.sh" "$HERE/firstboot.sh" "$HERE/minisoc-firstboot.service" \
  "$HERE/minisoc-sshd-config.sh" "$HERE/minisoc-setup.sh" "$HERE/banner.txt" \
  deploy/firewall/minisoc-firewall deploy/firewall/minisoc-firewall.service "$work/minisoc/"
# Application : fichiers du dépôt (suivis ou nouveaux), sans ce que .gitignore exclut (.env, secrets, données)
git config --global --add safe.directory "$(pwd)"
git ls-files -co --exclude-standard | grep -v -e '^build/' -e '^deploy/iso/' \
  | tar -T - -czf "$work/minisoc/minisoc.tar.gz"
echo "Application : $(tar -tzf "$work/minisoc/minisoc.tar.gz" | wc -l) fichiers ($(du -h "$work/minisoc/minisoc.tar.gz" | cut -f1))"
if [ -s "$KEYS" ]; then
  grep -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) ' "$KEYS" > "$work/minisoc/authorized_keys"
  echo "Clés SSH : $(wc -l < "$work/minisoc/authorized_keys")"
else
  echo "Aucune clé SSH (deploy/iso/authorized_keys) : la connexion par mot de passe restera active"
fi
# Fins de ligne Windows éventuelles (fichiers édités sous Windows)
for f in "$work"/site.cfg "$work"/minisoc/*; do
  case "$f" in *.tar.gz) ;; *) sed -i 's/\r$//' "$f" ;; esac
done
sed 's/\r$//' "$HERE/preseed.cfg" > "$work/preseed.cfg"

args="auto=true priority=high preseed/file=/cdrom/preseed.cfg language=fr country=FR locale=fr_FR.UTF-8 keymap=fr"
xorriso -osirrox on -indev "$CACHE/$iso" -extract /boot/grub/grub.cfg "$work/grub-debian.cfg" 2>/dev/null
chmod u+w "$work/grub-debian.cfg"

# UEFI (Secure Boot conservé : shim et GRUB signés de l'ISO d'origine sont repris tels quels)
cat > "$work/grub.cfg" <<EOF
set default=0
set timeout=$TIMEOUT
menuentry "Mini-SOC : installation automatique (EFFACE LE DISQUE SYSTEME)" {
  linux /install.amd/vmlinuz $args --- quiet
  initrd /install.amd/initrd.gz
}
menuentry "Menu d'installation Debian d'origine" {
  configfile /boot/grub/grub-debian.cfg
}
EOF
# BIOS
isolinux_timeout=$([ "$TIMEOUT" = -1 ] && echo 0 || echo $((TIMEOUT * 10)))
cat > "$work/isolinux.cfg" <<EOF
default minisoc
prompt 1
timeout $isolinux_timeout
display boot.txt
label minisoc
  kernel /install.amd/vmlinuz
  append $args initrd=/install.amd/initrd.gz --- quiet
EOF
printf 'Mini-SOC : installation automatique (EFFACE LE DISQUE SYSTEME). Appuyer sur Entree.\n' > "$work/boot.txt"

# ---------- ISO finale (secteurs de démarrage d'origine rejoués) ----------
target="$OUT/minisoc-debian-$version-amd64-auto.iso"
rm -f "$target"
xorriso -indev "$CACHE/$iso" -outdev "$target" \
  -map "$work/preseed.cfg" /preseed.cfg \
  -map "$work/site.cfg" /site.cfg \
  -map "$work/minisoc" /minisoc \
  -map "$work/grub-debian.cfg" /boot/grub/grub-debian.cfg \
  -map "$work/grub.cfg" /boot/grub/grub.cfg \
  -map "$work/isolinux.cfg" /isolinux/isolinux.cfg \
  -map "$work/boot.txt" /isolinux/boot.txt \
  -boot_image any replay 2>&1 | grep -iE 'error|fail|sorry' || true
[ -s "$target" ] || { echo "Échec de la construction"; exit 1; }
(cd "$OUT" && sha256sum "${target##*/}" > "${target##*/}.sha256")
echo "ISO prête : $target ($(du -h "$target" | cut -f1))"
echo "SHA-256 : $(cut -d' ' -f1 "$target.sha256")"
