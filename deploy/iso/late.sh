#!/bin/sh
# Lancé par l'installateur en fin d'installation : prépare le service du premier démarrage.
set -e
SRC=/cdrom/minisoc
T=/target
LIB=$T/usr/local/lib/minisoc-install

mkdir -p "$LIB" "$T/etc/minisoc-firstboot"
for f in minisoc.tar.gz minisoc-firewall minisoc-firewall.service minisoc-sshd-config.sh minisoc-setup.sh banner.txt \
         minisoc-motd minisoc-update.sh VERSION; do
  install -m 0600 "$SRC/$f" "$LIB/$f"
done
chmod 0700 "$LIB"
install -m 0700 "$SRC/firstboot.sh" "$T/usr/local/sbin/minisoc-firstboot"
install -m 0644 "$SRC/minisoc-firstboot.service" "$T/etc/systemd/system/minisoc-firstboot.service"
install -m 0600 "$SRC/site.env" "$T/etc/minisoc-firstboot/site.env"

# Bandeau Mini-SOC dès la première connexion, même si le premier démarrage échoue : avant la connexion
# (/etc/issue, console) et après (update-motd : console et SSH, avec l'état de l'installation)
install -D -m 0644 "$SRC/banner.txt" "$T/usr/local/share/minisoc/banner.txt"
install -m 0755 "$SRC/minisoc-motd" "$T/etc/update-motd.d/05-minisoc"
[ ! -f "$T/etc/update-motd.d/10-uname" ] || chmod -x "$T/etc/update-motd.d/10-uname"   # ligne « Linux minisoc 6.12… »
: > "$T/etc/motd"
{ cat "$SRC/banner.txt"; echo; echo '  \n.\o  ·  \4  ·  \s \r'; echo; } > "$T/etc/issue"

if [ -s "$SRC/authorized_keys" ]; then
  mkdir -p "$T/home/adminsoc/.ssh"
  install -m 0600 "$SRC/authorized_keys" "$T/home/adminsoc/.ssh/authorized_keys"
  chmod 0700 "$T/home/adminsoc/.ssh"
  in-target chown -R adminsoc:adminsoc /home/adminsoc/.ssh
fi

in-target systemctl enable minisoc-firstboot.service
