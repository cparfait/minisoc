#!/bin/sh
# Lancé par l'installateur en fin d'installation : prépare le service du premier démarrage.
set -e
SRC=/cdrom/minisoc
T=/target
LIB=$T/usr/local/lib/minisoc-install

mkdir -p "$LIB" "$T/etc/minisoc-firstboot"
for f in minisoc.tar.gz minisoc-firewall minisoc-firewall.service minisoc-sshd-config.sh minisoc-setup.sh banner.txt; do
  install -m 0600 "$SRC/$f" "$LIB/$f"
done
chmod 0700 "$LIB"
install -m 0700 "$SRC/firstboot.sh" "$T/usr/local/sbin/minisoc-firstboot"
install -m 0644 "$SRC/minisoc-firstboot.service" "$T/etc/systemd/system/minisoc-firstboot.service"
install -m 0600 "$SRC/site.env" "$T/etc/minisoc-firstboot/site.env"

if [ -s "$SRC/authorized_keys" ]; then
  mkdir -p "$T/home/adminsoc/.ssh"
  install -m 0600 "$SRC/authorized_keys" "$T/home/adminsoc/.ssh/authorized_keys"
  chmod 0700 "$T/home/adminsoc/.ssh"
  in-target chown -R adminsoc:adminsoc /home/adminsoc/.ssh
fi

in-target systemctl enable minisoc-firstboot.service
