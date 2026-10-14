#!/bin/sh
# Lancé par l'installateur avant le partitionnement : le disque système est le plus petit disque d'au moins
# 20 Gio. Le disque de données (le plus gros) n'est pas touché ici.
best=""
best_size=0
for dev in /sys/block/*; do
  name=${dev##*/}
  case "$name" in sd*|vd*|xvd*|nvme*n*) ;; *) continue ;; esac
  [ "$(cat "$dev/removable" 2>/dev/null)" = 1 ] && continue
  size=$(cat "$dev/size")                     # secteurs de 512 octets
  [ "$size" -ge 41943040 ] || continue        # 20 Gio
  if [ -z "$best" ] || [ "$size" -lt "$best_size" ]; then
    best=$name
    best_size=$size
  fi
done
[ -n "$best" ] && debconf-set partman-auto/disk "/dev/$best"
exit 0
