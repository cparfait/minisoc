#!/bin/bash
# Espace des disques de la VM Mini-SOC : relevé des systèmes de fichiers locaux (/, /var/log, disque de données
# /var/lib/docker, /boot…), déposé toutes les 5 minutes (minisoc-disk.timer) dans /var/lib/minisoc/disques.
# Le worker le lit (dossier monté en lecture seule, backend/minisoc/hostdisk.py) : alerte UC-63 au-delà du seuil
# réglé dans Paramètres › Détection, état affiché dans Statistiques › Disques de la VM.
# Le conteneur ne voit pas les disques de l'hôte : ce petit service, sans réseau ni privilège, les lit pour lui.
set -euo pipefail
DIR=${DISK_DIR:-/var/lib/minisoc/disques}
install -d -m 0755 "$DIR"   # créé aussi par systemd (StateDirectory)
python3 - "$DIR/disques.json" <<'EOF'
import json, os, re, socket, sys
from datetime import datetime, timezone

REAL = {"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "f2fs", "zfs", "jfs", "reiserfs"}
seen, filesystems = {}, []
with open("/proc/self/mounts", encoding="utf-8") as mounts:
    for line in mounts:
        device, mount, fstype = line.split()[:3]
        mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), mount)  # espaces codés \040
        if fstype not in REAL:
            continue
        try:
            dev = os.stat(mount).st_dev
            st = os.statvfs(mount)
        except OSError:
            continue
        # Un même système de fichiers peut être monté plusieurs fois (montages liés : containerd, archives) :
        # gardé une fois, sous son chemin le plus court
        if dev in seen and len(seen[dev]["mount"]) <= len(mount):
            continue
        size, avail = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        files_used = st.f_files - st.f_ffree
        entry = {
            "mount": mount, "device": device, "fstype": fstype, "size": size, "used": used, "avail": avail,
            # comme df : part utilisée de l'espace accessible (la réserve de root est exclue), arrondie au-dessus
            "percent": -(-used * 100 // (used + avail)) if used + avail else 0,
            "inodes_percent": -(-files_used * 100 // (files_used + st.f_favail)) if st.f_files else 0,
        }
        if dev in seen:
            filesystems.remove(seen[dev])
        seen[dev] = entry
        filesystems.append(entry)
report = {
    "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "host": socket.gethostname(),
    "filesystems": sorted(filesystems, key=lambda f: f["mount"]),
}
path = sys.argv[1]
with open(path + ".tmp", "w", encoding="utf-8") as out:
    json.dump(report, out, ensure_ascii=False)
os.chmod(path + ".tmp", 0o644)
os.replace(path + ".tmp", path)
EOF
