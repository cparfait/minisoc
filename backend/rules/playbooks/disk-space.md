# Disque de la VM Mini-SOC presque plein

Un disque plein arrête la réception des journaux (Vector, ClickHouse), les bases et les mises à jour : à traiter
avant qu'il n'atteigne 100 %.

## Vérifier
1. Sur la VM : `df -h` et `df -i` (inodes). Le détail de l'alerte donne la partition et son occupation.
2. Ce qui grossit :
   - `/` : `sudo du -xh --max-depth=2 / | sort -h | tail -20` (sauvegardes de `/var/backups/minisoc`, mises à jour
     dans `/var/backups/minisoc/mises-a-jour`, anciens paquets dans `/tmp`) ;
   - `/var/log` : `sudo journalctl --disk-usage`, `sudo du -sh /var/log/* | sort -h` ;
   - `/var/lib/docker` (disque de données) : `sudo docker system df` (images, cache de construction, volumes).
3. Alerte « non relevé » : `systemctl status minisoc-disk.timer` et `sudo journalctl -u minisoc-disk`.

## Agir
1. Images et cache de construction inutiles : `sudo docker builder prune -af` puis `sudo docker image prune -f`.
2. Journaux système : `sudo journalctl --vacuum-size=500M`.
3. Événements : réduire la conservation (Paramètres › Conservation) ou agrandir le disque de données (vSphere,
   puis `sudo resize2fs`).
4. Archives scellées : ne jamais les effacer sans décision de la DSI (preuve, chaîne d'empreintes).
5. Relevé arrêté : `sudo systemctl enable --now minisoc-disk.timer`.
