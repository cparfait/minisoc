#!/bin/sh
# Écrit /etc/ssh/sshd_config.d/10-minisoc.conf (doc 04 § 4.3 et § 8) selon l'état de la VM :
# - clé uniquement dès qu'une clé est déposée pour adminsoc, mot de passe sinon (installation en cours) ;
# - compte minisoc-backup autorisé depuis le seul serveur de sauvegarde (BACKUP_SERVER de firewall.conf).
# Ne recharge pas sshd : l'appelant vérifie (sshd -t) puis recharge.
set -eu
BACKUP_SERVER=""
[ -f /etc/minisoc/firewall.conf ] && . /etc/minisoc/firewall.conf
users="adminsoc"
if [ -n "$BACKUP_SERVER" ] && [ -s /var/lib/minisoc-backup/.ssh/authorized_keys ]; then
  users="$users minisoc-backup@$BACKUP_SERVER"
fi
if [ -s /home/adminsoc/.ssh/authorized_keys ]; then
  auth="PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey"
else
  auth="# Aucune clé déposée pour adminsoc : mot de passe autorisé (sudo minisoc-setup pour déposer une clé)
PasswordAuthentication yes
KbdInteractiveAuthentication no"
fi
cat > /etc/ssh/sshd_config.d/10-minisoc.conf <<EOF
# Généré par minisoc-sshd-config : relancer sudo minisoc-setup plutôt que modifier ce fichier.
PermitRootLogin no
$auth
AllowUsers $users
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/issue.net
EOF
chmod 644 /etc/ssh/sshd_config.d/10-minisoc.conf
