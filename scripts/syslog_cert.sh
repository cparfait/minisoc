#!/usr/bin/env sh
# Certificats du syslog chiffré (TLS, port 6514) : autorité de certification propre au Mini-SOC + certificat serveur.
#
#   ./scripts/syslog_cert.sh minisoc.mairie.local 10.1.0.50
#
# Crée data/syslog-tls/ : ca.crt (à installer sur les équipements émetteurs pour qu'ils vérifient le Mini-SOC),
# server.crt et server.key (utilisés par le service vector-tls). L'autorité (ca.key) n'est utile que pour
# renouveler le certificat : la conserver hors ligne. Validité : autorité 10 ans, serveur 2 ans.
set -eu

NAME="${1:?usage : $0 <nom DNS du Mini-SOC> [adresse IP]}"
IP="${2:-}"
DIR="$(dirname "$0")/../data/syslog-tls"
mkdir -p "$DIR"
cd "$DIR"
umask 077

if [ ! -f ca.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 -keyout ca.key -out ca.crt \
    -subj "/CN=Mini-SOC syslog CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

SAN="DNS:${NAME}"
[ -n "$IP" ] && SAN="${SAN},IP:${IP}"
openssl req -newkey rsa:3072 -sha256 -nodes -keyout server.key -out server.csr -subj "/CN=${NAME}"
printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n" "$SAN" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 730 -sha256 \
  -extfile server.ext -out server.crt
rm -f server.csr server.ext
# Lisibles par le conteneur Vector (utilisateur non root) ; la clé de l'autorité reste privée
chmod 644 server.crt ca.crt server.key
echo "Certificats créés dans $(pwd) :"
openssl x509 -in server.crt -noout -subject -ext subjectAltName -enddate
echo "Activer : COMPOSE_PROFILES=...,syslog-tls dans .env puis : docker compose up -d vector-tls"
