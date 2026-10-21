# Construit depuis la racine du dépôt : docker build -f frontend/Dockerfile .
# Images figées par leur empreinte, golang.org/x/net par sa version : mises à jour par scripts/update_pins.sh
FROM node:26-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM caddy:2-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f AS caddy-officiel

# Caddy recompilé à l'identique (même version que l'image officielle) avec le dernier Go et la dernière version de
# golang.org/x/net (relevés par scripts/update_pins.sh) : le binaire publié garde le Go et les dépendances du jour de
# sa sortie, et leurs CVE corrigées depuis (relevées par Cyberwatch) jusqu'à la version suivante de Caddy.
FROM golang:alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS caddy
ARG XNET_VERSION=v0.61.0
COPY --from=caddy-officiel /usr/bin/caddy /tmp/caddy-officiel
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN version=$(/tmp/caddy-officiel version | cut -d' ' -f1) \
 && printf '%s\n' 'package main' \
      'import (' \
      '	caddycmd "github.com/caddyserver/caddy/v2/cmd"' \
      '	_ "github.com/caddyserver/caddy/v2/modules/standard"' \
      ')' \
      'func main() { caddycmd.Main() }' > main.go \
 && go mod init caddy \
 && go get "github.com/caddyserver/caddy/v2@$version" "golang.org/x/net@$XNET_VERSION" \
 && go mod tidy \
 && go build -trimpath -ldflags '-s -w' -o /usr/bin/caddy . \
 && /usr/bin/caddy version | grep -q "^$version " \
 && /tmp/caddy-officiel list-modules > /tmp/modules-officiel \
 && /usr/bin/caddy list-modules > /tmp/modules-recompile \
 && diff /tmp/modules-officiel /tmp/modules-recompile

FROM caddy-officiel
# Correctifs Alpine publiés depuis la construction de l'image Caddy
RUN apk upgrade --no-cache
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
# Comme l'image officielle : écoute sur 80 et 443 sans être root
RUN setcap cap_net_bind_service=+ep /usr/bin/caddy
COPY --from=build /app/dist /srv
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
