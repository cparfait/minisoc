# Construit depuis la racine du dépôt : docker build -f frontend/Dockerfile .
FROM node:26-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM caddy:2-alpine AS caddy-officiel

# Caddy recompilé à l'identique (même version que l'image officielle) avec le dernier Go et la dernière version de
# golang.org/x/net : le binaire publié garde le Go et les dépendances du jour de sa sortie, et leurs CVE corrigées
# depuis (relevées par Trivy et Cyberwatch) jusqu'à la version suivante de Caddy. Reconstruit à chaque mise à jour.
FROM golang:alpine AS caddy
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
 && go get "github.com/caddyserver/caddy/v2@$version" golang.org/x/net@latest \
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
