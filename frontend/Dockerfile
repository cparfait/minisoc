# Construit depuis la racine du dépôt : docker build -f frontend/Dockerfile .
FROM node:26-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM caddy:2-alpine
# Correctifs Alpine publiés depuis la construction de l'image Caddy
RUN apk upgrade --no-cache
COPY --from=build /app/dist /srv
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
