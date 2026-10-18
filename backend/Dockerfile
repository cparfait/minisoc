# Python 3.14 (dernier correctif à chaque reconstruction) : au 16/10/2026, Python 3.15 est bloqué par
# clickhouse-connect (requires_python <3.15) ; pyyaml, lz4 et zstandard n'ont pas encore de roue cp315 et l'image
# n'a pas de compilateur. Revérifier à chaque paquet de mise à jour.
# Image figée par son empreinte et dépendances par requirements.lock (versions et empreintes) : la VM reconstruit
# exactement ce qui a été testé. Mise à jour des deux : scripts/update_pins.sh
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170 AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# Correctifs Debian publiés depuis la construction de l'image Python (dépôts en HTTPS : seule sortie permise aux
# conteneurs par le pare-feu de la VM)
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|' /etc/apt/sources.list.d/debian.sources  && apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
RUN groupadd --system minisoc && useradd --system --gid minisoc --home-dir /app --no-create-home minisoc
# Archives scellées : volume nommé, initialisé avec ce propriétaire (compte non privilégié)
RUN mkdir -p /var/lib/minisoc/archives && chown -R minisoc:minisoc /var/lib/minisoc
# Bases GeoIP : volume nommé initialisé avec ce propriétaire (téléchargées par le worker, compte non privilégié)
RUN mkdir -p /app/data/geoip && chown minisoc:minisoc /app/data/geoip
# Rapports Trivy de la VM : dossier de l'hôte monté ici (propriété du compte minisoc, voir deploy/trivy)
RUN mkdir -p /var/lib/minisoc/trivy && chown minisoc:minisoc /var/lib/minisoc/trivy
# --require-hashes : refuse tout paquet absent du verrou ou dont l'empreinte diffère (dépendance transitive comprise)
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock
# Le code s'exécute depuis /app (pas de pip install . : il téléchargerait setuptools hors verrou)
ENV PYTHONPATH=/app
COPY pyproject.toml ./
COPY minisoc ./minisoc
COPY rules ./rules

# Tests : docker build --target test backend && docker run --rm <image>
FROM base AS test
COPY requirements-dev.lock ./
RUN pip install --require-hashes -r requirements-dev.lock
COPY tests ./tests
USER minisoc
CMD ["pytest", "-q", "-p", "no:cacheprovider"]

FROM base AS runtime
# pip ne sert qu'à l'installation : retiré, avec les bibliothèques qu'il embarque (urllib3, msgpack… souvent en retard)
RUN pip uninstall -y pip
USER minisoc
EXPOSE 8000
CMD ["uvicorn", "minisoc.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
