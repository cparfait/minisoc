FROM python:3.14-slim AS base
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
COPY pyproject.toml ./
COPY minisoc ./minisoc
RUN pip install .
COPY rules ./rules

# Tests : docker build --target test backend && docker run --rm <image>
FROM base AS test
RUN pip install ".[dev]"
COPY tests ./tests
USER minisoc
CMD ["pytest", "-q", "-p", "no:cacheprovider"]

FROM base AS runtime
# pip ne sert qu'à l'installation : retiré, avec les bibliothèques qu'il embarque (urllib3, msgpack… souvent en retard)
RUN pip uninstall -y pip
USER minisoc
EXPOSE 8000
CMD ["uvicorn", "minisoc.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
