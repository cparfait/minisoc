FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN groupadd --system minisoc && useradd --system --gid minisoc --home-dir /app --no-create-home minisoc
# Archives scellées : volume nommé, initialisé avec ce propriétaire (compte non privilégié)
RUN mkdir -p /var/lib/minisoc/archives && chown -R minisoc:minisoc /var/lib/minisoc
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
USER minisoc
EXPOSE 8000
CMD ["uvicorn", "minisoc.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
