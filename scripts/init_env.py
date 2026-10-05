"""Crée le fichier .env à partir de .env.example en générant tous les secrets.

    python scripts/init_env.py
"""

from __future__ import annotations

import base64
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(32),
    "CLICKHOUSE_PASSWORD": lambda: secrets.token_urlsafe(32),
    "MINISOC_INGEST_TOKEN": lambda: secrets.token_urlsafe(32),
    "MINISOC_MASTER_KEY": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
    "MINISOC_BITDEFENDER_TOKEN": lambda: secrets.token_urlsafe(32),
}


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans les consoles Windows


def main() -> int:
    target = ROOT / ".env"
    if target.exists():
        print(".env existe déjà : rien n'a été modifié (supprimez-le d'abord pour régénérer les secrets).")
        return 1
    lines = []
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key in GENERATED and not value:
            line = f"{key}={GENERATED[key]()}"
        lines.append(line)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
    print(f"{target} créé avec des secrets aléatoires. Complétez les sections HarfangLab et notifications.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
