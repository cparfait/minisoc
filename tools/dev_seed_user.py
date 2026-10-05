"""DÉVELOPPEMENT UNIQUEMENT : crée (ou réinitialise) un compte de démonstration non interactif.

    docker compose exec -T api python - < tools/dev_seed_user.py > .dev-credentials.json

Le mot de passe et la clé TOTP générés sont écrits sur la sortie standard (JSON) : à rediriger vers
`.dev-credentials.json` (ignoré par git). En production, utiliser `python -m minisoc.cli create-user`.
"""

import asyncio
import json
import secrets

from sqlalchemy import select

from minisoc.crypto import encrypt
from minisoc.db import init_db, sessionmaker
from minisoc.models import User
from minisoc.security import hash_password, new_totp_secret

USERNAME = "demo"


async def main() -> None:
    await init_db()
    password = secrets.token_urlsafe(18)
    secret = new_totp_secret()
    async with sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.username == USERNAME))
        if user is None:
            user = User(username=USERNAME, role="admin")
            db.add(user)
        user.password_hash = hash_password(password)
        user.totp_secret_enc = encrypt(secret)
        user.totp_last_step = 0
        user.failed_attempts = 0
        user.locked_until = None
        await db.commit()
    print(json.dumps({"username": USERNAME, "password": password, "totp_secret": secret}))


asyncio.run(main())
