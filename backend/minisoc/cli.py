"""Administration en ligne de commande.

    docker compose exec api python -m minisoc.cli create-user --username alice --role admin
    docker compose exec api python -m minisoc.cli reset-mfa --username alice
    docker compose exec api python -m minisoc.cli check-rules
    docker compose exec api python -m minisoc.cli verify-audit
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import io
import ipaddress
import secrets
import sys
from datetime import datetime, timedelta, timezone

import qrcode
from sqlalchemy import func, select

from minisoc.audit import record, verify_chain
from minisoc.config import get_settings
from minisoc.crypto import encrypt
from minisoc.db import init_db, sessionmaker
from minisoc.models import ROLES, DisplayToken, User
from minisoc.rules import RuleError, load_rules
from minisoc.security import hash_password, new_totp_secret, password_problems, session_id, totp_uri

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _ask_password(username: str) -> str:
    while True:
        password = getpass.getpass("Mot de passe : ")
        problems = password_problems(password, username)
        if problems:
            print("Mot de passe refusé : " + ", ".join(problems))
            continue
        if getpass.getpass("Confirmation : ") != password:
            print("Les deux saisies diffèrent.")
            continue
        return password


def _show_totp(secret: str, username: str) -> None:
    uri = totp_uri(secret, username)
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    out = io.StringIO()
    qr.print_ascii(out=out, invert=True)
    print("\nScanner ce QR code avec une application d'authentification (Microsoft Authenticator, FreeOTP…) :\n")
    print(out.getvalue())
    print("Ou saisir manuellement la clé :", secret)
    print("Cette clé ne sera plus affichée.\n")


async def create_user(username: str, role: str) -> int:
    await init_db()
    async with sessionmaker()() as db:
        if await db.scalar(select(User).where(User.username == username)):
            print(f"L'utilisateur {username} existe déjà.")
            return 1
        password = _ask_password(username)
        secret = new_totp_secret()
        db.add(User(username=username, password_hash=hash_password(password), totp_secret_enc=encrypt(secret),
                    role=role))
        await record(db, actor="cli", action="user_create", obj=f"user:{username}", detail={"role": role})
        await db.commit()
    _show_totp(secret, username)
    print(f"Utilisateur {username} ({role}) créé.")
    return 0


async def reset_mfa(username: str) -> int:
    async with sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if not user:
            print(f"Utilisateur {username} introuvable.")
            return 1
        secret = new_totp_secret()
        user.totp_secret_enc = encrypt(secret)
        user.totp_last_step = 0
        user.failed_attempts = 0
        user.locked_until = None
        await record(db, actor="cli", action="mfa_reset", obj=f"user:{username}")
        await db.commit()
    _show_totp(secret, username)
    return 0


async def delete_user(username: str) -> int:
    """Supprime un compte (sessions comprises). L'historique des alertes et le journal d'audit sont conservés."""
    async with sessionmaker()() as db:
        user = await db.scalar(select(User).where(User.username == username))
        if not user:
            print(f"Utilisateur {username} introuvable.")
            return 1
        admins = await db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.active))
        if user.role == "admin" and user.active and admins <= 1:
            print("Refusé : c'est le dernier administrateur actif.")
            return 1
        await db.delete(user)
        await record(db, actor="cli", action="user_delete", obj=f"user:{username}",
                     detail={"role": user.role, "source": user.auth_source})
        await db.commit()
    print(f"Utilisateur {username} supprimé.")
    return 0


async def xgs_rules() -> int:
    """Lecture seule des règles du Sophos XGS avec les paramètres saisis dans Intégrations."""
    from minisoc.response.xgs import XGSClient, XGSError
    from minisoc.settings_store import store

    async with sessionmaker()() as db:
        cfg = await store.load(db, force=True)
    try:
        rules = await XGSClient(cfg).firewall_rules()
    except XGSError as exc:
        print(f"Échec : {exc}")
        return 1
    print(f"{len(rules)} règle(s) :")
    for r in rules:
        zones = f"{','.join(r['source_zones']) or 'toutes'} → {','.join(r['destination_zones']) or 'toutes'}"
        print(f"{r['position'] or '-':>3} [{r['status'] or '?':7}] {r['action'] or '?':7} {r['name'][:45]:45} {zones}"
              f"  journal={r['log'] or '?'}")
    return 0


async def verify_audit() -> int:
    async with sessionmaker()() as db:
        ok, broken = await verify_chain(db)
    print("Journal d'audit intègre." if ok else f"ALERTE : journal d'audit altéré à partir de l'entrée {broken}.")
    return 0 if ok else 2


def check_rules() -> int:
    try:
        rules = load_rules(get_settings().rules_dir, strict=True)
    except RuleError as exc:
        print(f"Erreur : {exc}")
        return 1
    for rule in rules:
        print(f"OK  {rule.id:<8} {rule.type:<10} {rule.severity:<10} {rule.name}")
    return 0


async def create_display_token(name: str, days: int, ips: list[str], show_users: bool, public_url: str) -> int:
    for net in ips:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            print(f"Adresse ou réseau invalide : {net}")
            return 1
    await init_db()
    token = secrets.token_urlsafe(32)
    async with sessionmaker()() as db:
        display = DisplayToken(
            name=name,
            token_hash=session_id(token),
            allowed_ips=ips,
            mask_users=not show_users,
            created_by="cli",
            expires_at=datetime.now(timezone.utc) + timedelta(days=days),
        )
        db.add(display)
        await db.flush()
        await record(db, actor="cli", action="display_token_create", obj=f"display:{display.id}",
                     detail={"name": name, "days": days, "ips": ips, "mask_users": not show_users})
        await db.commit()
    print(f"Jeton d'affichage n° {display.id} « {name} » créé, valable {days} jours.")
    print("Ouvrir cette adresse sur l'écran (une seule fois ; le lien n'est plus affiché ensuite) :\n")
    print(f"  {public_url.rstrip('/')}/wall#token={token}\n")
    if not ips:
        print("Conseil : restreindre le jeton à l'adresse IP de l'écran avec --ip.")
    return 0


async def list_display_tokens() -> int:
    await init_db()
    async with sessionmaker()() as db:
        tokens = (await db.scalars(select(DisplayToken).order_by(DisplayToken.id))).all()
    if not tokens:
        print("Aucun jeton d'affichage.")
    now = datetime.now(timezone.utc)
    for t in tokens:
        state = "révoqué" if t.revoked else ("expiré" if t.expires_at <= now else "actif")
        used = t.last_used_at.strftime("%d/%m/%Y %H:%M") if t.last_used_at else "jamais"
        print(f"{t.id:>3}  {state:<8} {t.name:<30} IP : {', '.join(t.allowed_ips) or 'toutes':<20} "
              f"dernier usage : {used} ({t.last_ip or '-'})")
    return 0


async def revoke_display_token(token_id: int) -> int:
    async with sessionmaker()() as db:
        display = await db.get(DisplayToken, token_id)
        if not display:
            print(f"Jeton {token_id} introuvable.")
            return 1
        display.revoked = True
        await record(db, actor="cli", action="display_token_revoke", obj=f"display:{token_id}")
        await db.commit()
    print(f"Jeton {token_id} révoqué : l'écran perd l'accès à son prochain rafraîchissement.")
    return 0


def db_current() -> int:
    from alembic import command

    from minisoc.db import alembic_config
    command.current(alembic_config(), verbose=False)
    return 0


def db_revision(message: str) -> int:
    """Développement : génère une migration à partir des modèles (à relire avant de la versionner)."""
    from alembic import command

    from minisoc.db import alembic_config
    command.revision(alembic_config(), message=message, autogenerate=True)
    return 0


async def repair_harfanglab_cli(dry_run: bool) -> int:
    from minisoc.events_store import EventStore
    from minisoc.repair import repair_harfanglab
    from minisoc.settings_store import store as settings_store

    store = await EventStore.connect()
    async with sessionmaker()() as session:
        cfg = await settings_store.load(session)
    report = await repair_harfanglab(store, cfg, dry_run=dry_run)
    if dry_run:
        print(f"{report['truncated']} alerte(s) HarfangLab au contenu tronqué (essai : rien n'a été modifié).")
    else:
        print(f"{report['repaired']} réparée(s) sur {report['truncated']} ; introuvables dans la console : "
              f"{report['not_found']} ; erreurs : {report['errors']}.")
    return 0 if report["errors"] == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="minisoc")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create-user", help="créer un compte (mot de passe + MFA)")
    p.add_argument("--username", required=True)
    p.add_argument("--role", choices=ROLES, default="analyst")
    p = sub.add_parser("delete-user", help="supprimer un compte (dernier administrateur protégé)")
    p.add_argument("--username", required=True)
    p = sub.add_parser("reset-mfa", help="régénérer la clé MFA d'un compte et le déverrouiller")
    p.add_argument("--username", required=True)
    sub.add_parser("check-rules", help="valider les fichiers de règles")
    sub.add_parser("verify-audit", help="vérifier l'intégrité du journal d'audit")
    p = sub.add_parser("create-display-token", help="créer un jeton d'écran mural (lecture seule)")
    p.add_argument("--name", required=True, help="ex. « Écran bureau informatique »")
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--ip", action="append", default=[], help="IP ou réseau autorisé (répétable)")
    p.add_argument("--show-users", action="store_true", help="afficher les noms de comptes en clair")
    sub.add_parser("list-display-tokens", help="lister les jetons d'écran mural")
    sub.add_parser("db-current", help="version du schéma de la base")
    sub.add_parser("xgs-rules", help="lire les règles du Sophos XGS (lecture seule)")
    p = sub.add_parser("db-revision", help="(développement) générer une migration de schéma")
    p.add_argument("-m", "--message", required=True)
    p = sub.add_parser("revoke-display-token", help="révoquer un jeton d'écran mural")
    p.add_argument("--id", type=int, required=True)
    p = sub.add_parser("repair-harfanglab", help="relire dans HarfangLab les alertes dont le contenu a été tronqué")
    p.add_argument("--dry-run", action="store_true", help="compter seulement, sans rien modifier")
    args = parser.parse_args()

    if args.command == "xgs-rules":
        return asyncio.run(xgs_rules())
    if args.command == "db-current":
        return db_current()
    if args.command == "db-revision":
        return db_revision(args.message)
    if args.command == "create-display-token":
        return asyncio.run(create_display_token(args.name, args.days, args.ip, args.show_users,
                                                get_settings().public_url))
    if args.command == "list-display-tokens":
        return asyncio.run(list_display_tokens())
    if args.command == "revoke-display-token":
        return asyncio.run(revoke_display_token(args.id))
    if args.command == "create-user":
        return asyncio.run(create_user(args.username, args.role))
    if args.command == "delete-user":
        return asyncio.run(delete_user(args.username))
    if args.command == "reset-mfa":
        return asyncio.run(reset_mfa(args.username))
    if args.command == "verify-audit":
        return asyncio.run(verify_audit())
    if args.command == "repair-harfanglab":
        return asyncio.run(repair_harfanglab_cli(args.dry_run))
    return check_rules()


if __name__ == "__main__":
    sys.exit(main())
