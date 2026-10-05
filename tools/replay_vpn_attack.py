"""Test de recette : rejoue une attaque de botnet sur le VPN, mêlée à des erreurs d'utilisateurs légitimes.

    python tools/replay_vpn_attack.py --host 127.0.0.1 --port 514

Envoie (en TCP, au format Sophos SFOS) :
  Attaque
  - 10 000 échecs d'authentification SSL VPN / IPsec depuis 200 IP sur 15 comptes  → UC-01, UC-02a, UC-02b
  - une connexion réussie depuis l'une des IP attaquantes                          → UC-03a/b « attaque »
  - une tentative de connexion à l'administration du pare-feu depuis Internet      → UC-10
  Erreurs d'utilisateurs légitimes (historique de connexions réussies simulé quelques jours plus tôt)
  - c.bernard : téléphone qui réessaie un ancien mot de passe depuis son IP habituelle → UC-01 « erreur d'utilisateur »
  - s.petit   : fautes de frappe puis connexion réussie depuis son IP habituelle      → UC-03a/b « erreur d'utilisateur »
  - l.moreau  : mot de passe expiré                                                   → UC-01 « erreur d'utilisateur »
Attendu : une seule alerte par (règle, entité), regroupement au-delà de 3, erreurs d'utilisateurs en sévérité faible.
Les IP utilisées appartiennent aux plages de documentation (RFC 5737) : aucune IP réelle.
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

ACCOUNTS = ["admin", "administrateur", "j.dupont", "m.martin", "compta", "rh", "test", "vpn", "support",
            "accueil", "dg", "informatique", "scanner", "backup", "guest"]
NETWORKS = ["192.0.2.", "198.51.100.", "203.0.113."]

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans les consoles Windows


def attacker_ips(count: int) -> list[str]:
    return [f"{NETWORKS[i % 3]}{(i // 3) % 250 + 1}" for i in range(count)]


def line(status: str, user: str, ip: str, component: str = "SSL VPN", *, days_ago: float = 0,
         reason: str = "") -> str:
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S%z")
    verb = "logged in successfully to" if status == "Successful" else "failed to login to"
    reason_kv = f' reason="{reason}"' if reason else ""
    return (
        f'<30>device_name="XGS-TEST" timestamp="{ts}" log_type="Authentication" log_component="{component}" '
        f'log_subtype="Authentication" severity="Information" status="{status}" user_name="{user}" '
        f'src_ip={ip}{reason_kv} message="User {user} {verb} {component}"\n'
    )


def legitimate_users() -> list[str]:
    lines = []
    # Historique : connexions réussies habituelles quelques jours plus tôt
    lines.append(line("Successful", "c.bernard", "198.51.100.200", days_ago=3))
    lines.append(line("Successful", "s.petit", "203.0.113.200", days_ago=5))
    # c.bernard : son téléphone réessaie l'ancien mot de passe toutes les quelques secondes
    lines += [line("Failed", "c.bernard", "198.51.100.200", reason="Wrong credentials") for _ in range(25)]
    # s.petit : fautes de frappe puis succès
    lines += [line("Failed", "s.petit", "203.0.113.200", reason="Wrong credentials") for _ in range(6)]
    lines.append(line("Successful", "s.petit", "203.0.113.200"))
    # l.moreau : mot de passe expiré, depuis une connexion jamais vue (nouvelle box)
    lines += [line("Failed", "l.moreau", "192.0.2.230", reason="Password expired") for _ in range(22)]
    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--failures", type=int, default=10_000)
    parser.add_argument("--ips", type=int, default=200)
    args = parser.parse_args()

    rng = random.Random(42)
    ips = attacker_ips(args.ips)
    sent = 0
    started = time.monotonic()
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        legit = legitimate_users()
        sock.sendall("".join(legit).encode())
        sent += len(legit)
        batch = []
        for i in range(args.failures):
            component = "IPsec" if i % 5 == 0 else "SSL VPN"
            batch.append(line("Failed", rng.choice(ACCOUNTS), rng.choice(ips), component, reason="Wrong credentials"))
            if len(batch) == 500:
                sock.sendall("".join(batch).encode())
                batch.clear()
        sock.sendall("".join(batch).encode())
        sent += args.failures
        # Mot de passe trouvé : succès depuis une IP attaquante sur un compte visé
        sock.sendall(line("Successful", "j.dupont", ips[7]).encode())
        # Console d'administration exposée sur Internet
        sock.sendall(line("Failed", "admin", "203.0.113.250", "GUI").encode())
        sent += 2
    elapsed = time.monotonic() - started
    print(f"{sent} événements envoyés en {elapsed:.1f} s ({args.ips} IP attaquantes, 3 utilisateurs légitimes).")
    print("Les alertes de seuil apparaissent au plus tard 30 s après la fin de l'envoi.")


if __name__ == "__main__":
    main()
