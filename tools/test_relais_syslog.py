"""Test de recette du relais syslog de minisoc-update, sur une VM DE TEST : aucun journal perdu pendant la mise à jour.

    python tools/test_relais_syslog.py --host <IP de la VM de test> --duree 600

Envoie en continu, en UDP et en TCP vers le port 514, des messages numérotés (10 par seconde et par protocole) portant
un marqueur unique, pendant que `sudo minisoc-update …` tourne sur la VM. Le TCP se reconnecte tout seul, comme un
équipement réel ; un message dont l'envoi TCP a échoué est réessayé après reconnexion. À la fin, le script affiche
les recherches à lancer dans le Mini-SOC (Recherche) et le nombre attendu pour chaque protocole.

Prérequis sur la VM de test : le poste qui lance le script est déclaré dans les sources syslog UDP et TCP
(sudo minisoc-setup › Entrants) et l'intégration « Syslog générique » est active (Intégrations).
"""

from __future__ import annotations

import argparse
import socket
import time
import uuid


def tcp_connect(host: str, port: int) -> socket.socket | None:
    try:
        return socket.create_connection((host, port), timeout=3)
    except OSError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True, help="adresse de la VM de test (jamais la production)")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--duree", type=int, default=600, help="durée d'envoi en secondes (couvrir toute la mise à jour)")
    parser.add_argument("--debit", type=int, default=10, help="messages par seconde et par protocole")
    args = parser.parse_args()

    marker = f"relais-{uuid.uuid4().hex[:8]}"
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = tcp_connect(args.host, args.port)
    sent = {"udp": 0, "tcp": 0}
    reconnects = 0
    print(f"Marqueur : {marker} ; envoi pendant {args.duree} s. Lancer maintenant la mise à jour sur la VM de test.")
    end = time.monotonic() + args.duree
    n = 0
    while time.monotonic() < end:
        n += 1
        tick = time.monotonic()
        for proto in ("udp", "tcp"):
            line = f"<134>minisoc-test: {marker} {proto} n={n}"
            if proto == "udp":
                udp.sendto(line.encode(), (args.host, args.port))
                sent["udp"] += 1
                continue
            for _ in range(30):  # TCP : réessai après reconnexion, comme un équipement qui garde ses messages
                if tcp is None:
                    time.sleep(1)
                    tcp = tcp_connect(args.host, args.port)
                    reconnects += tcp is not None
                    continue
                try:
                    tcp.sendall((line + "\n").encode())
                    sent["tcp"] += 1
                    break
                except OSError:
                    tcp.close()
                    tcp = None
        if n % (args.debit * 30) == 0:
            print(f"  {time.strftime('%H:%M:%S')} : {sent['udp']} UDP, {sent['tcp']} TCP envoyés ({reconnects} reconnexion(s))")
        time.sleep(max(0.0, 1 / args.debit - (time.monotonic() - tick)))
    if tcp is not None:
        tcp.close()
    print(f"\nEnvoyés : {sent['udp']} en UDP, {sent['tcp']} en TCP ; {reconnects} reconnexion(s) TCP.")
    print("Attendre 1 minute, puis dans le Mini-SOC > Recherche (période : 1 h) :")
    print(f"  {marker} udp | count  -> attendu {sent['udp']}")
    print(f"  {marker} tcp | count  -> attendu {sent['tcp']}")
    print("Un écart en UDP pendant la bascule = relais inopérant ; voir /var/log/minisoc-update.log sur la VM.")


if __name__ == "__main__":
    main()
