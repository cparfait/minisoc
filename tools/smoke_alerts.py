"""DÉVELOPPEMENT : contrôle sur la vraie base des filtres d'alertes, des alertes liées et des tickets NinjaOne.

    python tools/smoke_alerts.py [https://localhost]

Lecture seule : aucun ticket n'est créé dans NinjaOne, aucune alerte n'est modifiée. Part des alertes ouvertes : une
alerte qui cite une valeur doit être retrouvée par son filtre, et une valeur voisine ne doit pas la retrouver.
Une valeur absente des alertes ouvertes est signalée « sans objet », sans échec. Aussi lancé par `smoke_api.py`.
"""

from __future__ import annotations

import sys
from urllib.parse import quote

OPEN = "new,in_progress,waiting"
SEARCHES = (("host", "host.name", "machine"), ("account", "user.name", "compte"), ("ip", "source.ip", "IP"))
FINISHED = {"CLOSED", "MISSING"}


def entity_value(entity_key: str, field: str) -> str:
    for part in entity_key.split(" | "):
        name, sep, value = part.partition("=")
        if sep and name == field and value not in ("", "?"):
            return value
    return ""


def check_search(call, check, items: list[dict], param: str, field: str, label: str) -> None:
    alert, value = next(((a, v) for a in items if (v := entity_value(a["entity_key"], field))), (None, ""))
    if alert is None:
        print(f"--  {label} : sans objet (aucune alerte ouverte n'a cette valeur dans son entité)")
        return
    ident, encoded = alert["id"], quote(value, safe="")
    status, found, _ = call("GET", f"/api/alerts?status={OPEN}&{param}={encoded}&sort=recent&limit=200")
    check(f"filtre {label} : retrouve l'alerte qui cite {value}",
          status == 200 and ident in [a["id"] for a in found["items"]], (status, ident))
    status, near, _ = call("GET", f"/api/alerts?status={OPEN}&{param}={encoded}9&sort=recent&limit=200")
    check(f"filtre {label} : valeur voisine sans résultat erroné",
          status == 200 and ident not in [a["id"] for a in near["items"]], (status, ident))

    status, related, _ = call("GET", f"/api/alerts/related?{param}={encoded}")
    match = next((a for a in related.get("items", []) if a["id"] == ident), None) if status == 200 else None
    if status == 200 and match is None and related.get("truncated"):
        print(f"--  alertes liées {label} : sans objet (plus d'alertes que la limite)")
    else:
        check(f"alertes liées {label} : retrouve l'alerte et nomme la valeur",
              match is not None and f"{label} {value}" in match["via"], (status, match and match["via"]))
    status, related, _ = call("GET", f"/api/alerts/related?{param}={encoded}&exclude={ident}")
    check(f"alertes liées {label} : alerte courante exclue",
          status == 200 and ident not in [a["id"] for a in related["items"]], status)


def run(call, check) -> None:
    status, alerts, _ = call("GET", f"/api/alerts?status={OPEN}&sort=recent&limit=200")
    check("alertes ouvertes lisibles", status == 200, status)
    if status != 200:
        return
    items = alerts["items"]
    for param, field, label in SEARCHES:
        check_search(call, check, items, param, field, label)

    status, body, _ = call("GET", "/api/alerts/related")
    check("alertes liées sans valeur : liste vide", status == 200 and body == {"items": [], "truncated": False}, body)
    status, _, _ = call("GET", "/api/alerts?sort=priority&limit=5")
    check("tri par priorité", status == 200, status)

    status, tickets, _ = call("GET", "/api/alerts?ticket=open&status=&sort=recent&limit=200")
    in_progress = status == 200 and all(a["ticket"] and a["ticket"]["status"] not in FINISHED for a in tickets["items"])
    check("filtre « ticket ouvert » : seulement des tickets en cours", in_progress, status)
    status, _, _ = call("GET", "/api/alerts?ticket=autre")
    check("filtre « ticket » : valeur inconnue refusée", status == 422, status)

    status, facets, _ = call("GET", "/api/alerts/facets")
    check("filtres proposés : état des tickets NinjaOne", status == 200 and "tickets" in facets, status)
    if items:
        status, view, _ = call("GET", f"/api/response/ticket/{items[0]['id']}")
        check("texte proposé pour un ticket", status == 200 and view["draft"]["subject"], status)
        if status == 200 and not view["enabled"]:
            status, _, _ = call("POST", "/api/response/ticket",
                                {"alert_id": items[0]["id"], "subject": "Contrôle", "body": "Contrôle"})
            check("tickets désactivés : ouverture refusée", status == 409, status)
        else:
            print("--  ouverture d'un ticket : non testée, les tickets sont activés (ce contrôle n'en crée aucun)")


if __name__ == "__main__":
    import devlib

    if len(sys.argv) > 1:
        devlib.BASE = sys.argv[1]
    failures = 0

    def check(label: str, condition: object, detail: object = "") -> None:
        global failures
        print(f"{'OK ' if condition else 'KO '} {label}" + (f"  ({detail})" if not condition and detail else ""))
        failures += 0 if condition else 1

    devlib.login()
    run(devlib.call, check)
    print(f"\n{'Tous les contrôles sont passés.' if not failures else f'{failures} contrôle(s) en échec.'}")
    sys.exit(1 if failures else 0)
