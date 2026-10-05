"""DÉVELOPPEMENT : configure l'assistant sur un Ollama local et lance une vraie analyse d'alerte en flux.

    python tools/dev_ai_check.py [modèle] [n° d'alerte]

Utilise le compte de `.dev-credentials.json` (admin). Ollama doit être joignable depuis le conteneur api
(Docker Desktop : http://host.docker.internal:11434).
"""

from __future__ import annotations

import json
import sys
import time

from devlib import OPENER, call, login

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

MODEL = sys.argv[1] if len(sys.argv) > 1 else "gemma4:26b-a4b-it-qat"


def main() -> None:
    login()
    status, body, _ = call("PUT", "/api/admin/settings/ai", {
        "ai_enabled": True, "ai_provider": "ollama", "ai_base_url": "http://host.docker.internal:11434",
        "ai_model": MODEL, "ai_max_tokens": 4000,
    })
    print("Paramètres IA :", status, body.get("changed"))

    alert_id = int(sys.argv[2]) if len(sys.argv) > 2 else None
    if alert_id is None:
        _, alerts, _ = call("GET", "/api/alerts?status=new,in_progress&severity_min=critical&limit=50")
        alert_id = next(a["id"] for a in alerts["items"] if a["rule_id"].startswith("UC-03"))
    print(f"Analyse de l'alerte n° {alert_id} avec {MODEL}…\n")

    import urllib.request
    req = urllib.request.Request(
        "https://localhost/api/ai/alerts/%d/analyze" % alert_id, data=json.dumps({"messages": []}).encode(),
        headers={"Content-Type": "application/json", "X-MiniSOC": "1"}, method="POST",
    )
    started = time.monotonic()
    first = None
    with OPENER.open(req, timeout=600) as res:
        for raw in res:
            line = raw.decode().strip()
            if not line.startswith("data: "):
                continue
            event = json.loads(line[6:])
            if event["type"] == "text":
                first = first or time.monotonic() - started
                print(event["text"], end="", flush=True)
            elif event["type"] != "start":
                print(f"\n[{event['type']}] {json.dumps(event, ensure_ascii=False)}")
    print(f"\nPremier mot après {first or 0:.1f} s, total {time.monotonic() - started:.1f} s")


if __name__ == "__main__":
    main()
