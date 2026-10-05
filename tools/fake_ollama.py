"""DÉVELOPPEMENT : faux serveur Ollama (POST /api/chat en NDJSON) pour tester l'assistant IA sans modèle.

    python tools/fake_ollama.py 11435

Répond une analyse factice, en morceaux, et reprend quelques éléments du contexte reçu pour vérifier
qu'il est bien construit (titre de l'alerte, zone de données non fiables).
"""

from __future__ import annotations

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        context = messages[1]["content"] if len(messages) > 1 else ""
        title = next((line for line in context.splitlines() if line.startswith("Titre :")), "Titre : ?")
        untrusted = "<donnees_non_fiables>" in context
        answer = (
            "## Résumé\n"
            f"Alerte analysée ({title.removeprefix('Titre : ')}).\n\n"
            "## Évaluation\n"
            f"**Attaque probable**, confiance moyenne. Contexte délimité comme non fiable : {'oui' if untrusted else 'non'}.\n\n"
            "## Actions recommandées\n"
            "1. Activer la protection contre la force brute sur le XGS.\n"
            "2. Imposer le MFA sur le VPN SSL.\n\n"
            "## À vérifier\n"
            f"- {len(messages) - 1} message(s) reçu(s) dans la conversation.\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()
        for i in range(0, len(answer), 24):
            self.wfile.write((json.dumps({"message": {"content": answer[i:i + 24]}, "done": False}) + "\n").encode())
            self.wfile.flush()
            time.sleep(0.03)
        self.wfile.write((json.dumps({"done": True, "done_reason": "stop", "prompt_eval_count": len(context) // 4,
                                      "eval_count": len(answer) // 4}) + "\n").encode())

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11435
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
