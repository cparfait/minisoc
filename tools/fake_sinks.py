"""DÉVELOPPEMENT : faux serveur SMTP (sans TLS) et faux récepteur HTTP (ntfy, Teams) qui affichent ce qu'ils reçoivent.

    python tools/fake_sinks.py            # SMTP sur 2525, HTTP sur 8099

Configurer ensuite le Mini-SOC avec smtp_host=host.docker.internal, port 2525, chiffrement « aucun »,
et ntfy_url=http://host.docker.internal:8099.
"""

from __future__ import annotations

import asyncio
import email
import email.policy
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)


async def smtp_session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    def send(line: str) -> None:
        writer.write((line + "\r\n").encode())

    send("220 fake-smtp")
    recipients: list[str] = []
    while not reader.at_eof():
        line = (await reader.readline()).decode(errors="replace").strip()
        verb = line.split(" ")[0].upper()
        if verb in ("EHLO", "HELO"):
            send("250-fake-smtp\r\n250 8BITMIME")
        elif verb == "MAIL":
            recipients = []
            send("250 OK")
        elif verb == "RCPT":
            recipients.append(line.split(":", 1)[1].strip(" <>"))
            send("250 OK")
        elif verb == "DATA":
            send("354 Fin par <CRLF>.<CRLF>")
            await writer.drain()
            data = b""
            while True:
                chunk = await reader.readline()
                if chunk in (b".\r\n", b".\n"):
                    break
                data += chunk
            msg = email.message_from_bytes(data, policy=email.policy.default)
            body = msg.get_body(("plain",))
            print(f"\n=== E-MAIL à {', '.join(recipients)} ===\nSujet : {msg['Subject']}\n"
                  f"{(body.get_content() if body else '')[:1500]}")
            send("250 Reçu")
        elif verb == "QUIT":
            send("221 Au revoir")
            await writer.drain()
            break
        else:
            send("250 OK")
        await writer.drain()
    writer.close()


class Webhook(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.startswith("/webconsole/APIController"):  # faux Sophos XGS (API XML)
            from urllib.parse import parse_qs
            xml = parse_qs(body.decode()).get("reqxml", [""])[0]
            action = re.sub(r"<Login>.*?</Login>", "<Login>…</Login>", xml)
            print(f"\n=== XGS API ===\n{action[:400]}")
            group = "<IPHostGroup><Name>MiniSOC-Blocages</Name></IPHostGroup>" if "<Get>" in xml else ""
            reply = ("<Response><Login><status>Authentication Successful</status></Login>"
                     f"{group}<IPHost><Status code=\"200\">Configuration applied successfully.</Status></IPHost></Response>")
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(reply.encode())
            return
        try:
            data = json.loads(body)
            summary = data.get("title") or json.dumps(data, ensure_ascii=False)[:300]
            extra = f" (sujet {data.get('topic')}, priorité {data.get('priority')})" if "topic" in data else ""
        except ValueError:
            summary, extra = body[:300], ""
        print(f"\n=== HTTP {self.path} ===\n{summary}{extra}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


async def main() -> None:
    Thread(target=ThreadingHTTPServer(("0.0.0.0", 8099), Webhook).serve_forever, daemon=True).start()
    server = await asyncio.start_server(smtp_session, "0.0.0.0", 2525)
    print("SMTP :2525 et HTTP :8099 prêts")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
