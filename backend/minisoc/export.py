"""Export vers un SIEM ou un SOC externe (syslog RFC 5424, JSON ECS ou CEF ; TCP, UDP ou TLS).

Les alertes (créées ou escaladées) et, si demandé, les événements normalisés sont mis dans une file d'attente
bornée : une cible lente ou injoignable ne ralentit jamais le traitement des journaux (les messages en surplus
sont comptés comme perdus). Réglages : Intégrations › Export SIEM / SOC.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from datetime import datetime, timezone

from minisoc.ecs import SEVERITY_BY_NAME, Event, severity_name

log = logging.getLogger(__name__)

STATUS_KEY = "minisoc:export:status"
QUEUE_SIZE = 20_000
APP = "minisoc"
CEF_VENDOR, CEF_PRODUCT, CEF_VERSION = "Ville de Chatillon", "Mini-SOC", "1.0"


def configured(cfg: dict) -> bool:
    return bool(cfg.get("export_enabled") and cfg.get("export_host"))


# ---------- Formats ----------


def _cef_header(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_ext(value) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def cef(signature: str, name: str, severity: int, ext: dict) -> str:
    """CEF : sévérité 0-10 (Mini-SOC 0-4 → 0, 3, 5, 8, 10)."""
    sev = {0: 0, 1: 3, 2: 5, 3: 8, 4: 10}.get(int(severity), 5)
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v not in (None, "", 0))
    return (
        f"CEF:0|{_cef_header(CEF_VENDOR)}|{_cef_header(CEF_PRODUCT)}|{CEF_VERSION}|{_cef_header(signature)}|"
        f"{_cef_header(name)}|{sev}|{extension}"
    )


def _ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def format_alert(alert: dict, fmt: str) -> str:
    """`alert` : alerte sérialisée (API) avec `url`."""
    sample = alert.get("sample") or {}
    if fmt == "cef":
        return cef(
            alert["rule_id"],
            alert["title"],
            SEVERITY_BY_NAME.get(alert["severity"], 2),
            {
                "rt": _ms(datetime.fromisoformat(alert["last_seen"])),
                "cat": "alert",
                "cs1Label": "rule",
                "cs1": alert["rule_name"],
                "cs2Label": "entity",
                "cs2": alert["entity_key"],
                "cs3Label": "status",
                "cs3": alert["status"],
                "cn1Label": "count",
                "cn1": alert["count"],
                "externalId": alert["id"],
                "src": sample.get("source.ip"),
                "suser": sample.get("user.name"),
                "dhost": sample.get("host.name"),
                "request": alert.get("url"),
            },
        )
    return json.dumps(
        {
            "@timestamp": alert["last_seen"],
            "event": {
                "kind": "alert",
                "module": ",".join(alert.get("modules") or []),
                "severity": alert["severity"],
                "start": alert["first_seen"],
                "end": alert["last_seen"],
            },
            "rule": {"id": alert["rule_id"], "name": alert["rule_name"]},
            "message": alert["title"],
            "source": {"ip": sample.get("source.ip")} if sample.get("source.ip") else None,
            "user": {"name": sample.get("user.name")} if sample.get("user.name") else None,
            "host": {"name": sample.get("host.name")} if sample.get("host.name") else None,
            "minisoc": {
                "alert_id": alert["id"],
                "status": alert["status"],
                "count": alert["count"],
                "entity": alert["entity_key"],
                "priority": alert.get("priority"),
                "url": alert.get("url"),
            },
        },
        ensure_ascii=False,
        default=str,
    )


def format_event(ev: Event, fmt: str) -> str:
    if fmt == "cef":
        return cef(
            ev.action or ev.category or "event",
            ev.message[:200] or ev.rule_name or "événement",
            ev.severity,
            {
                "rt": _ms(ev.ts),
                "cat": ev.category,
                "act": ev.action,
                "outcome": ev.outcome,
                "src": ev.source_ip,
                "spt": ev.source_port,
                "dst": ev.destination_ip,
                "dpt": ev.destination_port,
                "suser": ev.user_name,
                "dhost": ev.host_name,
                "app": ev.network_service,
                "cs1Label": "module",
                "cs1": ev.module,
                "cs2Label": "rule",
                "cs2": ev.rule_name,
                "fname": ev.file_path,
                "externalId": ev.event_id,
            },
        )
    doc = {"@timestamp": ev.ts.isoformat()}
    for name, value in ev.ecs().items():
        if value in ("", 0, None) or name == "@timestamp":
            continue
        target = doc
        *parents, last = name.split(".")
        for p in parents:
            target = target.setdefault(p, {})
        target[last] = value.isoformat() if isinstance(value, datetime) else value
    doc.setdefault("event", {})["severity_name"] = severity_name(ev.severity)
    return json.dumps(doc, ensure_ascii=False, default=str)


def syslog_line(message: str, severity: int, hostname: str, now: datetime | None = None) -> str:
    """RFC 5424, facilité local4 (20) ; gravité syslog déduite de la sévérité Mini-SOC."""
    syslog_sev = {0: 6, 1: 5, 2: 4, 3: 3, 4: 2}.get(int(severity), 5)
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f"<{20 * 8 + syslog_sev}>1 {stamp} {hostname} {APP} - - - {message}"


def frame(line: str, protocol: str) -> bytes:
    """TCP/TLS : comptage d'octets (RFC 6587) ; UDP : datagramme borné."""
    data = line.encode("utf-8")
    if protocol == "udp":
        return data[:8000]
    return f"{len(data)} ".encode() + data


# ---------- Envoi ----------


class Exporter:
    def __init__(self, redis) -> None:
        self.redis = redis
        self.queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.cfg: dict = {}
        self.dropped = 0
        self.sent = 0

    def update(self, cfg: dict) -> None:
        self.cfg = cfg

    @property
    def scope(self) -> str:
        return str(self.cfg.get("export_scope") or "alerts")

    def _put(self, message: str, severity: int) -> None:
        try:
            self.queue.put_nowait((message, severity))
        except asyncio.QueueFull:
            self.dropped += 1

    def alert(self, alert: dict) -> None:
        if not configured(self.cfg):
            return
        minimum = SEVERITY_BY_NAME.get(str(self.cfg.get("export_min_severity") or "low"), 1)
        if SEVERITY_BY_NAME.get(alert["severity"], 2) >= minimum:
            self._put(
                format_alert(alert, str(self.cfg.get("export_format") or "json")),
                SEVERITY_BY_NAME.get(alert["severity"], 2),
            )

    def events(self, events: list[Event]) -> None:
        if configured(self.cfg) and self.scope == "both":
            fmt = str(self.cfg.get("export_format") or "json")
            for ev in events:
                self._put(format_event(ev, fmt), ev.severity)

    async def _open(self):
        host, port = str(self.cfg["export_host"]), int(self.cfg.get("export_port") or 514)
        protocol = str(self.cfg.get("export_protocol") or "tcp")
        if protocol == "udp":
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(host, port))
            return protocol, transport, None
        context = None
        if protocol == "tls":
            context = ssl.create_default_context()
            if not self.cfg.get("export_tls_verify", True):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context), timeout=10)
        return protocol, None, writer

    async def run(self) -> None:
        """Vide la file vers la cible ; reconnexion avec attente croissante en cas d'échec."""
        delay = 1
        while True:
            message, severity = await self.queue.get()
            if not configured(self.cfg):
                continue
            try:
                protocol, transport, writer = await self._open()
                hostname = str(self.cfg.get("export_hostname") or "minisoc")
                batch = [(message, severity)]
                while True:
                    for msg, sev in batch:
                        data = frame(syslog_line(msg, sev, hostname), protocol)
                        if transport:
                            transport.sendto(data)
                        else:
                            writer.write(data)
                    if writer:
                        await writer.drain()
                    self.sent += len(batch)
                    await self._status(ok=True)
                    delay = 1
                    batch = [await self.queue.get()]
                    while not self.queue.empty() and len(batch) < 500:
                        batch.append(self.queue.get_nowait())
                    if not configured(self.cfg):
                        break
            except Exception as exc:  # noqa: BLE001 - la cible peut être injoignable : on réessaie plus tard
                await self._status(ok=False, error=f"{type(exc).__name__} : {str(exc)[:200]}")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60)

    async def _status(self, ok: bool, error: str = "") -> None:
        status = {
            "at": time.time(),
            "ok": ok,
            "error": error,
            "sent": self.sent,
            "dropped": self.dropped,
            "queued": self.queue.qsize(),
        }
        try:
            await self.redis.set(STATUS_KEY, json.dumps(status), ex=86400)
        except Exception as exc:  # noqa: BLE001 - l'état est informatif, l'export continue
            log.debug("état de l'export non enregistré : %s", exc)


async def send_test(cfg: dict) -> tuple[bool, str]:
    """Message de test, envoi direct (bouton Tester)."""
    exporter = Exporter(None)
    exporter.update({**cfg, "export_enabled": True})
    try:
        protocol, transport, writer = await exporter._open()
        line = syslog_line(
            json.dumps({"message": "Test d'export du Mini-SOC", "event": {"kind": "test"}})
            if cfg.get("export_format") != "cef"
            else cef("test", "Test d'export du Mini-SOC", 0, {}),
            0,
            str(cfg.get("export_hostname") or "minisoc"),
        )
        data = frame(line, protocol)
        if transport:
            transport.sendto(data)
            transport.close()
        else:
            writer.write(data)
            await writer.drain()
            writer.close()
        return True, f"Message de test envoyé à {cfg.get('export_host')}:{cfg.get('export_port') or 514} ({protocol})"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__} : {str(exc)[:300]}"


def alert_payload(alert, public_url: str) -> dict:
    """Alerte (modèle) → dictionnaire exporté."""
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": severity_name(alert.severity),
        "title": alert.title,
        "entity_key": alert.entity_key,
        "status": alert.status,
        "count": alert.count,
        "modules": alert.modules,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "sample": (alert.details or {}).get("sample") or {},
        "url": f"{public_url.rstrip('/')}/alerts/{alert.id}",
    }
