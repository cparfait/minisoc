"""Rapport mensuel : bornes du mois (heure de Paris), mois précédent, rendus Markdown et HTML."""

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from minisoc.reports import last_complete_month, month_bounds, previous_month, render_html, render_markdown

TZ = ZoneInfo("Europe/Paris")


def test_month_bounds_follow_local_time():
    start, end = month_bounds(date(2026, 10, 1), TZ)
    assert start == datetime(2026, 9, 30, 22, 0, tzinfo=timezone.utc)  # 1er octobre 00:00 heure d'été
    assert end == datetime(2026, 10, 31, 23, 0, tzinfo=timezone.utc)  # 1er novembre 00:00 heure d'hiver
    assert month_bounds(date(2026, 12, 1), TZ)[1] == datetime(2026, 12, 31, 23, 0, tzinfo=timezone.utc)


def test_previous_and_last_complete_month():
    assert previous_month(date(2026, 1, 1)) == date(2025, 12, 1)
    assert previous_month(date(2026, 10, 1)) == date(2026, 9, 1)
    assert last_complete_month(datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc), TZ) == date(2026, 9, 1)


def sample():
    return {
        "month": "2026-09", "label": "septembre 2026", "period": {},
        "events": {"total": 1200, "by_module": [{"module": "sophos_xgs", "count": 1000}], "error": ""},
        "alerts": {"total": 12, "previous_total": 8, "by_severity": {"critical": 1, "high": 3, "medium": 8, "low": 0,
                                                                      "info": 0},
                   "by_status": {"resolved": 9, "false_positive": 1, "new": 2}, "by_module": [],
                   "top_rules": [{"rule_id": "UC-01", "name": "Échecs VPN | IP", "count": 7}],
                   "verdicts": {"attaque": 5}, "false_positive_rate": 10, "still_open": 2, "open_now": 3,
                   "time_to_acknowledge_min": {"count": 10, "median": 42, "p90": 300},
                   "time_to_close_min": {"count": 10, "median": 1500, "p90": 4000}},
        "incidents": {"opened": 1, "closed": 1, "items": [{"id": 3, "title": "Botnet <VPN>", "status": "closed",
                                                           "severity": "high", "category": "intrusion",
                                                           "personal_data": False}]},
        "blocks": 4,
        "auth": {"failures": 9000, "successes": 300, "ips": 210, "users": 40, "countries": [],
                 "top_attackers": [{"ip": "203.0.113.7", "country": "NL", "asn": "Hosting", "failures": 900,
                                    "users": 12}]},
    }


def test_render_markdown_summary():
    text = render_markdown(sample())
    assert "# Rapport de sécurité : septembre 2026" in text
    assert "+50 % par rapport au mois précédent (8)" in text
    assert "42 min" in text and "25,0 h" in text
    assert "| 203.0.113.7 | NL | Hosting | 900 | 12 |" in text


def test_render_html_escapes_content():
    page = render_html(sample(), "https://soc.mairie.local")
    assert "<VPN>" not in page and "/reports?month=2026-09" in page
