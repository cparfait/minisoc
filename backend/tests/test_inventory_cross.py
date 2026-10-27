"""Croisement des inventaires NinjaOne, Bitdefender, HarfangLab et AD ; groupe Bitdefender des alertes de couverture."""

from datetime import datetime, timedelta, timezone

from minisoc.coverage import Inventory, add_gravityzone, add_harfanglab, add_ninjaone, gaps, gravityzone_groups
from minisoc.inventory_cross import build

NOW = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
RECENT = NOW.timestamp() - 3600
OLD = NOW.timestamp() - 60 * 86400


def _raw():
    return {
        "ninjaone": [
            {"name": "PC-OK", "class": "WINDOWS_WORKSTATION", "last_contact": RECENT},
            {"name": "PC-FANTOME", "class": "WINDOWS_WORKSTATION", "last_contact": OLD},  # supprimé de l'AD
            {"name": "PC-SANS-EDR", "class": "WINDOWS_WORKSTATION", "last_contact": RECENT},
            {"name": "PC-DOUBLON", "class": "WINDOWS_WORKSTATION", "last_contact": RECENT},
            {"name": "SWITCH-01", "class": "NMS_SWITCH", "last_contact": RECENT},
        ],
        "bitdefender": [
            {"name": "PC-OK.mairie.local", "isManaged": True, "groupId": "g2"},
            {"name": "PC-SANS-EDR", "isManaged": False, "groupId": "g2"},
            {"name": "PC-DOUBLON", "isManaged": False, "groupId": "g1"},
            {"name": "PC-DOUBLON", "isManaged": True, "groupId": "g2"},
            {"name": "PC-FANTOME", "isManaged": True, "groupId": "g1"},
        ],
        "harfanglab": [
            {"hostname": "PC-OK", "lastseen": "2026-10-26T11:00:00Z", "ostype": "windows"},
            {"hostname": "PC-FANTOME", "lastseen": "2026-08-01T11:00:00Z", "ostype": "windows"},
            {"hostname": "PC-DOUBLON", "lastseen": "2026-10-26T11:00:00Z", "ostype": "windows"},
        ],
        "ad": [
            {"name": "PC-OK", "os": "Windows 11", "enabled": True, "last_logon": "2026-10-25T08:00:00+00:00"},
            {"name": "PC-SANS-EDR", "os": "Windows 10", "enabled": True, "last_logon": "2026-10-25T08:00:00+00:00"},
            {"name": "PC-DOUBLON", "os": "Windows 11", "enabled": True, "last_logon": "2026-10-20T08:00:00+00:00"},
            {"name": "PC-DESACTIVE", "os": "Windows 10", "enabled": False, "last_logon": "2025-01-01T00:00:00+00:00"},
            {"name": "PC-JAMAIS-OUTIL", "os": "Windows 10", "enabled": True, "last_logon": "2024-01-01T00:00:00+00:00"},
        ],
    }


def _rows(raw=None):
    result = build(raw or _raw(), {"g1": "Mairie", "g2": "Mairie / Postes"}, NOW)
    return result, {r["name"]: r for r in result["rows"]}


def test_cross_finds_machines_to_clean():
    result, rows = _rows()
    assert "PC-OK" not in rows  # présente partout : rien à faire
    assert "hors_ad" in rows["PC-FANTOME"]["issues"] and not rows["PC-FANTOME"]["ad"]
    assert {"inactif_ninjaone", "inactif_harfanglab"} <= set(rows["PC-FANTOME"]["issues"])
    assert rows["PC-SANS-EDR"]["issues"] == ["absent_harfanglab"]
    assert rows["PC-SANS-EDR"]["bitdefender_state"] == "non géré"
    assert rows["PC-SANS-EDR"]["bitdefender_group"] == "Mairie / Postes"
    assert result["summary"]["hors_ad"] == 2  # PC-FANTOME et SWITCH-01
    assert result["sources"]["ad"] == {"read": True, "count": 5}


def test_cross_duplicates_keep_the_managed_record_and_its_group():
    _, rows = _rows()
    assert rows["PC-DOUBLON"]["issues"] == ["doublon_bitdefender"]
    assert rows["PC-DOUBLON"]["doublons"] == {"bitdefender": 2}
    assert rows["PC-DOUBLON"]["bitdefender_state"] == "géré"
    assert rows["PC-DOUBLON"]["bitdefender_group"] == "Mairie / Postes"


def test_cross_disabled_ad_account_still_in_a_tool():
    raw = _raw()
    raw["harfanglab"].append({"hostname": "PC-DESACTIVE", "lastseen": "2026-10-26T11:00:00Z", "ostype": "windows"})
    _, rows = _rows(raw)
    assert "ad_desactive" in rows["PC-DESACTIVE"]["issues"]
    assert "PC-JAMAIS-OUTIL" not in rows  # ancienne machine de l'AD absente des outils : ni hors AD, ni absence


def test_cross_network_equipment_does_not_need_an_edr():
    _, rows = _rows()
    assert rows["SWITCH-01"]["issues"] == ["hors_ad"]  # ni Bitdefender ni HarfangLab attendus sur un commutateur


def test_cross_unread_source_concludes_nothing():
    raw = _raw()
    raw["ad"] = None  # annuaire illisible
    raw["harfanglab"] = None
    result, rows = _rows(raw)
    assert not any(code in ("hors_ad", "absent_harfanglab") for r in result["rows"] for code in r["issues"])
    assert result["sources"]["ad"]["read"] is False and rows["PC-FANTOME"]["ad"] is False


def test_coverage_gap_carries_the_bitdefender_group():
    inv = Inventory()
    inv.groups = {"g2": "Mairie / Postes"}
    add_ninjaone(inv, [
        {"name": "PC-A", "class": "WINDOWS_WORKSTATION", "last_contact": RECENT},
        {"name": "PC-B", "class": "WINDOWS_WORKSTATION", "last_contact": RECENT},
    ], NOW)
    add_harfanglab(inv, [], NOW)
    add_gravityzone(inv, [{"name": "PC-A", "isManaged": True, "groupId": "g2"}, {"name": "PC-C", "groupId": "inconnu"}])
    inv.ad = {"pc-a", "pc-b"}
    found = gaps(inv, NOW)["UC-59"]
    assert found["pc-a"]["bitdefender_group"] == "Mairie / Postes"
    assert found["pc-b"]["bitdefender_group"] == ""  # absente de GravityZone : pas de groupe
    assert inv.av_groups["pc-c"] == "groupe inconnu"  # groupe non résolu : identifiant


async def test_gravityzone_groups_are_read_as_a_tree():
    calls = []

    class Api:
        async def call(self, path, method, params):
            calls.append(params)
            return {None: [{"id": "g1", "name": "Mairie"}], "g1": [{"id": "g2", "name": "Postes"}], "g2": []}[
                params.get("parentId")]

    assert await gravityzone_groups(Api()) == {"g1": "Mairie", "g2": "Mairie / Postes"}
    assert calls[0] == {}


def test_edr_expected_depends_on_the_perimeter():
    """PC de l'AD : HarfangLab seul ; machine hors AD (école) : Bitdefender seul."""
    raw = {
        "ninjaone": [{"name": n, "class": "WINDOWS_WORKSTATION", "last_contact": RECENT}
                     for n in ("PC-AD", "ECOLE-OK", "ECOLE-SANS-BD")],
        "bitdefender": [{"name": "ECOLE-OK", "isManaged": True, "groupId": "g1"}],  # PC-AD sans Bitdefender : normal
        "harfanglab": [{"hostname": "PC-AD", "lastseen": "2026-10-26T11:00:00Z", "ostype": "windows"}],  # écoles sans HL : normal
        "ad": [{"name": "PC-AD", "os": "Windows 11", "enabled": True, "last_logon": "2026-10-25T08:00:00+00:00"}],
    }
    _, rows = _rows(raw)
    assert "absent_bitdefender" in rows["PC-AD"]["issues"]  # Bitdefender : antivirus de tout le parc
    assert rows["ECOLE-OK"]["issues"] == ["hors_ad"]
    assert "absent_bitdefender" in rows["ECOLE-SANS-BD"]["issues"]
    assert not any(i.startswith("absent_harfanglab") for r in rows.values() for i in r["issues"])
    raw["ad"] = None
    _, rows = _rows(raw)
    assert not any(i.startswith("absent_harfanglab") for r in rows.values() for i in r["issues"])


def test_no_edr_alert_follows_the_perimeter():
    inv = Inventory()
    add_ninjaone(inv, [{"name": n, "class": "WINDOWS_WORKSTATION", "last_contact": RECENT}
                       for n in ("PC-AD", "ECOLE-OK", "ECOLE-SANS-BD")], NOW)
    add_harfanglab(inv, [{"hostname": "PC-AD", "lastseen": "2026-10-26T11:00:00Z", "ostype": "windows"}], NOW)
    add_gravityzone(inv, [{"name": "ECOLE-OK", "isManaged": True}])
    assert gaps(inv, NOW)["UC-59"] == {}  # périmètre inconnu : aucune conclusion
    inv.ad = {"pc-ad"}
    found = gaps(inv, NOW)["UC-59"]
    assert set(found) == {"ecole-sans-bd"} and found["ecole-sans-bd"]["reason"] == "hors AD : absente de GravityZone"
