"""Authentification AD sur un annuaire simulé (ldap3 MOCK_SYNC) : recherche, bind, comptes désactivés, rôles."""

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from minisoc import ldap_auth
from minisoc.ldap_auth import LdapAuthFailed, LdapConfigError, _ad_reason, authenticate
from minisoc.settings_store import SettingsError, validate

BASE = "OU=Utilisateurs,DC=mairie,DC=local"
SERVICE = "CN=svc-minisoc,OU=Services,DC=mairie,DC=local"
GROUP_ADMIN = "CN=GG-MiniSOC-Admins,OU=Groupes,DC=mairie,DC=local"
GROUP_VIEWER = "CN=GG-MiniSOC-Lecteurs,OU=Groupes,DC=mairie,DC=local"

CFG = {
    "ldap_enabled": True,
    "ldap_url": "ldaps://dc01.mairie.local:636",
    "ldap_bind_dn": SERVICE,
    "ldap_bind_password": "service-secret",
    "ldap_base_dn": BASE,
    "ldap_user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
    "ldap_group_admin": GROUP_ADMIN,
    "ldap_group_analyst": "",
    "ldap_group_viewer": GROUP_VIEWER,
    "ldap_timeout": 5,
}

MEMBERSHIP = {  # appartenance (imbriquée comprise) simulée
    f"CN=Alice Admin,{BASE}": {GROUP_ADMIN, GROUP_VIEWER},
    f"CN=Bob Lecteur,{BASE}": {GROUP_VIEWER},
    f"CN=Carole Sansgroupe,{BASE}": set(),
}


@pytest.fixture
def directory(monkeypatch):
    server = Server("dc01.mairie.local", get_info=OFFLINE_AD_2012_R2)

    def add_entries(conn):
        conn.strategy.add_entry(SERVICE, {"objectClass": "user", "userPassword": "service-secret"})
        for cn, sam, uac, pwd in (
            ("Alice Admin", "alice", 512, "Mot-De-Passe-Alice"),
            ("Bob Lecteur", "bob", 512, "Mot-De-Passe-Bob"),
            ("Carole Sansgroupe", "carole", 512, "Mot-De-Passe-Carole"),
            ("David Desactive", "david", 514, "Mot-De-Passe-David"),
        ):
            conn.strategy.add_entry(f"CN={cn},{BASE}", {
                "objectClass": "user", "sAMAccountName": sam, "displayName": cn, "mail": f"{sam}@mairie.local",
                "userAccountControl": uac, "userPassword": pwd,
            })

    def fake_connect(cfg, user, password):
        conn = Connection(server, user=user, password=password, client_strategy=MOCK_SYNC)
        add_entries(conn)
        return conn

    monkeypatch.setattr(ldap_auth, "_connect", fake_connect)
    monkeypatch.setattr(ldap_auth, "_member_of", lambda conn, dn, group: group in MEMBERSHIP.get(dn, set()))


def test_admin_group_gives_admin_role(directory):
    user = authenticate(CFG, "Alice", "Mot-De-Passe-Alice")
    assert (user.username, user.role, user.email) == ("alice", "admin", "alice@mairie.local")


def test_viewer_group(directory):
    assert authenticate(CFG, "bob", "Mot-De-Passe-Bob").role == "viewer"


def test_wrong_password(directory):
    with pytest.raises(LdapAuthFailed):
        authenticate(CFG, "alice", "mauvais")


def test_no_matching_group_is_refused(directory):
    with pytest.raises(LdapAuthFailed) as exc:
        authenticate(CFG, "carole", "Mot-De-Passe-Carole")
    assert exc.value.reason == "no_group"


def test_disabled_account_is_refused_before_bind(directory):
    with pytest.raises(LdapAuthFailed) as exc:
        authenticate(CFG, "david", "Mot-De-Passe-David")
    assert exc.value.reason == "disabled"


def test_unknown_user(directory):
    with pytest.raises(LdapAuthFailed) as exc:
        authenticate(CFG, "inconnu", "x")
    assert exc.value.reason == "unknown_user"


@pytest.mark.parametrize("username", ["*", "alice)(objectClass=*", "a b", "x" * 65, ""])
def test_ldap_injection_and_invalid_names_rejected(directory, username):
    with pytest.raises(LdapAuthFailed):
        authenticate(CFG, username, "x")


def test_empty_password_never_reaches_directory(monkeypatch):
    monkeypatch.setattr(ldap_auth, "_service_connection", lambda cfg: pytest.fail("annuaire contacté"))
    with pytest.raises(LdapAuthFailed):
        authenticate(CFG, "alice", "")


def test_no_role_group_configured_fails_closed(directory):
    cfg = {**CFG, "ldap_group_admin": "", "ldap_group_viewer": ""}
    with pytest.raises(LdapConfigError):
        authenticate(cfg, "alice", "Mot-De-Passe-Alice")


def test_ad_error_codes():
    message = "80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 532, v3839"
    assert _ad_reason({"message": message}) == "password_expired"
    assert _ad_reason({"message": "data 775"}) == "locked"
    assert _ad_reason({"message": "autre"}) == ""


def test_only_ldaps_is_accepted():
    with pytest.raises(SettingsError, match="LDAPS"):
        validate("ldap_url", "ldap://dc01.mairie.local")
    assert validate("ldap_url", "ldaps://dc01.mairie.local:636")


def test_invalid_ca_certificate_rejected():
    with pytest.raises(SettingsError, match="PEM"):
        validate("ldap_ca_cert", "-----BEGIN CERTIFICATE-----\nnimporte quoi\n-----END CERTIFICATE-----")


def test_user_filter_must_contain_placeholder():
    with pytest.raises(SettingsError):
        validate("ldap_user_filter", "(sAMAccountName=alice)")
