from datetime import datetime, timezone

import pyotp
import pytest

from minisoc.audit import GENESIS, compute_hash
from minisoc.crypto import CryptoError, decrypt, encrypt
from minisoc.security import hash_password, password_problems, verify_password, verify_totp


def test_password_hashing():
    h = hash_password("correct horse battery staple")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "mauvais")
    assert not verify_password(None, "peu importe")


def test_password_policy():
    assert password_problems("court") != []
    assert password_problems("alice-est-super-2026", "alice") == ["ne doit pas contenir l'identifiant"]
    assert password_problems("Vraiment-Long-Et-Varie-42") == []


def test_totp_valid_once_only():
    secret = pyotp.random_base32()
    now = 1_790_000_000.0
    code = pyotp.TOTP(secret).at(now)
    step = verify_totp(secret, code, last_step=0, now=now)
    assert step is not None
    assert verify_totp(secret, code, last_step=step, now=now) is None  # rejeu refusé
    wrong = "000000" if code != "000000" else "111111"
    assert verify_totp(secret, wrong, 0, now=now) is None
    assert verify_totp(secret, "abc", 0, now=now) is None


def test_secret_encryption_roundtrip():
    token = encrypt("JBSWY3DPEHPK3PXP")
    assert token.startswith("v1:") and "JBSWY3DPEHPK3PXP" not in token
    assert decrypt(token) == "JBSWY3DPEHPK3PXP"


def test_wrong_master_key_rejected():
    with pytest.raises(CryptoError):
        encrypt("x", master_key="trop-court")


def test_audit_hash_chain_detects_tampering():
    ts = datetime(2026, 10, 1, tzinfo=timezone.utc)
    h1 = compute_hash(GENESIS, ts, "alice", "10.0.0.1", "login", "auth", {})
    h2 = compute_hash(h1, ts, "alice", "10.0.0.1", "alert_update", "alert:1", {"status": ["new", "resolved"]})
    forged = compute_hash(h1, ts, "alice", "10.0.0.1", "alert_update", "alert:1", {"status": ["new", "false_positive"]})
    assert h2 != forged and len(h2) == 64


def test_wall_masks_user_names():
    from minisoc.api.wall import mask_name

    assert mask_name("j.dupont") == "j.d*****"
    assert mask_name("rh") == "r**"
    assert "dupont" not in mask_name("j.dupont")
