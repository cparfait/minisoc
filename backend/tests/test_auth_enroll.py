"""Enrôlement MFA : le mot de passe seul ne suffit pas, il faut une fenêtre de 24 h ouverte par un admin."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from minisoc.api import auth
from minisoc.crypto import encrypt
from minisoc.models import AuthChallenge, User
from minisoc.security import hash_password, new_session_token, new_totp_secret

IP = "192.168.3.1"
PASSWORD = "Correct-horse-battery-staple-42"


class FakeDb:
    def __init__(self, user: User, challenge: AuthChallenge | None = None):
        self.user, self.challenge = user, challenge
        self.added = []

    async def get(self, model, key, **kw):
        return {User: self.user, AuthChallenge: self.challenge}.get(model)

    async def scalar(self, stmt):
        return self.user

    async def execute(self, stmt):
        return None

    def add(self, obj):
        self.added.append(obj)

    async def delete(self, obj):
        pass

    async def commit(self):
        pass

    async def flush(self):
        pass


@pytest.fixture
def audited(monkeypatch):
    actions = []

    async def record(db, *, action, **kw):
        actions.append(action)

    monkeypatch.setattr(auth.audit, "record", record)
    monkeypatch.setattr(auth, "_attempts_by_ip", auth.defaultdict(auth.deque))
    return actions


def _request(cookies: str = "") -> Request:
    headers = [(b"cookie", cookies.encode())] if cookies else []
    return Request({"type": "http", "client": (IP, 50000), "headers": headers})


def _local_user(**kw) -> User:
    return User(**{"id": 1, "username": "secours", "auth_source": "local", "password_hash": hash_password(PASSWORD),
                   "totp_secret_enc": "", "totp_last_step": 0, "active": True, **kw})


async def _login(user: User):
    return await auth.login(auth.LoginRequest(username=user.username, password=PASSWORD), _request(), Response(),
                            FakeDb(user))


async def test_enrollment_refused_without_admin_window(audited):
    with pytest.raises(HTTPException) as exc:
        await _login(_local_user())
    assert exc.value.status_code == 403 and "administrateur" in exc.value.detail
    assert audited == ["mfa_enroll_refused"]


async def test_enrollment_refused_after_window_expired(audited):
    with pytest.raises(HTTPException) as exc:
        await _login(_local_user(mfa_enroll_until=datetime.now(timezone.utc) - timedelta(minutes=1)))
    assert exc.value.status_code == 403


async def test_enrollment_offered_inside_window(audited):
    result = await _login(_local_user(mfa_enroll_until=datetime.now(timezone.utc) + timedelta(hours=23)))
    assert result["step"] == "enroll" and result["secret"]


async def test_enrolled_user_goes_straight_to_totp(audited):
    assert await _login(_local_user(totp_secret_enc=encrypt(new_totp_secret()))) == {"step": "totp"}


async def test_verify_rejects_enrollment_once_window_closed(audited):
    """Fenêtre retirée par un admin entre l'étape 1 et la saisie du code : l'enrôlement n'aboutit pas."""
    user = _local_user(mfa_enroll_until=None)
    token, token_hash = new_session_token()
    challenge = AuthChallenge(id=token_hash, user_id=1, kind="enroll", pending_secret_enc=encrypt(new_totp_secret()),
                              attempts=0, ip=IP, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    with pytest.raises(HTTPException) as exc:
        await auth.verify(auth.VerifyRequest(code="123456"), _request(f"{auth.CHALLENGE_COOKIE}={token}"), Response(),
                          FakeDb(user, challenge))
    assert exc.value.status_code == 401 and "expirée" in exc.value.detail
    assert not user.totp_secret_enc
