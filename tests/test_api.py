# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grundlegende Server-Tests: Sicherheits-Header, CSRF-Schutz, Registrierung mit TOTP, Login,
Ablage nur verschlüsselter Daten und Trennung zwischen Konten.

Aufruf: pip install -r requirements.txt pytest httpx && pytest -q
"""
import base64, os, secrets, sqlite3, sys, tempfile, time

import pyotp
import pytest

TMP = tempfile.mkdtemp()
os.environ.update(APP_SECRET=secrets.token_hex(32), SETUP_TOKEN="setup-test", COOKIE_SECURE="0",
                  DB_PATH=os.path.join(TMP, "test.db"), REQUIRE_APPROVAL="0")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402
import app as server  # noqa: E402

H = {"X-Requested-With": "kopfwetter-app"}
key = lambda: base64.b64encode(secrets.token_bytes(32)).decode()
blob = lambda: {"iv": base64.b64encode(secrets.token_bytes(12)).decode(),
                "ct": base64.b64encode(secrets.token_bytes(48)).decode()}


@pytest.fixture(scope="module")
def client():
    with TestClient(server.app) as c:
        yield c


def register(c, name, setup=""):
    auth, wrapped = key(), blob()
    r = c.post("/api/auth/register/begin", headers=H, json={
        "username": name, "authKey": auth, "setupToken": setup, "consent": True, "wrappedKey": wrapped})
    assert r.status_code == 200, r.text
    totp = pyotp.TOTP(r.json()["secret"])
    f = c.post("/api/auth/register/finish", headers=H, json={"regToken": r.json()["regToken"], "code": totp.now()})
    assert f.status_code == 200, f.text
    return auth, totp, wrapped


def test_health_and_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_csrf_header_required(client):
    r = client.post("/api/auth/salt", json={"username": "irgendwer"})
    assert r.status_code == 403


def test_foreign_origin_rejected(client):
    r = client.post("/api/auth/salt", headers={**H, "Origin": "https://evil.example"}, json={"username": "irgendwer"})
    assert r.status_code == 403


def test_salt_does_not_reveal_accounts(client):
    a = client.post("/api/auth/salt", headers=H, json={"username": "gibtsnicht"}).json()["salt"]
    b = client.post("/api/auth/salt", headers=H, json={"username": "gibtsnicht"}).json()["salt"]
    assert a == b and len(base64.b64decode(a)) == 16


def test_first_account_needs_setup_token(client):
    r = client.post("/api/auth/register/begin", headers=H, json={
        "username": "ohnetoken", "authKey": key(), "consent": True, "wrappedKey": blob()})
    assert r.status_code == 403


def test_full_flow_and_isolation(client):
    auth_a, totp_a, wrapped_a = register(client, "alice", setup="setup-test")
    entry, rid = blob(), secrets.token_hex(16)
    assert client.put("/api/records/" + rid, headers=H, json=entry).status_code == 200
    assert client.get("/api/records").json() == [{"id": rid, **entry}]
    assert client.put("/api/records/2026-11-04", headers=H, json=entry).status_code == 400   # Datum als Kennung abgelehnt
    st = client.post("/api/auth/salt", headers=H, json={"username": "alice"}).json()
    assert st["kdf"]["alg"] == "argon2id" and st["kdf"]["m"] >= 65536

    # Logout, dann Login mit Passwort-Schlüssel und Code aus dem nächsten Zeitfenster
    assert client.post("/api/auth/logout", headers=H).status_code == 204
    assert client.get("/api/records").status_code == 401
    bad = client.post("/api/auth/login", headers=H, json={"username": "alice", "authKey": key(), "code": totp_a.now()})
    assert bad.status_code == 401
    ok = client.post("/api/auth/login", headers=H, json={
        "username": "alice", "authKey": auth_a, "code": totp_a.at(time.time() + 30)})
    assert ok.status_code == 200, ok.text
    assert ok.json()["wrappedKey"] == wrapped_a
    client.post("/api/auth/logout", headers=H)

    # Zweites Konto sieht nichts vom ersten
    register(client, "bob")
    assert client.get("/api/records").json() == []

    # In der Datenbank liegen nur die Chiffrate, die der Client geschickt hat
    con = sqlite3.connect(os.environ["DB_PATH"])
    rows = con.execute("SELECT iv, ct FROM records").fetchall()
    assert rows == [(entry["iv"], entry["ct"])]
    user_cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
    assert "password" not in user_cols and "auth_key" not in user_cols
