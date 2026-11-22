# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Demo-Modus: Wegwerf-Konten, gesperrte Endpunkte, automatisches Löschen, Schutz echter Datenbanken."""
import json, os, secrets, sqlite3, subprocess, sys, tempfile, textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEP = textwrap.dedent('''
    import base64, json, os, sys
    sys.path.insert(0, os.environ["ROOT"])
    from fastapi.testclient import TestClient
    import app as server
    H = {"X-Requested-With": "kopfwetter-app"}
    key = lambda: base64.b64encode(os.urandom(32)).decode()
    blob = lambda: {"iv": base64.b64encode(os.urandom(12)).decode(), "ct": base64.b64encode(os.urandom(48)).decode()}
    out = {}
    with TestClient(server.app) as c:
        out["state"] = c.get("/api/auth/state").json()["demo"]
        out["no_consent"] = c.post("/api/demo/start", headers=H, json={"username": "demo-abcdefghij", "authKey": key(), "wrappedKey": blob()}).status_code
        out["bad_name"] = c.post("/api/demo/start", headers=H, json={"username": "admin", "authKey": key(), "wrappedKey": blob(), "consent": True}).status_code
        r = c.post("/api/demo/start", headers=H, json={"username": "demo-abcdefghij", "authKey": key(), "wrappedKey": blob(), "consent": True})
        out["start"] = r.status_code; out["until"] = r.json().get("until")
        out["put"] = c.put("/api/records/" + "ab" * 16, headers=H, json=blob()).status_code
        out["blocked"] = {p: c.post(p, headers=H, json={}).status_code for p in ("/api/auth/login", "/api/auth/register/begin", "/api/account/delete")}
        with server.db() as con:  # Konto künstlich altern lassen, dann aufräumen
            con.execute("UPDATE users SET created_at='2000-01-01T00:00:00+00:00'")
            out["deleted"] = server.cleanup_demo(con)
            out["left"] = [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("users", "records", "sessions")]
        r = c.post("/api/demo/start", headers=H, json={"username": "demo-zzzzzzzzzz", "authKey": key(), "wrappedKey": blob(), "consent": True})
        out["end"] = c.post("/api/demo/end", headers=H).status_code
        with server.db() as con:
            out["after_end"] = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    print(json.dumps(out))
''')


def run(db, extra=None):
    e = {**os.environ, "ROOT": ROOT, "APP_SECRET": secrets.token_hex(32), "COOKIE_SECURE": "0", "DB_PATH": db, "DEMO_MODE": "1", **(extra or {})}
    return subprocess.run([sys.executable, "-c", STEP], env=e, capture_output=True, text=True)


def test_demo_flow():
    p = run(os.path.join(tempfile.mkdtemp(), "demo.db"))
    assert p.returncode == 0, p.stderr
    o = json.loads(p.stdout.strip().splitlines()[-1])
    assert o["state"]["hours"] == 24
    assert o["no_consent"] == 400 and o["bad_name"] == 400 and o["start"] == 200 and o["until"]
    assert o["put"] == 200
    assert set(o["blocked"].values()) == {403}
    assert o["deleted"] == 1 and o["left"] == [0, 0, 0]
    assert o["end"] == 204 and o["after_end"] == 0


def test_demo_refuses_database_with_real_accounts():
    db = os.path.join(tempfile.mkdtemp(), "echt.db")
    con = sqlite3.connect(db)
    con.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO meta VALUES ('protocol', 'kopfwetter-app/v1');"
                      "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT); INSERT INTO users (username) VALUES ('toddi');")
    con.commit(); con.close()
    p = run(db)
    assert p.returncode != 0 and "echte Konten" in (p.stderr + p.stdout)
    assert sqlite3.connect(db).execute("SELECT username FROM users").fetchall() == [("toddi",)]
