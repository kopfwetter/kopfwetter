# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""APP_SECRET-Wechsel über APP_SECRET_PREVIOUS und Abweisen von Datenbanken älterer Versionen.

Jeder Schritt läuft in einem eigenen Prozess, weil app.py seine Konfiguration beim Import liest.
"""
import json, os, secrets, sqlite3, subprocess, sys, tempfile, textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STEP = textwrap.dedent('''
    import base64, json, os, sys, time
    sys.path.insert(0, os.environ["ROOT"])
    import pyotp
    from fastapi.testclient import TestClient
    import app as server
    mode, state = sys.argv[1], json.loads(sys.argv[2] or "{}")
    H = {"X-Requested-With": "kopfwetter-app"}
    with TestClient(server.app) as c:
        if mode == "register":
            auth = base64.b64encode(os.urandom(32)).decode()
            iv, ct = base64.b64encode(os.urandom(12)).decode(), base64.b64encode(os.urandom(48)).decode()
            r = c.post("/api/auth/register/begin", headers=H, json={"username": "alice", "authKey": auth, "setupToken": "s",
                       "consent": True, "wrappedKey": {"iv": iv, "ct": ct}}).json()
            t = pyotp.TOTP(r["secret"])
            assert c.post("/api/auth/register/finish", headers=H, json={"regToken": r["regToken"], "code": t.now()}).status_code == 200
            print(json.dumps({"auth": auth, "secret": r["secret"]}))
        elif mode == "check":
            with server.db() as con:
                tok = con.execute("SELECT totp_secret FROM users WHERE username='alice'").fetchone()[0]
            print(json.dumps({"ok": server.dec_secret(tok) == state["secret"],
                              "primary": server._totp_primary.decrypt(tok.encode()).decode() == state["secret"]}))
        else:
            r = c.post("/api/auth/login", headers=H, json={"username": "alice", "authKey": state["auth"],
                       "code": pyotp.TOTP(state["secret"]).at(time.time() + 30)})
            print(json.dumps({"status": r.status_code}))
''')


def run(env, mode, state=None):
    e = {k: v for k, v in os.environ.items() if k != "APP_SECRET_PREVIOUS"}
    e.update({"ROOT": ROOT, "SETUP_TOKEN": "s", "COOKIE_SECURE": "0", "REQUIRE_APPROVAL": "0", **env})
    return subprocess.run([sys.executable, "-c", STEP, mode, json.dumps(state or {})], env=e, capture_output=True, text=True)


def last(p):
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def test_secret_rotation_keeps_2fa():
    db = os.path.join(tempfile.mkdtemp(), "kopfwetter-app.db")
    a, b, c = (secrets.token_hex(32) for _ in range(3))
    st = last(run({"APP_SECRET": a, "DB_PATH": db}, "register"))

    # Neues Secret, altes als PREVIOUS: alles wird umgeschlüsselt, Login klappt
    p = run({"APP_SECRET": b, "APP_SECRET_PREVIOUS": a, "DB_PATH": db}, "login", st)
    assert last(p) == {"status": 200} and "umgestellt" in p.stdout

    # Ohne PREVIOUS: das alte Secret wird nicht mehr gebraucht
    assert last(run({"APP_SECRET": b, "DB_PATH": db}, "check", st)) == {"ok": True, "primary": True}

    # Falsches Secret: Start bricht ab und ändert nichts
    before = open(db, "rb").read()
    p = run({"APP_SECRET": c, "DB_PATH": db}, "check", st)
    assert p.returncode != 0 and "APP_SECRET_PREVIOUS" in (p.stderr + p.stdout)
    assert open(db, "rb").read() == before


def test_database_of_older_version_is_rejected_unchanged():
    d = tempfile.mkdtemp()
    db = os.path.join(d, "kopfwetter-app.db")
    con = sqlite3.connect(db)  # Datenbank wie aus der Version vor 11/2026: Tabellen, aber keine Protokollkennung
    con.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO meta VALUES ('schema', '3');"
                      "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);")
    con.commit(); con.close()
    before = open(db, "rb").read()
    p = run({"APP_SECRET": secrets.token_hex(32), "DB_PATH": db}, "check", {})
    assert p.returncode != 0 and "Export" in (p.stderr + p.stdout)
    assert open(db, "rb").read() == before
