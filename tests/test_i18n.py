# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Englische Fassung: jeder markierte Text hat eine Übersetzung, die Seite wird nach Sprache ausgeliefert."""
import json, os, re, secrets, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "i18n"))


def js_keys(src: str) -> set[str]:
    """Schlüssel aus $t("…") und $T`…${x}…` (verschachtelte ${…} werden übersprungen)."""
    keys = set()
    for m in re.finditer(r'\$t\("((?:[^"\\]|\\.)*)"\)', src):
        keys.add(json.loads('"' + m.group(1) + '"'))
    i = 0
    while (i := src.find("$T`", i)) >= 0:
        j, parts, cur, n = i + 3, [], "", 0
        while src[j] != "`":
            if src.startswith("${", j):
                parts.append(cur); cur = ""; depth = 1; j += 2
                while depth:
                    depth += {"{": 1, "}": -1}.get(src[j], 0); j += 1
                continue
            if src[j] == "\\":
                cur += {"n": "\n", "r": "\r", "`": "`", "\\": "\\", "$": "$"}.get(src[j + 1], src[j + 1]); j += 2; continue
            cur += src[j]; j += 1
        parts.append(cur)
        keys.add("".join(p + ("{%d}" % k if k < len(parts) - 1 else "") for k, p in enumerate(parts)))
        i = j + 1
    return keys


def test_every_marked_text_is_translated():
    import en_js
    missing = []
    for f in ("static/app.js", "static/report.js"):
        missing += [(f, k) for k in js_keys(open(os.path.join(ROOT, f), encoding="utf-8").read()) if k not in en_js.EN]
    assert not missing, missing[:10]


def test_en_js_is_generated_from_source():
    import en_js
    src = open(os.path.join(ROOT, "static/i18n/en.js"), encoding="utf-8").read()
    data = json.loads(src.split("window.KW_EN = ", 1)[1].split(";\nwindow.KW_EN_PATTERNS", 1)[0])
    assert data == en_js.EN, "static/i18n/en.js ist veraltet: python3 i18n/en_js.py"


def test_server_messages_are_translated():
    import en_js
    src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
    msgs = set(re.findall(r'HTTPException\(\d+,\s*"([^"]+)"', src)) | set(re.findall(r'"detail":\s*"([^"]+)"', src))
    msgs |= set(re.findall(r'rate_limit\([^)]*?"([^"]+)"\)', src))
    assert not [m for m in msgs if m not in en_js.EN]


def test_html_is_fully_translated():
    import i18n_html
    html, missing = i18n_html.translate_html(open(os.path.join(ROOT, "static/index.html"), encoding="utf-8").read(), i18n_html.load("en"), "en")
    assert not missing, missing
    assert '<html lang="en">' in html and "Your mood diary" in html


def test_language_selection():
    os.environ.update(APP_SECRET=secrets.token_hex(32), COOKIE_SECURE="0", DB_PATH=os.path.join(tempfile.mkdtemp(), "t.db"))
    from fastapi.testclient import TestClient
    import app as server
    with TestClient(server.app) as c:
        assert '<html lang="de">' in c.get("/").text
        assert '<html lang="en">' in c.get("/", headers={"Accept-Language": "en-US,en;q=0.9"}).text
        assert '<html lang="de">' in c.get("/", headers={"Accept-Language": "de-DE,de;q=0.9,en;q=0.8"}).text
        assert '<html lang="en">' in c.get("/", headers={"Accept-Language": "fr-FR"}).text
        c.cookies.set("kw-lang", "de")
        assert '<html lang="de">' in c.get("/", headers={"Accept-Language": "en"}).text
        assert "/static/i18n/en.js" in c.get("/app?lang=en").text
        assert "Privacy policy" in c.get("/datenschutz?lang=en").text
        assert "Legal notice" in c.get("/impressum?lang=en").text
        assert "Datenschutzerklärung" in c.get("/datenschutz?lang=de").text


def test_landing_page_and_app_route():
    """/ zeigt die Landingpage (de/en), /app die Web-App; Store-Links nur, wenn gesetzt."""
    import subprocess
    db = os.path.join(tempfile.mkdtemp(), "l.db")
    code = '''
import json
from fastapi.testclient import TestClient
import app as server
c = TestClient(server.app)
r = c.get("/"); a = c.get("/app"); e = c.get("/?lang=en")
print(json.dumps({"root": r.status_code, "landing": "Roadmap" in r.text and 'href="/app"' in r.text, "en": "A mood diary only you can read." in e.text,
  "app": a.status_code, "is_app": 'id="view-app"' in a.text, "play": "play.google.com" in r.text, "soon": "Bald verfügbar" in r.text}))
'''
    e = {**os.environ, "ROOT": ROOT, "APP_SECRET": secrets.token_hex(32), "COOKIE_SECURE": "0", "DB_PATH": db}
    p = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0, p.stderr
    o = json.loads(p.stdout.strip().splitlines()[-1])
    assert o == {"root": 200, "landing": True, "en": True, "app": 200, "is_app": True, "play": False, "soon": True}


def test_web_subdomain_routing():
    """Mit WEB_URL: / auf der Web-Adresse ist die App, sonst die Landingpage; /app leitet um; API auf beiden."""
    import subprocess
    db = os.path.join(tempfile.mkdtemp(), "w.db")
    code = '''
import json
from fastapi.testclient import TestClient
import app as server
c = TestClient(server.app, base_url="https://kopfwetter.test").__enter__()
w = TestClient(server.app, base_url="https://web.kopfwetter.test")
r = c.get("/"); a = c.get("/app?lang=en", follow_redirects=False); wa = w.get("/")
print(json.dumps({"landing": "Roadmap" in r.text and 'href="https://web.kopfwetter.test/"' in r.text,
  "redirect": [a.status_code, a.headers.get("location")], "web_app": 'id="view-app"' in wa.text,
  "manifest": [c.get("/manifest.webmanifest").json()["start_url"], w.get("/manifest.webmanifest").json()["start_url"]],
  "api": w.get("/api/auth/state").json()["links"]["site"]}))
'''
    e = {**os.environ, "ROOT": ROOT, "APP_SECRET": secrets.token_hex(32), "COOKIE_SECURE": "0", "DB_PATH": db,
         "WEB_URL": "https://web.kopfwetter.test", "SITE_URL": "https://kopfwetter.test"}
    p = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0, p.stderr
    o = json.loads(p.stdout.strip().splitlines()[-1])
    assert o == {"landing": True, "redirect": [301, "https://web.kopfwetter.test/?lang=en"], "web_app": True,
                 "manifest": ["/app", "/"], "api": "https://kopfwetter.test"}


def test_addon_info_pages():
    """Add-on-Infoseiten: /addon/<name> und <name>.<ADDON_DOMAIN>; Link zum Einschalten in der App."""
    import subprocess
    db = os.path.join(tempfile.mkdtemp(), "a.db")
    code = '''
import json
from fastapi.testclient import TestClient
import app as server
c = TestClient(server.app, base_url="https://kopfwetter.test").__enter__()
g = TestClient(server.app, base_url="https://gefuehle.kopfwetter.test")
x = TestClient(server.app, base_url="https://unbekannt.kopfwetter.test")
p = c.get("/addon/fragebogen?lang=en"); s = g.get("/")
print(json.dumps({"path": [p.status_code, "Questionnaires" in p.text, "addon=fragebogen" in p.text],
  "sub": [s.status_code, "Gefühle" in s.text, 'href="https://web.kopfwetter.test/?addon=gefuehle"' in s.text],
  "unknown_sub_is_landing": "Roadmap" in x.get("/").text, "missing": c.get("/addon/nix").status_code,
  "landing_links": "https://tabletten.kopfwetter.test/" in c.get("/").text,
  "domain": c.get("/api/auth/state").json()["links"]["addonDomain"]}))
'''
    e = {**os.environ, "ROOT": ROOT, "APP_SECRET": secrets.token_hex(32), "COOKIE_SECURE": "0", "DB_PATH": db,
         "WEB_URL": "https://web.kopfwetter.test", "ADDON_DOMAIN": "kopfwetter.test"}
    p = subprocess.run([sys.executable, "-c", code], env=e, capture_output=True, text=True, cwd=ROOT)
    assert p.returncode == 0, p.stderr
    o = json.loads(p.stdout.strip().splitlines()[-1])
    assert o == {"path": [200, True, True], "sub": [200, True, True], "unknown_sub_is_landing": True, "missing": 404,
                 "landing_links": True, "domain": "kopfwetter.test"}
