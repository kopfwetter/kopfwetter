# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Kopfwetter (Stimmungstagebuch) – selbst gehostet, mehrere Konten, 2-Faktor-Login, Ende-zu-Ende-Verschlüsselung.

Schlüssel (auf dem Gerät, siehe static/app.js und docs/CRYPTO.md), pro Konto:
    master  = PBKDF2-SHA256(Passwort, Salt des Kontos, 600 000 Runden)
    authKey = HKDF(master, "kopfwetter-app/auth/v1") -> geht an den Server, dort nur als Argon2id-Hash
    KEK     = HKDF(master, "kopfwetter-app/kek/v1")  -> packt den zufälligen Datenschlüssel (DEK) ein
    DEK     = 32 Zufallsbytes, AES-256-GCM für alle Inhalte; der Server speichert ihn nur eingepackt

Der Server – und damit auch Admins – kennt weder Passwörter noch Klartext-Einträge.
Registrierung: Benutzername + Passwort + Pflicht-2FA. Neue Konten sind (standardmäßig) erst nach Freigabe
durch einen Admin nutzbar. Das erste Konto wird mit SETUP_TOKEN angelegt und ist Admin.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from typing import Literal, Optional
from urllib.parse import urlparse

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import i18n_html
import landing
import legal

# ---------------------------------------------------------------- Konfiguration
env = os.environ.get
DB_PATH = env("DB_PATH", "/data/kopfwetter-app.db")
APP_SECRET = env("APP_SECRET", "")
# Nur während eines Schlüsselwechsels setzen: das bisherige APP_SECRET. Beim Start werden alle TOTP-Geheimnisse
# auf das neue APP_SECRET umgeschlüsselt, danach kann die Zeile wieder aus der .env entfernt werden.
APP_SECRET_PREVIOUS = env("APP_SECRET_PREVIOUS", "")
SETUP_TOKEN = env("SETUP_TOKEN", "")
COOKIE_SECURE = env("COOKIE_SECURE", "1") != "0"
SESSION_HOURS = int(env("SESSION_HOURS", "12"))
TOTP_ISSUER = env("TOTP_ISSUER", "Kopfwetter")
REGISTRATION_OPEN = env("REGISTRATION_OPEN", "1") != "0"
REQUIRE_APPROVAL = env("REQUIRE_APPROVAL", "1") != "0"
MAX_USERS = int(env("MAX_USERS", "50"))
MAX_PENDING = int(env("MAX_PENDING", "20"))
PENDING_DAYS = int(env("PENDING_DAYS", "14"))
TRUSTED_IP_HEADER = env("TRUSTED_IP_HEADER", "cf-connecting-ip").lower()
PRIVACY_URL = env("PRIVACY_URL", "/datenschutz")
IMPRINT_URL = env("IMPRINT_URL", "/impressum")
BLOG_URL = env("BLOG_URL", "")
DEMO_URL = env("DEMO_URL", "")   # echte Instanz: Link zur Demo, z. B. https://demo.kopfwetter.app
APP_URL = env("APP_URL", "")     # Demo-Instanz: Link zurück zur echten App, z. B. https://kopfwetter.app
# Eigene Adresse für die Web-App, z. B. https://web.kopfwetter.app (gleicher Container, im Tunnel auf denselben Dienst zeigen).
# Dort zeigt / die App; auf allen anderen Adressen zeigt / die Landingpage und /app leitet zur Web-Adresse um.
# Ohne WEB_URL liegt die App unter /app.
WEB_URL = env("WEB_URL", "").strip().rstrip("/")
WEB_HOST = urlparse(WEB_URL).netloc.lower() if WEB_URL.startswith("https://") else ""
SITE_URL = env("SITE_URL", "").strip().rstrip("/")
# Infoseiten der Add-ons auf eigenen Subdomains, z. B. ADDON_DOMAIN=kopfwetter.app -> gefuehle.kopfwetter.app.
# Ohne ADDON_DOMAIN liegen sie unter /addon/<name>.
ADDON_DOMAIN = env("ADDON_DOMAIN", "").strip().lower().strip(".")   # Landingpage für den Link „Über Kopfwetter“, z. B. https://kopfwetter.app
NATIVE_ORIGINS = [o.strip() for o in env("NATIVE_ORIGINS", "capacitor://localhost,https://localhost").split(",") if o.strip()]
NATIVE_SESSION_HOURS = int(env("NATIVE_SESSION_HOURS", "168"))
# Demo-Instanz: jeder Besucher bekommt ein eigenes Wegwerf-Konto ohne Anmeldung, das nach DEMO_HOURS gelöscht wird.
# Nur auf einer eigenen Instanz mit eigener Datenbank betreiben, nie zusammen mit echten Konten.
DEMO_MODE = env("DEMO_MODE", "0") == "1"
DEMO_HOURS = int(env("DEMO_HOURS", "24"))
DEMO_MAX = int(env("DEMO_MAX", "200"))
DEMO_USER_RE = re.compile(r"^demo-[a-z0-9]{10}$")
if DEMO_MODE:
    SESSION_HOURS = min(SESSION_HOURS, DEMO_HOURS)
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
COOKIE = "__Host-kopfwetter-app" if COOKIE_SECURE else "kopfwetter-app"
CSRF_HEADER = "kopfwetter-app"
# Kennung des Protokolls (Schlüsselableitung, Formate). Datenbanken älterer Versionen haben keine und werden abgewiesen.
PROTOCOL = "kopfwetter-app/v2"
PROTOCOL_V1 = "kopfwetter-app/v1"   # wird beim Start auf v2 gehoben; Inhalte stellt der Browser beim nächsten Login um
# Schlüsselableitung aus dem Passwort (im Browser). Neue Passwörter bekommen immer KDF_DEFAULT.
KDF_DEFAULT = {"alg": "argon2id", "m": 65536, "t": 3, "p": 1}
KDF_V1 = {"alg": "pbkdf2-sha256", "i": 600_000}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
USERNAME_HINT = "Benutzername: 3–32 Zeichen, nur a–z, 0–9, Punkt, Unterstrich und Bindestrich."

if len(APP_SECRET) < 32:
    sys.exit("APP_SECRET fehlt oder ist kürzer als 32 Zeichen. Erzeugen mit: openssl rand -hex 32")

if APP_SECRET_PREVIOUS and APP_SECRET_PREVIOUS == APP_SECRET:
    sys.exit("APP_SECRET_PREVIOUS ist gleich APP_SECRET. Erzeuge ein neues APP_SECRET: openssl rand -hex 32")


def _totp_key(prefix: bytes, secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(prefix + secret.encode()).digest()))


# Verschlüsselt die TOTP-Geheimnisse in der Datenbank. Der erste Schlüssel verschlüsselt, beide entschlüsseln.
_totp_primary = _totp_key(b"kopfwetter-app/totp/v1:", APP_SECRET)
_fernet = MultiFernet([_totp_primary] + ([_totp_key(b"kopfwetter-app/totp/v1:", APP_SECRET_PREVIOUS)] if APP_SECRET_PREVIOUS else []))
_ph = PasswordHasher()  # Argon2id, 64 MiB, t=3
_DUMMY_HASH = _ph.hash(secrets.token_bytes(32))  # gleiche Rechenzeit für unbekannte Benutzernamen


# ---------------------------------------------------------------- Datenbank
@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA secure_delete=ON")
    try:
        yield con
        con.commit()
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()


def now() -> int:
    return int(time.time())


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def mget(con, key, default=None):
    r = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r[0] if r else default


def mset(con, key, value):
    con.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def table_exists(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    kdf_salt TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    totp_last_step INTEGER NOT NULL DEFAULT -1,
    recovery TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled')),
    is_admin INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login TEXT,
    consent_at TEXT,
    consent_version TEXT,
    wrapped_key TEXT NOT NULL,
    kdf TEXT NOT NULL,
    recovery_auth_hash TEXT,
    recovery_wrapped TEXT,
    recovery_created TEXT
);
CREATE TABLE IF NOT EXISTS registrations (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consent_at TEXT,
    wrapped_key TEXT NOT NULL,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
);
-- Alle Inhalte (Einträge, Tests, Medikamente, Einnahmen, Notizen, Krisenplan) liegen hier.
-- id = HMAC des Inhaltsschlüssels über Art und Kennung: Der Server sieht weder Art noch Datum.
CREATE TABLE IF NOT EXISTS records (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    iv TEXT NOT NULL,
    ct TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
);
"""


def rotate_totp_secrets(con) -> int:
    """Schlüsselt alle TOTP-Geheimnisse auf den aktuellen Schlüssel um. Bricht ab, wenn eines nicht lesbar ist."""
    rows = [("users", "id", r["id"], r["totp_secret"]) for r in con.execute("SELECT id, totp_secret FROM users")]
    rows += [("registrations", "token_hash", r["token_hash"], r["totp_secret"]) for r in con.execute("SELECT token_hash, totp_secret FROM registrations")]
    changed = 0
    for table, key, ident, token in rows:
        try:
            _totp_primary.decrypt(token.encode())
            continue  # schon mit dem aktuellen Schlüssel
        except InvalidToken:
            pass
        try:
            new = _fernet.rotate(token.encode()).decode()
        except InvalidToken:
            sys.exit("Ein TOTP-Geheimnis lässt sich weder mit APP_SECRET noch mit APP_SECRET_PREVIOUS lesen. "
                     "Ist APP_SECRET_PREVIOUS das bisherige APP_SECRET? Es wurde nichts geändert.")
        con.execute(f"UPDATE {table} SET totp_secret=? WHERE {key}=?", (new, ident))
        changed += 1
    return changed


OLD_DB_HINT = ("Diese Datenbank stammt aus einer Version vor 11/2026 (Kennungen „stimmung/…“). "
               "Sie lässt sich mit dieser Version nicht öffnen. Umzug: in der alten Version unter Sicherheit "
               "„Alles exportieren (JSON)“, hier ein neues Konto anlegen und die Datei importieren (README, „Umzug per Export“).")


def check_data_dir():
    """Klare Meldung statt Traceback, wenn der Datenordner fehlt oder nicht beschreibbar ist (häufig nach einem Umzug)."""
    d = os.path.dirname(os.path.abspath(DB_PATH))
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        sys.exit(f"Datenordner {d} lässt sich nicht anlegen: {e.strerror}.")
    target = DB_PATH if os.path.exists(DB_PATH) else d
    if not os.access(target, os.W_OK) or not os.access(d, os.W_OK | os.X_OK):
        st = os.stat(target)
        sys.exit(f"Keine Schreibrechte auf {target} (gehört UID {st.st_uid}, die App läuft als UID {os.getuid()}). "
                 f"Auf dem Server im App-Verzeichnis: sudo chown -R {os.getuid()}:{os.getgid()} data "
                 "– bei Podman rootless stattdessen ./data:/data:U in compose.yaml.")


LEGACY_TABLES = ("entries", "assessments", "items")


def drop_empty_legacy_tables(con):
    """Löscht die v1-Tabellen, sobald kein Konto mehr Daten darin hat."""
    for t in LEGACY_TABLES:
        if table_exists(con, t) and not con.execute(f"SELECT 1 FROM {t} LIMIT 1").fetchone():
            con.execute(f"DROP TABLE {t}")


def init_db():
    check_data_dir()
    with db() as con:
        if table_exists(con, "users") or table_exists(con, "entries"):
            if not table_exists(con, "meta") or mget(con, "protocol") not in (PROTOCOL, PROTOCOL_V1):
                sys.exit(OLD_DB_HINT)   # vor jeder Änderung an der Datei
        con.execute("PRAGMA journal_mode=WAL")
        if DEMO_MODE and table_exists(con, "users") and con.execute(
                "SELECT 1 FROM users WHERE username NOT LIKE 'demo-%'").fetchone():
            sys.exit("DEMO_MODE=1, aber die Datenbank enthält echte Konten. Die Demo braucht eine eigene, leere Datenbank, "
                     "weil sie Konten automatisch löscht.")
        upgrade_v1 = mget(con, "protocol") == PROTOCOL_V1 if table_exists(con, "meta") else False
        con.executescript(SCHEMA)
        if upgrade_v1:
            # v1 -> v2: Konten behalten ihre PBKDF2-Ableitung bis zum nächsten Login. Die alten Tabellen bleiben,
            # bis der Browser jedes Konto umgestellt hat (/api/legacy), und werden dann gelöscht.
            if "kdf" not in [r[1] for r in con.execute("PRAGMA table_info(users)")]:
                con.execute("ALTER TABLE users ADD COLUMN kdf TEXT")
            con.execute("UPDATE users SET kdf=? WHERE kdf IS NULL", (json.dumps(KDF_V1),))
            mset(con, "protocol", PROTOCOL)
            print("Datenbank auf Protokoll v2 gehoben. Inhalte werden beim nächsten Login im Browser umgestellt.", flush=True)
        drop_empty_legacy_tables(con)
        if mget(con, "protocol") is None:
            mset(con, "protocol", PROTOCOL)
            if os.path.exists(os.path.join(os.path.dirname(DB_PATH) or ".", "stimmung.db")):
                print("Hinweis: Neben der neuen Datenbank liegt eine alte stimmung.db. Sie wird nicht verwendet. " + OLD_DB_HINT, flush=True)
        n = rotate_totp_secrets(con)
        if n:
            print(f"{n} TOTP-Geheimnis(se) auf den aktuellen Schlüssel umgestellt.", flush=True)
        if APP_SECRET_PREVIOUS:
            print("APP_SECRET-Wechsel abgeschlossen. Entferne APP_SECRET_PREVIOUS jetzt aus der .env und starte neu.", flush=True)
    gaps = legal.missing()
    if gaps:
        print("Hinweis: Für Impressum und Datenschutzerklärung fehlen in der .env: " + ", ".join(gaps), flush=True)


# ---------------------------------------------------------------- Schutz vor Massenanfragen
class Limiter:
    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: int) -> bool:
        t = time.monotonic()
        q = self.hits[key]
        while q and q[0] < t - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(t)
        if len(self.hits) > 10_000:  # Speicher begrenzen
            for k in [k for k, v in self.hits.items() if not v][:5000]:
                del self.hits[k]
        return True


limiter = Limiter()


def client_ip(request: Request) -> str:
    if TRUSTED_IP_HEADER and request.headers.get(TRUSTED_IP_HEADER):
        return request.headers[TRUSTED_IP_HEADER].strip()
    return request.client.host if request.client else "?"


def rate_limit(request: Request, bucket: str, limit: int, window: int, text: str):
    if not limiter.allow(f"{bucket}:{client_ip(request)}", limit, window):
        raise HTTPException(429, text)


# ---------------------------------------------------------------- Bausteine
def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def norm_username(u: str) -> Optional[str]:
    u = (u or "").strip().lower()
    return u if USERNAME_RE.match(u) else None


def derived_salt(username: str) -> str:
    """Salt für neue/unbekannte Namen. Bekannte und unbekannte Namen sehen gleich aus (kein Ausforschen)."""
    return base64.b64encode(hmac.new(APP_SECRET.encode(), b"salt:" + username.encode(), hashlib.sha256).digest()[:16]).decode()


def parse_key(s: str) -> bytes:
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        raw = b""
    if len(raw) != 32:
        raise HTTPException(400, "Ungültige Anfrage.")
    return raw


def verify_hash(h: str, raw: bytes) -> bool:
    try:
        return _ph.verify(h, raw)
    except (VerificationError, InvalidHashError):
        return False


def enc_secret(secret: str) -> str:
    return _fernet.encrypt(secret.encode()).decode()


def dec_secret(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()


def totp_step(secret: str, code: str, last_step: int) -> Optional[int]:
    code = (code or "").replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    step = now() // 30
    for s in (step - 1, step, step + 1):  # ±30 s Uhrabweichung
        if s > last_step and hmac.compare_digest(totp.at(s * 30), code):
            return s  # derselbe Code funktioniert kein zweites Mal
    return None


_RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def make_recovery_codes() -> tuple[list[str], str]:
    codes = ["".join(secrets.choice(_RC_ALPHABET) for _ in range(10)) for _ in range(10)]
    return [c[:5] + "-" + c[5:] for c in codes], json.dumps([sha(c) for c in codes])


def check_second_factor(con, user, code: str) -> tuple[bool, Optional[int]]:
    """Prüft TOTP oder Wiederherstellungscode und verbraucht ihn. -> (ok, verbleibende Codes oder None)"""
    step = totp_step(dec_secret(user["totp_secret"]), code, user["totp_last_step"])
    if step is not None:
        con.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, user["id"]))
        return True, None
    norm = (code or "").upper().replace("-", "").replace(" ", "")
    if len(norm) == 10:
        h = sha(norm)
        remaining = json.loads(user["recovery"])
        for x in remaining:
            if hmac.compare_digest(x, h):
                remaining.remove(x)
                con.execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(remaining), user["id"]))
                return True, len(remaining)
    return False, None


def check_user_lock(user):
    if now() < user["locked_until"]:
        mins = (user["locked_until"] - now()) // 60 + 1
        raise HTTPException(429, f"Zu viele Fehlversuche. Bitte in {mins} Minuten noch einmal versuchen.")


def record_fail(con, user_id: int):
    r = con.execute("SELECT fail_count FROM users WHERE id=?", (user_id,)).fetchone()
    n = (r[0] if r else 0) + 1
    if n >= MAX_FAILS:
        con.execute("UPDATE users SET fail_count=0, locked_until=? WHERE id=?", (now() + LOCK_SECONDS, user_id))
    else:
        con.execute("UPDATE users SET fail_count=? WHERE id=?", (n, user_id))
    con.commit()  # Fehlversuch bleibt gezählt, auch wenn danach eine Exception kommt


def qr_data_uri(text: str) -> str:
    svg = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2).to_string()
    if isinstance(svg, str):
        svg = svg.encode()
    return "data:image/svg+xml;base64," + base64.b64encode(svg).decode()


def otpauth_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def is_native(request: Request) -> bool:
    """Anfrage aus der iOS-/Android-App (Capacitor). Die App nutzt Bearer-Tokens statt Cookies."""
    origin = request.headers.get("origin")
    return request.headers.get("x-client") == "native" and (origin is None or origin in NATIVE_ORIGINS)


def new_session(con, request: Request, response: Response, user_id: int) -> Optional[str]:
    """Legt eine Sitzung an. Web: HttpOnly-Cookie. App: Token in der Antwort (liegt in Keychain/Keystore)."""
    token = secrets.token_urlsafe(32)
    native = is_native(request)
    hours = NATIVE_SESSION_HOURS if native else SESSION_HOURS
    con.execute("DELETE FROM sessions WHERE expires < ?", (now(),))
    con.execute("INSERT INTO sessions VALUES (?, ?, ?)", (sha(token), user_id, now() + hours * 3600))
    con.execute("UPDATE users SET last_login=? WHERE id=?", (utcnow(), user_id))
    if native:
        return token
    response.set_cookie(COOKIE, token, max_age=hours * 3600, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return None


def request_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and is_native(request):
        return auth[7:].strip() or None
    if request.headers.get("origin") in NATIVE_ORIGINS:
        return None  # App-Anfragen nie per Cookie
    return request.cookies.get(COOKIE)


def session_user(con, request: Request):
    tok = request_token(request)
    if not tok:
        return None
    return con.execute(
        "SELECT u.*, s.token_hash FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=? AND s.expires>? AND u.status='active'",
        (sha(tok), now()),
    ).fetchone()


def current_user(request: Request) -> dict:
    with db() as con:
        u = session_user(con, request)
    if not u:
        raise HTTPException(401, "Nicht angemeldet.")
    return dict(u)


def current_admin(user: dict = Depends(current_user)) -> dict:
    if not user["is_admin"]:
        raise HTTPException(403, "Nur für Admins.")
    return user


def demo_until(created_at: str) -> str:
    return (dt.datetime.fromisoformat(created_at) + dt.timedelta(hours=DEMO_HOURS)).isoformat(timespec="seconds")


def cleanup_demo(con) -> int:
    """Löscht abgelaufene Demo-Konten samt Daten (Einträge, Tests, Items und Sitzungen über ON DELETE CASCADE)."""
    if not DEMO_MODE:
        return 0
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=DEMO_HOURS)).isoformat(timespec="seconds")
    return con.execute("DELETE FROM users WHERE username LIKE 'demo-%' AND created_at < ?", (cutoff,)).rowcount


def cleanup(con):
    cleanup_demo(con)
    con.execute("DELETE FROM registrations WHERE expires < ?", (now(),))
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=PENDING_DAYS)).isoformat(timespec="seconds")
    con.execute("DELETE FROM users WHERE status='pending' AND created_at < ?", (cutoff,))


# ---------------------------------------------------------------- App
@asynccontextmanager
async def lifespan(_app):
    init_db()
    task = asyncio.create_task(demo_janitor()) if DEMO_MODE else None
    yield
    if task:
        task.cancel()


async def demo_janitor():
    while True:
        try:
            with db() as con:
                cleanup_demo(con)
                con.execute("DELETE FROM sessions WHERE expires < ?", (now(),))
        except Exception as e:  # Aufräumen darf die App nie beenden
            print(f"Demo-Aufräumen fehlgeschlagen: {e}", flush=True)
        await asyncio.sleep(600)


app = FastAPI(title="Kopfwetter", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# In der Demo gibt es keine Passwörter, keine 2FA und keine Verwaltung: Konten entstehen nur über /api/demo/start.
DEMO_BLOCKED = {"/api/auth/register/begin", "/api/auth/register/finish", "/api/auth/login", "/api/auth/change-password",
                "/api/auth/recover/begin", "/api/auth/recover/finish", "/api/account/recovery", "/api/account/delete",
                "/api/admin/users"}

CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    origin = request.headers.get("origin")
    app_origin = origin in NATIVE_ORIGINS
    cors = {
        "Access-Control-Allow-Origin": origin or "",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Requested-With, X-Client",
        "Access-Control-Max-Age": "600",
        "Vary": "Origin",
    } if (app_origin and path.startswith("/api/")) else {}
    if DEMO_MODE and path in DEMO_BLOCKED:
        return JSONResponse({"detail": "In der Demo nicht verfügbar."}, status_code=403, headers=cors)
    if request.method == "OPTIONS" and path.startswith("/api/"):
        return Response(status_code=204 if cors else 403, headers=cors)
    if path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        # CSRF: eigener Header (erzwingt CORS-Preflight) + Origin muss zum Host passen (oder die App sein)
        if request.headers.get("x-requested-with") != CSRF_HEADER:
            return JSONResponse({"detail": "Ungültige Anfrage."}, status_code=403, headers=cors)
        if origin and not app_origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "Ungültige Herkunft."}, status_code=403)
    resp = await call_next(request)
    h = resp.headers
    for k, v in cors.items():
        h[k] = v
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if COOKIE_SECURE:
        h["Strict-Transport-Security"] = "max-age=31536000"
    if path.startswith("/api/") or path in ("/", "/app", "/datenschutz", "/impressum"):
        h["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        # mit Versionsangabe: dauerhaft cachen; ohne: jedes Mal beim Server nachfragen
        h["Cache-Control"] = "public, max-age=31536000, immutable" if request.query_params.get("v") == ASSET_VERSION else "no-cache"
    return resp


def _asset_version() -> str:
    """Prüfsumme aller Dateien in static/: ändert sich mit jedem Update, damit Browser und Cloudflare nie alte Skripte nutzen."""
    h = hashlib.sha256()
    for base, _, files in sorted(os.walk(STATIC)):
        for f in sorted(files):
            p = os.path.join(base, f)
            h.update(p.encode())
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()[:12]


ASSET_VERSION = _asset_version()


def versioned(html: str) -> str:
    for asset in ("/static/app.css", "/static/landing.css", "/static/app.js", "/static/vendor/argon2.umd.min.js", "/static/i18n.js", "/static/i18n/en.js"):
        html = html.replace(f'"{asset}"', f'"{asset}?v={ASSET_VERSION}"')
    return html


LANGS = ("de", "en")


def request_lang(request: Request) -> str:
    """Sprache: ?lang=, dann Cookie kw-lang (Umschalter), dann Accept-Language; sonst Deutsch."""
    for v in (request.query_params.get("lang"), request.cookies.get("kw-lang")):
        if v in LANGS:
            return v
    prefs = []
    for i, item in enumerate(request.headers.get("accept-language", "").split(",")):
        tag, _, q = item.strip().partition(";q=")
        try:
            prefs.append((-float(q or 1), i, tag.strip().lower()[:2]))
        except ValueError:
            continue
    for _, _, tag in sorted(prefs):
        if tag in LANGS:
            return tag
    return "en" if any(t for _, _, t in prefs) else "de"   # andere Sprachen: eher Englisch als Deutsch


with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as _f:
    _INDEX_SRC = _f.read()
INDEX_HTML = {"de": versioned(_INDEX_SRC)}
_en_src, _en_missing = i18n_html.translate_html(_INDEX_SRC, i18n_html.load("en"), "en")
INDEX_HTML["en"] = versioned(_en_src.replace(
    '<script src="/static/i18n.js" defer></script>',
    '<script src="/static/i18n/en.js" defer></script>\n<script src="/static/i18n.js" defer></script>'))
if _en_missing:
    print("Hinweis: In der englischen Oberfläche fehlen Übersetzungen für: " + "; ".join(_en_missing[:10]), flush=True)


def is_web_host(request: Request) -> bool:
    return bool(WEB_HOST) and request.headers.get("host", "").lower() == WEB_HOST


def app_page(request: Request) -> HTMLResponse:
    return HTMLResponse(INDEX_HTML[request_lang(request)], headers={"Vary": "Cookie, Accept-Language"})


def web_app_url(lang_param: str | None) -> str:
    q = "?lang=" + lang_param if lang_param in LANGS else ""
    return (WEB_URL + "/" if WEB_HOST else "/app") + q


def addon_slug(request: Request) -> str | None:
    """<name>.<ADDON_DOMAIN> zeigt die Infoseite des Add-ons."""
    host = request.headers.get("host", "").lower().split(":")[0]
    if not ADDON_DOMAIN or not host.endswith("." + ADDON_DOMAIN):
        return None
    sub = host[: -len(ADDON_DOMAIN) - 1]
    return sub if sub in landing.ADDON_INFO else None


@app.get("/addon/{slug}", include_in_schema=False, response_class=HTMLResponse)
def addon_page(slug: str, request: Request):
    if slug not in landing.ADDON_INFO:
        raise HTTPException(404, "Nicht gefunden.")
    return HTMLResponse(versioned(landing.addon_html(slug, request_lang(request), web_app_url(request.query_params.get("lang")))),
                        headers={"Vary": "Cookie, Accept-Language"})


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
def home(request: Request):
    """Web-Adresse (WEB_URL): die App. Sonst die Landingpage; eine Demo-Instanz zeigt gleich die App."""
    if is_web_host(request):
        return app_page(request)
    slug = addon_slug(request)
    if slug:
        return HTMLResponse(versioned(landing.addon_html(slug, request_lang(request), web_app_url(request.query_params.get("lang")))),
                            headers={"Vary": "Cookie, Accept-Language"})
    if DEMO_MODE:
        return RedirectResponse(web_app_url(request.query_params.get("lang")), status_code=302)
    return HTMLResponse(versioned(landing.landing_html(request_lang(request), web_app_url(request.query_params.get("lang")))),
                        headers={"Vary": "Cookie, Accept-Language"})


@app.get("/app", include_in_schema=False, response_class=HTMLResponse)
def index(request: Request):
    """Ohne WEB_URL die App; mit WEB_URL eine dauerhafte Umleitung dorthin (alte Lesezeichen)."""
    if WEB_HOST and not is_web_host(request):
        return RedirectResponse(web_app_url(request.query_params.get("lang")), status_code=301)
    return app_page(request)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(os.path.join(STATIC, "icons", "favicon.ico"), media_type="image/x-icon", headers={"Cache-Control": "public, max-age=604800"})


with open(os.path.join(STATIC, "manifest.webmanifest"), encoding="utf-8") as _f:
    _MANIFEST = json.load(_f)


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifest(request: Request):
    # Startadresse dort, wo die App auf diesem Host liegt
    m = {**_MANIFEST, "start_url": "/" if is_web_host(request) else "/app"}
    return JSONResponse(m, media_type="application/manifest+json")


@app.get("/datenschutz", include_in_schema=False, response_class=HTMLResponse)
def privacy_page(request: Request):
    return HTMLResponse(versioned(legal.privacy_html(request_lang(request))), headers={"Vary": "Cookie, Accept-Language"})


@app.get("/impressum", include_in_schema=False, response_class=HTMLResponse)
def imprint_page(request: Request):
    return HTMLResponse(versioned(legal.imprint_html(request_lang(request))), headers={"Vary": "Cookie, Accept-Language"})


@app.get("/healthz", include_in_schema=False)
def health():
    return {"ok": True}


# ---------------------------------------------------------------- Status & Salt
@app.get("/api/auth/state")
def auth_state(request: Request):
    with db() as con:
        has_users = con.execute("SELECT 1 FROM users").fetchone() is not None
        u = session_user(con, request)
    return {
        "needsSetup": not has_users,
        "setupEnabled": bool(SETUP_TOKEN),
        "registrationOpen": REGISTRATION_OPEN,
        "requireApproval": REQUIRE_APPROVAL,
        "user": {"username": u["username"], "isAdmin": bool(u["is_admin"]),
                 "consentCurrent": u["consent_version"] == legal.PRIVACY_VERSION} if u else None,
        "kdf": KDF_DEFAULT,
        "links": {"privacy": PRIVACY_URL, "imprint": IMPRINT_URL, "blog": BLOG_URL, "demo": DEMO_URL, "app": APP_URL, "site": SITE_URL, "addonDomain": ADDON_DOMAIN},
        "privacyVersion": legal.PRIVACY_VERSION,
        "demo": {"hours": DEMO_HOURS, "until": demo_until(u["created_at"]) if u else None} if DEMO_MODE else None,
    }


class SaltReq(BaseModel):
    username: str = Field(max_length=64)


@app.post("/api/auth/salt")
def salt(b: SaltReq, request: Request):
    rate_limit(request, "salt", 60, 900, "Zu viele Anfragen. Bitte warte ein paar Minuten.")
    u = norm_username(b.username)
    if not u:
        raise HTTPException(400, USERNAME_HINT)
    with db() as con:
        r = con.execute("SELECT kdf_salt, kdf FROM users WHERE username=?", (u,)).fetchone()
    return {"salt": r[0] if r else derived_salt(u), "kdf": json.loads(r[1]) if r and r[1] else KDF_DEFAULT}


# ---------------------------------------------------------------- Registrierung
class Sealed(BaseModel):
    iv: str = Field(min_length=16, max_length=16)
    ct: str = Field(min_length=24, max_length=140_000)


class RegBegin(BaseModel):
    username: str = Field(max_length=64)
    authKey: str = Field(max_length=64)
    setupToken: str = Field("", max_length=200)
    consent: bool = False
    wrappedKey: Sealed   # Datenschlüssel, verpackt mit dem aus dem Passwort abgeleiteten Schlüssel


class RegFinish(BaseModel):
    regToken: str = Field(max_length=100)
    code: str = Field(max_length=20)


@app.post("/api/auth/register/begin")
def register_begin(b: RegBegin, request: Request):
    u = norm_username(b.username)
    if not u:
        raise HTTPException(400, USERNAME_HINT)
    raw = parse_key(b.authKey)
    if not b.consent:
        raise HTTPException(400, "Bitte bestätige die Einwilligung zur Speicherung deiner Gesundheitsdaten.")
    with db() as con:
        cleanup(con)
        first = con.execute("SELECT 1 FROM users").fetchone() is None
        if first:
            if not SETUP_TOKEN:
                raise HTTPException(403, "Für das erste Konto (Admin) muss SETUP_TOKEN in der .env gesetzt sein.")
            rate_limit(request, "setup", 10, 3600, "Zu viele Versuche. Bitte warte eine Stunde.")
            if not hmac.compare_digest(b.setupToken.encode(), SETUP_TOKEN.encode()):
                raise HTTPException(403, "Der Einrichtungscode stimmt nicht.")
        else:
            if not REGISTRATION_OPEN:
                raise HTTPException(403, "Die Registrierung ist derzeit geschlossen.")
            rate_limit(request, "register", 5, 3600, "Zu viele Registrierungen von dieser Adresse. Bitte versuch es später noch einmal.")
            total = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            pending = con.execute("SELECT COUNT(*) FROM users WHERE status='pending'").fetchone()[0]
            if total >= MAX_USERS or (REQUIRE_APPROVAL and pending >= MAX_PENDING):
                raise HTTPException(503, "Im Moment können keine neuen Konten angelegt werden.")
        taken = con.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone() or con.execute(
            "SELECT 1 FROM registrations WHERE username=? AND expires>?", (u, now())).fetchone()
        if taken:
            raise HTTPException(409, "Dieser Benutzername ist schon vergeben.")
        token = secrets.token_urlsafe(32)
        secret = pyotp.random_base32()
        con.execute(
            "INSERT INTO registrations (token_hash, username, kdf_salt, auth_hash, totp_secret, consent_at, wrapped_key, expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (sha(token), u, derived_salt(u), _ph.hash(raw), enc_secret(secret), utcnow(), seal_json(b.wrappedKey), now() + 15 * 60),
        )
    return {"regToken": token, "secret": secret, "qr": qr_data_uri(otpauth_uri(secret, u))}


@app.post("/api/auth/register/finish")
def register_finish(b: RegFinish, request: Request, response: Response):
    with db() as con:
        reg = con.execute("SELECT * FROM registrations WHERE token_hash=? AND expires>?", (sha(b.regToken), now())).fetchone()
        if not reg:
            raise HTTPException(400, "Die Registrierung ist abgelaufen. Bitte fang noch einmal an.")
        step = totp_step(dec_secret(reg["totp_secret"]), b.code, -1)
        if step is None:
            if reg["attempts"] >= 4:
                con.execute("DELETE FROM registrations WHERE token_hash=?", (reg["token_hash"],))
                con.commit()
                raise HTTPException(400, "Zu viele falsche Codes. Bitte fang noch einmal an.")
            con.execute("UPDATE registrations SET attempts=attempts+1 WHERE token_hash=?", (reg["token_hash"],))
            con.commit()
            raise HTTPException(401, "Der Code stimmt nicht. Prüfe die Uhrzeit auf dem Handy und nimm den nächsten Code.")
        if con.execute("SELECT 1 FROM users WHERE username=?", (reg["username"],)).fetchone():
            raise HTTPException(409, "Dieser Benutzername ist schon vergeben.")
        first = con.execute("SELECT 1 FROM users").fetchone() is None
        status = "active" if (first or not REQUIRE_APPROVAL) else "pending"
        codes, codes_json = make_recovery_codes()
        cur = con.execute(
            "INSERT INTO users (username, kdf_salt, auth_hash, totp_secret, totp_last_step, recovery, status, is_admin, created_at, consent_at, consent_version, wrapped_key, kdf)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (reg["username"], reg["kdf_salt"], reg["auth_hash"], reg["totp_secret"], step, codes_json, status, int(first), utcnow(),
             reg["consent_at"], legal.PRIVACY_VERSION, reg["wrapped_key"], json.dumps(KDF_DEFAULT)),
        )
        con.execute("DELETE FROM registrations WHERE token_hash=?", (reg["token_hash"],))
        token = new_session(con, request, response, cur.lastrowid) if status == "active" else None
    return {"status": status, "isAdmin": first, "username": reg["username"], "recoveryCodes": codes, "token": token}


# ---------------------------------------------------------------- Demo
class DemoStart(BaseModel):
    username: str = Field(max_length=20)
    authKey: str = Field(max_length=64)
    wrappedKey: Sealed
    consent: bool = False


@app.post("/api/demo/start")
def demo_start(b: DemoStart, request: Request, response: Response):
    if not DEMO_MODE:
        raise HTTPException(404, "Nicht gefunden.")
    if not DEMO_USER_RE.match(b.username):
        raise HTTPException(400, "Ungültige Anfrage.")
    if not b.consent:
        raise HTTPException(400, "Bitte bestätige, dass du keine echten Daten eingibst.")
    rate_limit(request, "demo", 10, 3600, "Zu viele Demo-Konten von dieser Adresse. Bitte versuch es später noch einmal.")
    raw = parse_key(b.authKey)
    with db() as con:
        cleanup_demo(con)
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= DEMO_MAX:
            raise HTTPException(503, "Die Demo ist gerade voll. Bitte versuch es später noch einmal.")
        if con.execute("SELECT 1 FROM users WHERE username=?", (b.username,)).fetchone():
            raise HTTPException(409, "Bitte noch einmal versuchen.")
        cur = con.execute(
            "INSERT INTO users (username, kdf_salt, auth_hash, totp_secret, totp_last_step, recovery, status, is_admin, created_at, consent_at, consent_version, wrapped_key, kdf)"
            " VALUES (?, ?, ?, ?, -1, '[]', 'active', 0, ?, ?, ?, ?, ?)",
            (b.username, derived_salt(b.username), _ph.hash(raw), enc_secret(pyotp.random_base32()), utcnow(), utcnow(),
             legal.PRIVACY_VERSION, seal_json(b.wrappedKey), json.dumps(KDF_DEFAULT)),
        )
        token = new_session(con, request, response, cur.lastrowid)
        created = con.execute("SELECT created_at FROM users WHERE id=?", (cur.lastrowid,)).fetchone()[0]
    return {"username": b.username, "isAdmin": False, "consentCurrent": True, "token": token, "until": demo_until(created)}


@app.post("/api/demo/end", status_code=204)
def demo_end(request: Request, response: Response, user: dict = Depends(current_user)):
    if not DEMO_MODE or not user["username"].startswith("demo-"):
        raise HTTPException(404, "Nicht gefunden.")
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?", (user["id"],))
    response.delete_cookie(COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")


# ---------------------------------------------------------------- Anmeldung
class Login(BaseModel):
    username: str = Field(max_length=64)
    authKey: str = Field(max_length=64)
    code: str = Field(max_length=30)


GENERIC_LOGIN_ERROR = "Benutzername, Passwort oder Code stimmt nicht."


@app.post("/api/auth/login")
def login(b: Login, request: Request, response: Response):
    rate_limit(request, "login", 20, 900, "Zu viele Anmeldeversuche von dieser Adresse. Bitte warte 15 Minuten.")
    raw = parse_key(b.authKey)
    u = norm_username(b.username)
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone() if u else None
        if not user:
            verify_hash(_DUMMY_HASH, raw)
            raise HTTPException(401, GENERIC_LOGIN_ERROR)
        check_user_lock(user)
        left = None
        ok = verify_hash(user["auth_hash"], raw)
        if ok:
            ok, left = check_second_factor(con, user, b.code)
        if not ok:
            record_fail(con, user["id"])
            raise HTTPException(401, GENERIC_LOGIN_ERROR)
        con.execute("UPDATE users SET fail_count=0 WHERE id=?", (user["id"],))
        if user["status"] != "active":
            con.commit()
            if user["status"] == "pending":
                raise HTTPException(403, "Dein Konto wartet noch auf Freigabe. Versuch es später noch einmal.")
            raise HTTPException(403, "Dein Konto ist gesperrt. Wende dich an die Person, die diese Seite betreibt.")
        token = new_session(con, request, response, user["id"])
        consent_ok = user["consent_version"] == legal.PRIVACY_VERSION
    return {"usedRecovery": left is not None, "recoveryCodesLeft": left, "username": user["username"],
            "isAdmin": bool(user["is_admin"]), "consentCurrent": consent_ok, "token": token,
            "wrappedKey": unseal_json(user["wrapped_key"]), "hasRecoveryKey": bool(user["recovery_wrapped"])}


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    tok = request_token(request)
    if tok:
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sha(tok),))
    response.delete_cookie(COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")


# ---------------------------------------------------------------- Konto
class ChangePassword(BaseModel):
    oldAuthKey: str = Field(max_length=64)
    newAuthKey: str = Field(max_length=64)
    code: str = Field(max_length=20)
    wrappedKey: Sealed   # derselbe Datenschlüssel, verpackt mit dem neuen Passwort. Einträge bleiben unverändert.


class Confirm(BaseModel):
    authKey: str = Field(max_length=64)
    code: str = Field(max_length=20)


def check_blob(b: Sealed):
    try:
        if len(base64.b64decode(b.iv, validate=True)) != 12:
            raise ValueError
        base64.b64decode(b.ct, validate=True)
    except Exception:
        raise HTTPException(400, "Ungültige Anfrage.")


def reauth(con, user_id: int, raw: bytes, code: str):
    user = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    check_user_lock(user)
    ok = verify_hash(user["auth_hash"], raw) and check_second_factor(con, user, code)[0]
    if not ok:
        record_fail(con, user_id)
        raise HTTPException(401, "Passwort oder Code stimmt nicht.")
    con.execute("UPDATE users SET fail_count=0 WHERE id=?", (user_id,))


@app.post("/api/auth/change-password")
def change_password(b: ChangePassword, user: dict = Depends(current_user)):
    old, new = parse_key(b.oldAuthKey), parse_key(b.newAuthKey)
    check_wrap(b.wrappedKey)
    with db() as con:
        reauth(con, user["id"], old, b.code)
        con.execute("UPDATE users SET auth_hash=?, wrapped_key=?, kdf=? WHERE id=?",
                    (_ph.hash(new), seal_json(b.wrappedKey), json.dumps(KDF_DEFAULT), user["id"]))
        con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash != ?", (user["id"], user["token_hash"]))
    return {"ok": True, "kdf": KDF_DEFAULT}


class KdfUpgrade(BaseModel):
    oldAuthKey: str = Field(max_length=64)
    newAuthKey: str = Field(max_length=64)
    wrappedKey: Sealed


@app.post("/api/account/kdf")
def upgrade_kdf(b: KdfUpgrade, user: dict = Depends(current_user)):
    """Direkt nach dem Login: gleiches Passwort, neue Ableitung (Argon2id). Die Inhalte bleiben unverändert."""
    if user["kdf"] and json.loads(user["kdf"]) == KDF_DEFAULT:
        return {"ok": True, "kdf": KDF_DEFAULT}
    old, new = parse_key(b.oldAuthKey), parse_key(b.newAuthKey)
    check_wrap(b.wrappedKey)
    if not verify_hash(user["auth_hash"], old):
        raise HTTPException(401, "Ungültige Anfrage.")
    with db() as con:
        con.execute("UPDATE users SET auth_hash=?, wrapped_key=?, kdf=? WHERE id=?",
                    (_ph.hash(new), seal_json(b.wrappedKey), json.dumps(KDF_DEFAULT), user["id"]))
    return {"ok": True, "kdf": KDF_DEFAULT}


# ---------------------------------------------------------------- Datenschlüssel und Wiederherstellungsschlüssel
# Alle Inhalte sind mit einem Datenschlüssel (DEK) verschlüsselt. Der Server speichert ihn nur verpackt:
#   wrapped_key      = AES-GCM(KEK aus Passwort, DEK)
#   recovery_wrapped = AES-GCM(KEK aus Wiederherstellungsschlüssel, DEK)
# Beide KEKs entstehen im Browser; der Server kann den DEK nie auspacken.
def seal_json(b: Optional[Sealed]) -> Optional[str]:
    if b is None:
        return None
    check_wrap(b)
    return json.dumps({"iv": b.iv, "ct": b.ct})


def unseal_json(v: Optional[str]) -> Optional[dict]:
    return json.loads(v) if v else None


def check_wrap(b: Sealed):
    check_blob(b)
    if len(base64.b64decode(b.ct)) != 48:  # 32 Byte Schlüssel + 16 Byte GCM-Tag
        raise HTTPException(400, "Ungültige Anfrage.")


@app.get("/api/account/keys")
def get_keys(user: dict = Depends(current_user)):
    return {"wrappedKey": unseal_json(user["wrapped_key"]), "recovery": {
        "set": bool(user["recovery_wrapped"]), "createdAt": user["recovery_created"]}}


class RecoverySet(BaseModel):
    authKey: str = Field(max_length=64)
    code: str = Field(max_length=20)
    recoveryAuth: str = Field(max_length=64)
    recoveryWrapped: Sealed


@app.post("/api/account/recovery")
def set_recovery(b: RecoverySet, user: dict = Depends(current_user)):
    raw, rec = parse_key(b.authKey), parse_key(b.recoveryAuth)
    check_wrap(b.recoveryWrapped)
    with db() as con:
        reauth(con, user["id"], raw, b.code)
        con.execute("UPDATE users SET recovery_auth_hash=?, recovery_wrapped=?, recovery_created=? WHERE id=?",
                    (_ph.hash(rec), seal_json(b.recoveryWrapped), utcnow(), user["id"]))
    return {"ok": True, "createdAt": utcnow()}


class RecoverBegin(BaseModel):
    username: str = Field(max_length=64)
    recoveryAuth: str = Field(max_length=64)
    code: str = Field(max_length=30)


class RecoverFinish(BaseModel):
    recoverToken: str = Field(max_length=100)
    newAuthKey: str = Field(max_length=64)
    wrappedKey: Sealed


_recover_tokens: dict[str, tuple[int, int]] = {}  # sha(token) -> (user_id, expires); nur im Arbeitsspeicher


@app.post("/api/auth/recover/begin")
def recover_begin(b: RecoverBegin, request: Request):
    """Passwort vergessen: Wiederherstellungsschlüssel + zweiter Faktor (App-Code oder Wiederherstellungscode)."""
    rate_limit(request, "recover", 10, 3600, "Zu viele Versuche von dieser Adresse. Bitte warte eine Stunde.")
    raw = parse_key(b.recoveryAuth)
    u = norm_username(b.username)
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone() if u else None
        if not user or not user["recovery_auth_hash"]:
            verify_hash(_DUMMY_HASH, raw)
            raise HTTPException(401, "Benutzername, Wiederherstellungsschlüssel oder Code stimmt nicht.")
        check_user_lock(user)
        ok = verify_hash(user["recovery_auth_hash"], raw) and check_second_factor(con, user, b.code)[0]
        if not ok:
            record_fail(con, user["id"])
            raise HTTPException(401, "Benutzername, Wiederherstellungsschlüssel oder Code stimmt nicht.")
        if user["status"] != "active":
            raise HTTPException(403, "Dieses Konto ist nicht aktiv.")
        con.execute("UPDATE users SET fail_count=0 WHERE id=?", (user["id"],))
    token = secrets.token_urlsafe(32)
    for k in [k for k, (_, exp) in _recover_tokens.items() if exp < now()]:
        del _recover_tokens[k]
    _recover_tokens[sha(token)] = (user["id"], now() + 10 * 60)
    return {"recoverToken": token, "recoveryWrapped": unseal_json(user["recovery_wrapped"]), "salt": user["kdf_salt"]}


@app.post("/api/auth/recover/finish")
def recover_finish(b: RecoverFinish, request: Request, response: Response):
    entry = _recover_tokens.pop(sha(b.recoverToken), None)
    if not entry or entry[1] < now():
        raise HTTPException(400, "Die Wiederherstellung ist abgelaufen. Bitte fang noch einmal an.")
    new = parse_key(b.newAuthKey)
    check_wrap(b.wrappedKey)
    with db() as con:
        con.execute("UPDATE users SET auth_hash=?, wrapped_key=?, kdf=? WHERE id=?",
                    (_ph.hash(new), seal_json(b.wrappedKey), json.dumps(KDF_DEFAULT), entry[0]))
        con.execute("DELETE FROM sessions WHERE user_id=?", (entry[0],))
        user = con.execute("SELECT * FROM users WHERE id=?", (entry[0],)).fetchone()
        token = new_session(con, request, response, entry[0])
    return {"username": user["username"], "isAdmin": bool(user["is_admin"]), "token": token,
            "consentCurrent": user["consent_version"] == legal.PRIVACY_VERSION}


@app.post("/api/account/delete", status_code=204)
def delete_account(b: Confirm, response: Response, user: dict = Depends(current_user)):
    raw = parse_key(b.authKey)
    with db() as con:
        reauth(con, user["id"], raw, b.code)
        if user["is_admin"]:
            others = con.execute("SELECT COUNT(*) FROM users WHERE is_admin=1 AND status='active' AND id != ?", (user["id"],)).fetchone()[0]
            users = con.execute("SELECT COUNT(*) FROM users WHERE id != ?", (user["id"],)).fetchone()[0]
            if users and not others:
                raise HTTPException(409, "Du bist der einzige Admin. Mach zuerst ein anderes aktives Konto zum Admin.")
        con.execute("DELETE FROM users WHERE id=?", (user["id"],))  # Einträge und Sitzungen per CASCADE
    response.delete_cookie(COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="strict")


class ConsentReq(BaseModel):
    consent: bool


@app.post("/api/account/consent")
def give_consent(b: ConsentReq, user: dict = Depends(current_user)):
    if not b.consent:
        raise HTTPException(400, "Bitte bestätige die Einwilligung.")
    with db() as con:
        con.execute("UPDATE users SET consent_at=?, consent_version=? WHERE id=?", (utcnow(), legal.PRIVACY_VERSION, user["id"]))
    return {"consentVersion": legal.PRIVACY_VERSION}


def require_consent(user: dict):
    if user.get("consent_version") != legal.PRIVACY_VERSION:
        raise HTTPException(403, "Bitte bestätige zuerst die aktualisierte Einwilligung.")


# ---------------------------------------------------------------- Inhalte (nur Ciphertext)
RECORD_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_RECORDS = 50_000


@app.get("/api/records")
def list_records(user: dict = Depends(current_user)):
    with db() as con:
        rows = con.execute("SELECT id, iv, ct FROM records WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.put("/api/records/{rid}")
def put_record(rid: str, b: Sealed, user: dict = Depends(current_user)):
    if not RECORD_ID.match(rid):
        raise HTTPException(400, "Ungültige Anfrage.")
    require_consent(user)
    check_blob(b)
    with db() as con:
        if con.execute("SELECT COUNT(*) FROM records WHERE user_id=?", (user["id"],)).fetchone()[0] >= MAX_RECORDS:
            raise HTTPException(507, "Speichergrenze erreicht.")
        con.execute("INSERT INTO records (user_id, id, iv, ct) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(user_id, id) DO UPDATE SET iv=excluded.iv, ct=excluded.ct", (user["id"], rid, b.iv, b.ct))
    return {"id": rid}


@app.delete("/api/records/{rid}", status_code=204)
def delete_record(rid: str, user: dict = Depends(current_user)):
    if not RECORD_ID.match(rid):
        raise HTTPException(400, "Ungültige Anfrage.")
    with db() as con:
        con.execute("DELETE FROM records WHERE user_id=? AND id=?", (user["id"], rid))


# ---------------------------------------------------------------- Umstellung v1 -> v2 (einmalig pro Konto)
# Der Browser liest die alten Datensätze, verschlüsselt sie im neuen Format und löscht sie dann hier.
@app.get("/api/legacy")
def legacy_get(user: dict = Depends(current_user)):
    out = {}
    with db() as con:
        for t, key in (("entries", "date"), ("assessments", "id"), ("items", "id")):
            out[t] = [dict(r) for r in con.execute(f"SELECT {key} AS key, iv, ct FROM {t} WHERE user_id=?", (user["id"],))] \
                if table_exists(con, t) else []
    return out


@app.delete("/api/legacy", status_code=204)
def legacy_done(user: dict = Depends(current_user)):
    with db() as con:
        for t in LEGACY_TABLES:
            if table_exists(con, t):
                con.execute(f"DELETE FROM {t} WHERE user_id=?", (user["id"],))
        drop_empty_legacy_tables(con)


# ---------------------------------------------------------------- Verwaltung (Admins)
@app.get("/api/admin/users")
def admin_users(admin: dict = Depends(current_admin)):
    with db() as con:
        cleanup(con)
        rows = con.execute("SELECT id, username, status, is_admin, created_at, last_login FROM users "
                           "ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, username").fetchall()
    return [{"id": r["id"], "username": r["username"], "status": r["status"], "isAdmin": bool(r["is_admin"]),
             "createdAt": r["created_at"], "lastLogin": r["last_login"], "isMe": r["id"] == admin["id"]} for r in rows]


class AdminAction(BaseModel):
    action: Literal["approve", "disable", "enable", "make-admin", "remove-admin", "delete"]


@app.post("/api/admin/users/{user_id}")
def admin_action(user_id: int, b: AdminAction, admin: dict = Depends(current_admin)):
    if user_id == admin["id"] and b.action in ("disable", "remove-admin", "delete"):
        raise HTTPException(400, "Das geht nicht mit deinem eigenen Konto.")
    with db() as con:
        target = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "Konto nicht gefunden.")
        if b.action in ("approve", "enable"):
            con.execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
        elif b.action == "disable":
            con.execute("UPDATE users SET status='disabled' WHERE id=?", (user_id,))
            con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        elif b.action == "make-admin":
            if target["status"] != "active":
                raise HTTPException(400, "Nur aktive Konten können Admin werden.")
            con.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
        elif b.action == "remove-admin":
            con.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
        elif b.action == "delete":
            con.execute("DELETE FROM users WHERE id=?", (user_id,))
    return {"ok": True}



# ---------------------------------------------------------------- Kommandozeile
def cli(argv):
    init_db()
    cmd, arg = (argv[1] if len(argv) > 1 else ""), (argv[2] if len(argv) > 2 else "")
    with db() as con:
        def need_user():
            u = con.execute("SELECT * FROM users WHERE username=?", ((arg or "").lower(),)).fetchone()
            if not u:
                sys.exit(f"Kein Konto mit dem Benutzernamen „{arg}“.")
            return u

        if cmd == "list-users":
            for r in con.execute("SELECT username, status, is_admin, created_at, last_login, fail_count, locked_until FROM users ORDER BY username"):
                lock = f"  GESPERRT bis {time.strftime('%H:%M', time.localtime(r['locked_until']))}" if r["locked_until"] > now() else ""
                fails = f"  {r['fail_count']} Fehlversuche" if r["fail_count"] else ""
                print(f"{r['username']:<32} {r['status']:<9} {'admin' if r['is_admin'] else '':<6} angelegt {r['created_at'][:10]}  zuletzt {(r['last_login'] or '-')[:10]}{fails}{lock}")
        elif cmd == "rename":
            u, new = need_user(), norm_username(argv[3] if len(argv) > 3 else "")
            if not new:
                sys.exit(USERNAME_HINT)
            if con.execute("SELECT 1 FROM users WHERE username=?", (new,)).fetchone():
                sys.exit(f"„{new}“ ist schon vergeben.")
            # sicher: das Salt ist am Konto gespeichert, Passwort und Verschlüsselung bleiben gültig
            con.execute("UPDATE users SET username=? WHERE id=?", (new, u["id"]))
            print(f"Umbenannt: {u['username']} -> {new}. Passwort, Authenticator-App und Einträge bleiben gleich.")
        elif cmd == "approve":
            con.execute("UPDATE users SET status='active' WHERE id=?", (need_user()["id"],)); print("Freigegeben.")
        elif cmd == "disable":
            u = need_user(); con.execute("UPDATE users SET status='disabled' WHERE id=?", (u["id"],))
            con.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],)); print("Gesperrt.")
        elif cmd == "make-admin":
            con.execute("UPDATE users SET is_admin=1, status='active' WHERE id=?", (need_user()["id"],)); print("Ist jetzt Admin.")
        elif cmd == "reset-2fa":
            u = need_user()
            secret = pyotp.random_base32()
            codes, codes_json = make_recovery_codes()
            con.execute("UPDATE users SET totp_secret=?, totp_last_step=-1, recovery=? WHERE id=?", (enc_secret(secret), codes_json, u["id"]))
            con.execute("DELETE FROM sessions WHERE user_id=?", (u["id"],))
            q = qrcode.QRCode(border=1)
            q.add_data(otpauth_uri(secret, u["username"]))
            q.print_ascii(invert=True)
            print(f"\nNeues 2FA-Geheimnis für {u['username']}: {secret}\nSitzungen beendet.\n\nNeue Wiederherstellungscodes:")
            print("\n".join("  " + c for c in codes))
        elif cmd == "unlock":
            con.execute("UPDATE users SET fail_count=0, locked_until=0 WHERE id=?", (need_user()["id"],)); print("Sperre aufgehoben.")
        elif cmd == "logout-all":
            con.execute("DELETE FROM sessions"); print("Alle Sitzungen beendet.")
        else:
            print("Befehle: list-users | rename <alt> <neu> | approve <name> | disable <name> | make-admin <name> | reset-2fa <name> | unlock <name> | logout-all")


if __name__ == "__main__":
    cli(sys.argv)
