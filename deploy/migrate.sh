#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
# Umzug von Kopfwetter (App + Blog) auf einen anderen Server.
# Läuft auf deinem Rechner und braucht SSH-Zugang zu beiden Servern (Host-Aliase aus ~/.ssh/config).
#
#   ./deploy/migrate.sh check    # nur prüfen, ändert nichts
#   ./deploy/migrate.sh copy     # Probelauf: Kopie übertragen und auf NEU starten, ALT läuft weiter
#   ./deploy/migrate.sh cutover  # echter Umzug: ALT stoppen, letzte Kopie übertragen, NEU starten
#
# Danach den Cloudflare-Tunnel umstellen (siehe deploy/MIGRATION.md). ALT wird nie gelöscht.
set -euo pipefail

OLD="${OLD:?Bitte OLD=<ssh-host des alten Servers> setzen}"
NEW="${NEW:?Bitte NEW=<ssh-host des neuen Servers> setzen}"
# Verzeichnisse mit compose.yaml. Auf dem neuen Server dürfen sie anders heißen (z. B. nach Umbenennung des Repos).
OLD_APP_DIR="${OLD_APP_DIR:-${APP_DIR:-~/kopfwetter-app}}"
NEW_APP_DIR="${NEW_APP_DIR:-$OLD_APP_DIR}"
OLD_BLOG_DIR="${OLD_BLOG_DIR:-${BLOG_DIR:-~/kopfwetter-blog}}"
NEW_BLOG_DIR="${NEW_BLOG_DIR:-$OLD_BLOG_DIR}"
# Dienstname der App in compose.yaml und Datenbankdatei. Für einen Umzug aus einer Version vor 11/2026
# (stimmung.db) gilt dieses Skript nicht: dafür Export/Import nutzen (README, „Umzug per Export“).
NEW_SERVICE="${NEW_SERVICE:-kopfwetter-app}"
OLD_SERVICE="${OLD_SERVICE:-$NEW_SERVICE}"
DB=kopfwetter-app.db
OLD_DB=$DB
STAMP="$(date +%Y%m%d-%H%M%S)"
LOCAL_TMP="$(mktemp -d)"
trap 'rm -rf "$LOCAL_TMP"' EXIT

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mFEHLER: %s\033[0m\n' "$*" >&2; exit 1; }
rsh()  { local h="$1"; shift; ssh -o BatchMode=yes "$h" "$@"; }

check() {
  say "Verbindung und Docker prüfen"
  for h in "$OLD" "$NEW"; do
    rsh "$h" 'docker compose version >/dev/null' || die "$h: kein SSH-Zugang oder kein 'docker compose'"
    echo "  $h: ok"
  done
  rsh "$OLD" "test -f $OLD_APP_DIR/.env" || die "$OLD: $OLD_APP_DIR/.env fehlt"
  rsh "$OLD" "test -f $OLD_APP_DIR/data/$OLD_DB" || die "$OLD: $OLD_APP_DIR/data/$OLD_DB fehlt (Version vor 11/2026? Dann Export/Import nutzen)"
  rsh "$OLD" "grep -q '^APP_SECRET=.\{32,\}' $OLD_APP_DIR/.env" || die "$OLD: APP_SECRET in der .env fehlt oder ist zu kurz"
  if rsh "$NEW" "test -f $NEW_APP_DIR/data/$DB"; then
    echo "  Hinweis: Auf $NEW liegt schon eine Datenbank. Sie wird vor dem Überschreiben gesichert."
  fi
  say "Konten auf $OLD"
  rsh "$OLD" "cd $OLD_APP_DIR && docker compose exec -T $OLD_SERVICE python app.py list-users" || true
}

snapshot() {
  # Konsistente Kopie (SQLite-Backup-API, berücksichtigt WAL), danach Integritätsprüfung.
  # $1 = exec (App läuft weiter) oder run (App ist gestoppt, Einmal-Container nur für das Backup)
  local how="exec -T"; [ "${1:-exec}" = run ] && how="run --rm --no-deps -T"
  say "Datenbank auf $OLD sichern"
  rsh "$OLD" "cd $OLD_APP_DIR && docker compose $how $OLD_SERVICE python -c \"
import sqlite3
src = sqlite3.connect('/data/$OLD_DB'); dst = sqlite3.connect('/data/migrate-$STAMP.db')
src.backup(dst); dst.close(); src.close()
c = sqlite3.connect('/data/migrate-$STAMP.db'); r = c.execute('PRAGMA integrity_check').fetchone()[0]
n = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]; e = c.execute('SELECT COUNT(*) FROM records').fetchone()[0]
print(f'  integrity: {r}, Konten: {n}, Datensätze: {e}'); assert r == 'ok'
\""
}

transfer() {
  say "Dateien von $OLD nach $NEW übertragen"
  rsh "$OLD" "cd $OLD_APP_DIR && tar -czf - --exclude=./data --exclude=./mobile/node_modules . data/migrate-$STAMP.db" > "$LOCAL_TMP/app.tgz"
  rsh "$OLD" "cd $OLD_BLOG_DIR && tar -czf - --exclude=./public --exclude=./resources ." > "$LOCAL_TMP/blog.tgz" || echo "  (kein Blog auf $OLD gefunden, übersprungen)"
  ( cd "$LOCAL_TMP" && sha256sum app.tgz > app.sha256 )
  rsh "$NEW" "mkdir -p $NEW_APP_DIR/data $NEW_BLOG_DIR && cd $NEW_APP_DIR/data && if [ -f $DB ]; then mv $DB $DB.vor-umzug-$STAMP; rm -f $DB-wal $DB-shm; fi"
  rsh "$NEW" "cd $NEW_APP_DIR && tar -xzf -" < "$LOCAL_TMP/app.tgz"
  [ -s "$LOCAL_TMP/blog.tgz" ] && rsh "$NEW" "cd $NEW_BLOG_DIR && tar -xzf -" < "$LOCAL_TMP/blog.tgz"
  rsh "$NEW" "cd $NEW_APP_DIR && mv data/migrate-$STAMP.db data/$DB && chmod 600 .env"
  rsh "$NEW" "cd $NEW_APP_DIR && { chown -R 1000:1000 data 2>/dev/null || sudo -n chown -R 1000:1000 data; }" \
    || echo "  Hinweis: Bitte auf $NEW ausführen: sudo chown -R 1000:1000 $NEW_APP_DIR/data (Podman rootless: :U am Volume)"
  rsh "$OLD" "rm -f $OLD_APP_DIR/data/migrate-$STAMP.db"
  rm -f "$LOCAL_TMP"/*.tgz
}

start_new() {
  say "Auf $NEW bauen und starten"
  rsh "$NEW" "cd $NEW_APP_DIR && docker compose up -d --build"
  rsh "$NEW" "cd $NEW_BLOG_DIR && test -f compose.yaml && docker compose up -d --build" || echo "  (Blog nicht gestartet)"
  say "Auf $NEW prüfen"
  for _ in $(seq 1 30); do rsh "$NEW" 'curl -fsS http://127.0.0.1:8085/healthz >/dev/null' && break; sleep 2; done
  rsh "$NEW" 'curl -fsS http://127.0.0.1:8085/healthz' >/dev/null && echo "  App: ok (127.0.0.1:8085)" || die "App antwortet auf $NEW nicht. Logs: docker compose logs $NEW_SERVICE"
  rsh "$NEW" 'curl -fsS http://127.0.0.1:8086/healthz' >/dev/null && echo "  Blog: ok (127.0.0.1:8086)" || echo "  Blog: antwortet nicht"
  rsh "$NEW" "cd $NEW_APP_DIR && docker compose exec -T $NEW_SERVICE python app.py list-users"
}

case "${1:-}" in
  check)   check ;;
  copy)    check; snapshot exec; transfer; start_new
           say "Probelauf fertig. $OLD läuft unverändert weiter; Änderungen nach diesem Zeitpunkt fehlen auf $NEW." ;;
  cutover) check
           say "App auf $OLD stoppen (ab jetzt kurze Auszeit)"
           rsh "$OLD" "cd $OLD_APP_DIR && docker compose stop $OLD_SERVICE"
           snapshot run
           transfer; start_new
           say "Jetzt den Tunnel umstellen (deploy/MIGRATION.md, Schritt 4). Zurück geht es mit: ssh $OLD 'cd $OLD_APP_DIR && docker compose start $OLD_SERVICE'" ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
