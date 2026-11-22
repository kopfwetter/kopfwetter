# Umzug von Kopfwetter (App und Blog) auf einen anderen Server

Weil der Cloudflare Tunnel der einzige Zugang von außen ist, ist der Umzug einfach: Du startest beides auf dem neuen
Server, kopierst die Datenbank und stellst im Tunnel die Ziele um. Am DNS ändert sich nichts. Der alte Server bleibt
unangetastet, bis alles läuft. Die Auszeit für die App beträgt etwa eine Minute.

## Was umzieht

| | Wo | Hinweis |
|---|---|---|
| **App-Datenbank** | `kopfwetter-app/data/kopfwetter-app.db` | Konten, Einträge, Tests, Tabletten. Inhalte sind Ende-zu-Ende verschlüsselt. |
| **`.env` der App** | `kopfwetter-app/.env` | **`APP_SECRET` mitnehmen.** Wechseln nur über `APP_SECRET_PREVIOUS` (README, „APP_SECRET erneuern“), sonst funktioniert keine Authenticator-App mehr. |
| App-Code | `kopfwetter-app/` | wird auf dem neuen Server neu gebaut |
| Blog | `kopfwetter-blog/` | hat keine Daten und wird neu gebaut (oder aus der GitLab-Registry gezogen) |

Sitzungen bleiben gültig, weil sie in der Datenbank stehen. Angemeldete Geräte und die Handy-Apps merken vom Umzug nichts.

## 0. Vorbereiten

- Auf dem neuen Server: Docker mit Compose-Plugin, `curl`, freie Ports `127.0.0.1:8085` (App) und `127.0.0.1:8086` (Blog).
- Auf deinem Rechner: SSH-Zugang zu beiden Servern ohne Passwortabfrage, zum Beispiel als Host-Aliase in `~/.ssh/config`.
- Ein Backup des alten Servers, unabhängig von diesem Umzug.

## 1. Prüfen

```bash
cd kopfwetter-app
OLD=alt NEW=neu ./deploy/migrate.sh check
```

Das Skript prüft SSH, Docker, `.env` und `APP_SECRET` und zeigt die Konten an. Liegen die Verzeichnisse woanders als unter
`~/kopfwetter-app` und `~/kopfwetter-blog`, setzt du `APP_DIR=…` bzw. `BLOG_DIR=…`.

## 2. Probelauf (ohne Auszeit)

```bash
OLD=alt NEW=neu ./deploy/migrate.sh copy
```

Das Skript kopiert Code, `.env` und eine konsistente Momentaufnahme der Datenbank und startet beides auf dem neuen Server.
Der alte Server läuft weiter, die Nutzer merken nichts.

Auf dem neuen Server testen, ohne den Tunnel umzustellen:

```bash
ssh -L 8085:127.0.0.1:8085 -L 8086:127.0.0.1:8086 neu
# im Browser: http://localhost:8085 und http://localhost:8086
```

Achtung: Ohne HTTPS setzt die App das Anmelde-Cookie nicht (`COOKIE_SECURE=1`). Die Startseite lädt, die Anmeldung klappt
so nicht. Für einen Anmeldetest kannst du vorübergehend einen eigenen Test-Hostnamen im Tunnel auf den neuen Server
zeigen lassen, zum Beispiel `test.kopfwetter.app`.

## 3. Echter Umzug

```bash
OLD=alt NEW=neu ./deploy/migrate.sh cutover
```

Das Skript stoppt die App auf dem alten Server, damit keine Einträge mehr verloren gehen können, sichert die Datenbank,
überträgt sie und startet den neuen Server. Die vorherige Datenbank auf dem neuen Server (vom Probelauf) wird
als `kopfwetter-app.db.vor-umzug-<zeit>` gesichert.

## 4. Tunnel umstellen

**Variante A: derselbe Tunnel, neuer Connector (am einfachsten).** Auf dem neuen Server cloudflared mit dem Token des
bestehenden Tunnels installieren (Cloudflare Zero Trust → Networks → Tunnels → dein Tunnel → *Install connector*).
Ziele sind weiterhin `http://localhost:8085` und `http://localhost:8086`. Danach cloudflared auf dem alten Server stoppen,
damit keine Anfragen mehr dorthin gehen:

```bash
ssh alt 'sudo systemctl stop cloudflared'
```

Läuft über diesen Tunnel auf dem alten Server noch mehr als Kopfwetter, nimm Variante B.

**Variante B: eigener Tunnel auf dem neuen Server.** Dort in dessen Konfiguration eintragen:

```yaml
ingress:
  - hostname: kopfwetter.app
    service: http://localhost:8085
  - hostname: blog.kopfwetter.app
    service: http://localhost:8086
  - service: http_status:404
```

DNS auf den neuen Tunnel zeigen lassen und die beiden Einträge aus der Konfiguration des alten Tunnels entfernen:

```bash
cloudflared tunnel route dns --overwrite-dns <neuer-tunnel> kopfwetter.app
cloudflared tunnel route dns --overwrite-dns <neuer-tunnel> blog.kopfwetter.app
```

## 5. Nachher prüfen

- `https://kopfwetter.app`: anmelden, ein Eintrag ist sichtbar, oben steht „Ende-zu-Ende verschlüsselt“.
- Einen Test-Eintrag speichern und auf einem zweiten Gerät neu laden.
- `https://blog.kopfwetter.app` lädt.
- Die Handy-App öffnen: Sie ist weiter angemeldet.
- **Backups** auf dem neuen Server einrichten (age + rclone), denn das alte Backup-Ziel sichert jetzt nichts Neues mehr:
  ```bash
  docker compose exec -T kopfwetter-app python -c "import sqlite3;s=sqlite3.connect('/data/kopfwetter-app.db');d=sqlite3.connect('/data/backup.db');s.backup(d)"
  age -r <dein-age-key> -o kopfwetter-app-$(date +%F).db.age data/backup.db && rm data/backup.db
  rclone copy kopfwetter-app-$(date +%F).db.age pcloud:backups/kopfwetter/
  ```
- Hast du den Hoster gewechselt: `HOSTER=` in der `.env` anpassen (erscheint in der Datenschutzerklärung) und einen
  Auftragsverarbeitungsvertrag mit dem neuen Hoster abschließen.

## Zurück, falls etwas schiefgeht

Der alte Server ist unverändert. App wieder starten und den Tunnel zurückstellen:

```bash
ssh alt 'cd ~/kopfwetter-app && docker compose start kopfwetter-app && sudo systemctl start cloudflared'
```

Einträge, die in der Zwischenzeit auf dem neuen Server gespeichert wurden, fehlen dann auf dem alten. Also möglichst
schnell entscheiden.

## Alten Server aufräumen (nach ein paar Tagen)

```bash
ssh alt 'cd ~/kopfwetter-app && docker compose down && cd ~/kopfwetter-blog && docker compose down'
```

Die alte Datenbank enthält nur verschlüsselte Inhalte. Lösche sie trotzdem (`shred -u data/*.db*`) und auch
ältere Klartext-Backups aus Version 1, falls es solche noch gibt.
