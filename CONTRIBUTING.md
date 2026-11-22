# Mitmachen

Danke für dein Interesse. Kopfwetter ist ein kleines Projekt, und Beiträge sind willkommen, ob als Fehlerberichte,
Übersetzungen, Barrierefreiheit, Tests oder Code.

## Grundsätze

- **Keine Klartextdaten auf dem Server.** Jede neue Funktion, die Inhalte speichert, verschlüsselt sie auf dem Gerät mit dem Datenschlüssel und einer passenden AAD (siehe [docs/CRYPTO.md](docs/CRYPTO.md)).
- **Keine externen Quellen:** keine CDNs, keine Tracker, keine Webfonts. Die CSP bleibt `'self'`.
- **Keine Heilversprechen.** Die App ist ein Tagebuch und ersetzt keine Behandlung. Fragebögen werden beschreibend ausgewertet.
- **Klein bleiben:** keine Frameworks im Frontend, wenige Abhängigkeiten im Backend.

## Lokal starten

```bash
cp .env.example .env        # APP_SECRET und SETUP_TOKEN setzen, COOKIE_SECURE=0 für http://localhost
docker compose up --build   # oder: pip install -r requirements.txt && DB_PATH=./data/dev.db uvicorn app:app --reload
```

## Übersetzungen

Deutsch ist die Quellsprache. Texte im Code stehen in `$t("…")` bzw. `` $T`… ${wert} …` ``, die englischen Fassungen in
`i18n/en_js.py`, die der Oberfläche (`static/index.html`) in `i18n/en-html.json`. Nach einer Änderung:

```bash
python3 i18n/en_js.py        # erzeugt static/i18n/en.js
pytest -q tests/test_i18n.py # meldet jeden Text ohne Übersetzung
```

Datenwerte bleiben deutsch und werden nur in der Anzeige übersetzt, z. B. die Aktivitäten (`Bewegung` → „Exercise“).
So passen Einträge und Exporte zu beiden Sprachen.

## Tests

```bash
pip install -r requirements.txt pytest httpx && pytest -q
(cd mobile && npm ci) && node tests/vectors/check.mjs
```

Wer an der Kryptografie etwas ändert, erzeugt die Testvektoren mit `python3 tests/vectors/generate.py` neu und
begründet die Änderung im Merge Request. Ändert sich ein Format, steigt die Protokollversion (`…/v2`), und es
braucht einen Migrationspfad.

## Merge Requests

- ein Thema pro Merge Request, mit kurzer Beschreibung, was und warum
- Tests grün, keine Geheimnisse und keine echten Daten im Commit
- Mit dem Einreichen stimmst du zu, dass dein Beitrag unter der AGPL-3.0-or-later steht.

Sicherheitsprobleme bitte nicht als Merge Request oder Issue melden, sondern wie in [SECURITY.md](SECURITY.md) beschrieben.
