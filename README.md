# Kopfwetter – Stimmungstagebuch (selbst gehostet)

Tägliches Stimmungstagebuch: Stimmung, Angst, Antrieb (je 1–10), Aktivitäten, Medikamente und eine Notiz,
dazu ein 30-Tage-Verlauf, eine Historie und eine CSV-Sicherheitskopie.
FastAPI + SQLite in einem Container, **mit mehreren Konten, Registrierung mit Freigabe, 2-Faktor-Login und Ende-zu-Ende-Verschlüsselung**.

> **Kein Medizinprodukt.** Kopfwetter ist ein Tagebuch und ersetzt keine Diagnose oder Behandlung. In einer Krise: Telefonseelsorge 0800 111 0 111 oder 0800 111 0 222, Notruf 112.

**Weitere Dokumente:** [Kryptografie und Bedrohungsmodell](docs/CRYPTO.md) · [Sicherheitslücken melden](SECURITY.md) · [Mitmachen](CONTRIBUTING.md) · [Lizenzen Dritter](THIRD_PARTY_NOTICES.md) · [Release-Checkliste](docs/RELEASE-CHECKLIST.md)


**Repositories:** die App (dieses Repository, AGPL-3.0) und **kopfwetter/crypto** mit Spezifikation, Testvektoren und Entwürfen für Teilen und Post-Quanten-Kryptografie (Apache-2.0).
## Sicherheitsmodell

| | |
|---|---|
| **Anmeldung** | Passwort **und** 6-stelliger Code aus einer Authenticator-App (TOTP). Ein Code gilt nur einmal (Replay-Schutz). Dazu gibt es 10 Wiederherstellungscodes für den Fall, dass das Handy weg ist. |
| **Brute Force** | Nach 5 Fehlversuchen ist die Anmeldung 15 Minuten gesperrt. |
| **Verschlüsselung** | Alle Inhalte sind im Browser mit einem zufälligen **Datenschlüssel** (AES-256-GCM) verschlüsselt, **bevor** sie gesendet werden. Der Server speichert den Datenschlüssel nur verpackt: mit einem Schlüssel aus dem Passwort (Argon2id mit 64 MiB, dann HKDF) und optional mit dem Wiederherstellungsschlüssel. |
| **Metadaten** | Alle Inhalte liegen in einer Tabelle mit zufällig wirkenden Kennungen (HMAC) und sind auf feste Größen aufgefüllt. Der Server sieht weder Datum noch Art eines Datensatzes noch die Länge einer Notiz. |
| **Sperre** | Nach 5, 15 oder 60 Minuten ohne Nutzung oder beim Schließen sperrt sich die App. Entsperrt wird mit dem Passwort. |
| **Wiederherstellung** | Ein Wiederherstellungsschlüssel (160 Bit, 32 Zeichen) kann zusammen mit dem zweiten Faktor ein neues Passwort setzen. Der Server speichert nur einen Argon2id-Hash davon und den verpackten Datenschlüssel. |
| **Passwort** | Das Passwort selbst erreicht den Server nie. Er bekommt nur einen davon abgeleiteten Login-Schlüssel und speichert davon einen Argon2id-Hash. |
| **2FA-Geheimnis** | liegt verschlüsselt in der DB (Schlüssel aus `APP_SECRET`). |
| **Sitzung** | `__Host-`-Cookie mit HttpOnly, Secure und SameSite=Strict, gültig 12 h. Die Datenbank kennt nur den Hash des Tokens. |
| **Browser-Härtung** | Strikte CSP (nur eigene Skripte, keine externen Quellen; `wasm-unsafe-eval` nur für Argon2), HSTS, kein Framing, CSRF-Schutz über Header- und Origin-Prüfung. |
| **Container** | read-only, alle Capabilities entfernt, `no-new-privileges`, Port nur auf 127.0.0.1. |

Was der Server **trotzdem sieht**: wie viele Datensätze es gibt, ihre Größenklasse und den Zeitpunkt deiner letzten Anmeldung. Details in [docs/CRYPTO.md](docs/CRYPTO.md).

> ⚠️ **Passwort vergessen und kein Wiederherstellungsschlüssel = Einträge verloren.** Niemand, auch kein Admin, kann
> sie dann wiederherstellen. Die App erinnert nach dem Login daran, einen Wiederherstellungsschlüssel anzulegen
> (Bereich „Sicherheit“). Mit ihm und dem Code aus der Authenticator-App (oder einem der zehn Wiederherstellungscodes)
> setzt man unter „Passwort vergessen?“ ein neues Passwort. Die Einträge bleiben dabei unverändert.

## Einrichtung

```bash
cp .env.example .env
# APP_SECRET und SETUP_TOKEN eintragen:
openssl rand -hex 32      # -> APP_SECRET
openssl rand -base64 24   # -> SETUP_TOKEN
mkdir -p data && chown 1000:1000 data     # Podman rootless: stattdessen ./data:/data:U im Volume
docker compose up -d --build              # oder: podman compose up -d --build
```

1. Öffne die Seite über **HTTPS**. Die Verschlüsselung im Browser braucht einen sicheren Kontext, für Tests geht auch `http://localhost`.
2. **Erstes Konto:** Benutzername, Passwort und Einrichtungscode (`SETUP_TOKEN`) eingeben, QR-Code scannen und mit dem ersten Code bestätigen. Dieses Konto ist Admin und sofort aktiv.
3. Speichere die Wiederherstellungscodes.
4. Leere danach `SETUP_TOKEN` in der `.env` und führe `docker compose up -d` aus.

## Konten und Registrierung

- **Registrieren:** Jeder kann mit Benutzername, Passwort und Pflicht-2FA ein Konto anlegen (`REGISTRATION_OPEN=1`).
- **Freigabe:** Neue Konten sind erst nutzbar, wenn ein Admin sie im Bereich „Verwaltung“ freigibt (`REQUIRE_APPROVAL=1`). Nicht freigegebene Konten verschwinden nach `PENDING_DAYS` Tagen.
- **Verwaltung (Admins):** freigeben, ablehnen, sperren, entsperren, zum Admin machen, löschen. Admins sehen **keine** Einträge anderer Konten, denn die sind mit deren Passwort verschlüsselt.
- **Selbst löschen:** Jedes Konto kann sich unter „Sicherheit“ mit Passwort und Code selbst löschen, inklusive aller Einträge.
- **Schutz vor Missbrauch:** höchstens 5 Registrierungen pro Stunde und IP-Adresse, höchstens 20 Anmeldeversuche pro 15 Minuten und IP-Adresse, 15 Minuten Sperre nach 5 Fehlversuchen pro Konto, Obergrenzen `MAX_USERS` und `MAX_PENDING`.
- **Kein Ausforschen von Namen:** Bei der Anmeldung lässt sich nicht erkennen, ob ein Benutzername existiert. Bei der Registrierung ist das unvermeidbar („schon vergeben“).

### Impressum, Datenschutzerklärung, Einwilligung

Die App bringt beide Seiten mit: **`/impressum`** und **`/datenschutz`**. Sie werden aus deinen Angaben in der `.env` erzeugt
(`OPERATOR_NAME`, `OPERATOR_STREET`, `OPERATOR_CITY`, `OPERATOR_EMAIL`, optional `OPERATOR_PHONE`, `HOSTER`, `USE_CLOUDFLARE`,
`BACKUP_RETENTION_DAYS`, `SUPERVISORY_AUTHORITY`). Fehlt eine Pflichtangabe, steht auf der Seite ein gelb markierter Platzhalter,
und beim Start erscheint ein Hinweis im Log. Die Texte stehen in `legal.py`.

Bei der Registrierung muss jede Person **ausdrücklich in die Speicherung ihrer Gesundheitsdaten einwilligen**
(Art. 9 Abs. 2 lit. a DSGVO). Zeitpunkt und Version der Datenschutzerklärung werden zum Nachweis am Konto gespeichert
(`consent_at`, `consent_version`). Der Widerruf erfolgt über „Konto löschen“. Wenn du die Erklärung inhaltlich änderst,
erhöhe `PRIVACY_VERSION` in `legal.py`.

Die App schreibt keine Zugriffsprotokolle (`--no-access-log`). IP-Adressen liegen nur für die Rate-Limits bis zu einer Stunde im Arbeitsspeicher.

Bitte prüfe vor dem Livegang:
- **Auftragsverarbeitungsverträge** mit deinem Hoster und mit Cloudflare abschließen (bei beiden im Kundenkonto möglich).
- Die Erklärung beschreibt Cloudflare nur dann, wenn `USE_CLOUDFLARE=1` gesetzt ist.
- Das ist eine sorgfältige Vorlage, **keine Rechtsberatung**. Bei offener Registrierung für Gesundheitsdaten lohnt sich ein Blick von Fachleuten.

### Rechtliches bei offener Registrierung

Sobald andere Menschen Konten anlegen, bist du **Verantwortlicher im Sinne der DSGVO**, und es geht um Gesundheitsdaten (Art. 9 DSGVO).
Die Einträge sind zwar Ende-zu-Ende verschlüsselt, aber Benutzernamen, Zeitpunkte und IP-Adressen in Logs sind personenbezogen.
Impressum und Datenschutzerklärung sind eingebaut (siehe oben). Wer eigene Seiten nutzen will, setzt `PRIVACY_URL` und `IMPRINT_URL`.
und solltest das Projekt nicht als medizinisches Angebot darstellen. Das ist keine Rechtsberatung. Lass dich im Zweifel beraten.

## Ins Netz stellen (Cloudflare Tunnel)

```yaml
# cloudflared config.yml
ingress:
  - hostname: kopfwetter.app
    service: http://localhost:8085
  - service: http_status:404
```

- Setze **kein** `httpHostHeader`, denn die App vergleicht `Origin` mit `Host`.
- Optional als zusätzliche Schicht: eine **Cloudflare-Access**-Policy nur für deine E-Mail. Dann muss ein Angreifer zuerst an Cloudflare vorbei und danach noch Passwort und 2FA überwinden.
- Mit anderem Reverse Proxy (Caddy, Traefik): TLS dort terminieren und `X-Forwarded-*` setzen.

## Landingpage und Web-App

Ein Container, zwei Adressen:

- **`kopfwetter.app`** zeigt die Landingpage mit Funktionen, Sicherheit, Apps, Roadmap und Fragen (`landing.py`,
  `static/landing.css`, ohne JavaScript). Impressum und Datenschutz liegen auf beiden Adressen.
- **`web.kopfwetter.app`** zeigt die Web-App. Dafür in der `.env` `WEB_URL=https://web.kopfwetter.app` setzen und im
  Cloudflare-Tunnel einen zweiten öffentlichen Hostnamen `web.kopfwetter.app` auf **denselben Dienst** zeigen lassen
  (den Host-Header nicht umschreiben). `kopfwetter.app/app` leitet dann dauerhaft dorthin um.
- **`SITE_URL=https://kopfwetter.app`** setzt das Ziel des Links „Über Kopfwetter“ in der App.
- Ohne `WEB_URL` liegt die App unter `/app` (praktisch zum Selbsthosten mit nur einer Adresse).
- Die API bleibt auf beiden Adressen unter `/api`. Die iOS-/Android-Apps müssen nicht geändert werden.
- Anmeldung und Schlüssel im Browser gelten pro Adresse: Nach dem Umzug auf `web.` meldet man sich dort einmal neu an.
- Auf einer Demo-Instanz (`DEMO_MODE=1`) führt `/` direkt zur App.
- **Links auf der Landingpage** kommen aus der `.env` und erscheinen nur, wenn sie gesetzt sind: `DEMO_URL`, `BLOG_URL`,
  `SOURCE_URL` (Quellcode), `PLAY_URL`, `FDROID_URL`, `APPSTORE_URL`. Ohne Store-Links steht dort „Bald verfügbar“.
- **Roadmap und Texte** stehen in `landing.py` (Deutsch und Englisch). Die Bildschirmfotos in `static/landing/` stammen aus der Demo.

## Ein Tag in der App

Die Startseite („Heute“) ist bewusst kurz gehalten und folgt dem Tag:

- **Morgen-Check-in:** Stimmung, Angst und Antrieb (je 1–10, wie am Abend) und optional ein Vorhaben, „das Eine, das heute zählt“.
  Grafik, Muster und Bericht nehmen die Abendwerte; fehlt der Check-out, die Werte vom Morgen. Ältere Check-ins mit
  Stimmung und Energie (1–5) bleiben lesbar, fließen aber nicht in die Grafik ein.
- **Gefühle:** tagsüber ein Gefühl antippen, Stärke wählen (leicht, mittel, stark) und optional den Auslöser notieren. Jedes Gefühl wird mit Uhrzeit gespeichert. Die Auswahl betont Gefühle, die in einer Depression häufig sind (leer, hoffnungslos, erschöpft, überfordert …), dazu leichtere Gefühle und ein freies Feld. Bei „hoffnungslos“, „wertlos“ oder „leer“ in starker Ausprägung erscheint ein Hinweis auf die Telefonseelsorge.
- **Abend-Check-out:** Stimmung, Angst und Antrieb (1–10), Vorhaben geschafft?, Aktivitäten, Medikamente und Notiz. Ab 17 Uhr ist er geöffnet, vorher mit einem Tipp.
- **Tagesübersicht:** alles des Tages in zeitlicher Reihenfolge, auch Tabletten-Einnahmen. Gefühle lassen sich dort antippen und ändern.
- **Mein Verlauf:** PHQ-9 und GAD-7 als Monatsbalken (letzter Fragebogen im Monat) mit Hinweis, wann der nächste fällig ist.

Verlauf, Muster, Tabletten, Notizen für die Sitzung, PDF-Bericht und Sicherheit stehen unter **„Verlauf & mehr“**.
Gefühle erscheinen im PDF-Bericht (Übersicht und bei jedem Tag) und lassen sich als CSV herunterladen.

## Add-ons

Der Kern bleibt schlicht: Konto und Verschlüsselung, Morgen-Check-in und Abend-Check-out, Tagesübersicht, Verlauf,
Krisenplan und Krisenmodus, Export. Alles Weitere schaltet man unter **„Verlauf & mehr“ → „Add-ons“** ein:

| Add-on | Infoseite | Inhalt |
|---|---|---|
| Gefühle | `gefuehle.kopfwetter.app` | Gefühle mit Stärke, Auslöser und Uhrzeit, CSV |
| Fragebögen | `fragebogen.kopfwetter.app` | PHQ-9 und GAD-7 mit Monatsverlauf |
| Tabletten | `tabletten.kopfwetter.app` | Medikamente, Einnahmen, Tagesüberblick im Check-out, CSV |
| Muster | `muster.kopfwetter.app` | Jahresübersicht, Wochentage, Aktivitäten |
| Therapie | `therapie.kopfwetter.app` | Notizen für die Sitzung, PDF-Bericht |

- **Gespeichert** wird die Auswahl verschlüsselt im Datensatz `prefs`; sie gilt damit in der App und im Browser.
- **Neue Konten:** alle Add-ons aus. Konten von vor den Add-ons: an, was schon Daten hat.
- **Ausschalten** blendet nur aus; die Einträge bleiben verschlüsselt erhalten. Der PDF-Bericht enthält nur Daten eingeschalteter Add-ons.
- **Infoseiten:** `ADDON_DOMAIN=kopfwetter.app` setzen und im Cloudflare-Tunnel die fünf Hostnamen auf denselben Dienst
  zeigen lassen. Ohne `ADDON_DOMAIN` liegen sie unter `/addon/<name>`. „In Kopfwetter einschalten“ führt zu
  `WEB_URL/?addon=<name>`: Nach der Anmeldung öffnen sich die Add-on-Einstellungen mit dem Add-on hervorgehoben.
- Texte der Infoseiten stehen in `landing.py` (`ADDON_INFO`).

## Krisenmodus

Für schwere Phasen, etwa eine depressive Episode. Ein Tipp auf „Schwere Phase? Krisenmodus einschalten“ unter den Tabs
genügt, ohne Begründung; „Krisenmodus beenden“ schaltet ihn genauso leicht wieder aus. Der Zustand wird verschlüsselt
gespeichert (`crisis-<Datum>-…` mit Beginn und Ende) und gilt auf allen Geräten.

- **Nur das Nötigste:** Tabs, Check-ins, Gefühle, Fragebögen, Grafik, Muster und Tabletten sind ausgeblendet, nicht gelöscht.
  Größere Schrift, ruhige Farben, keine Fälligkeiten oder Bewertungen.
- **Hilfe ganz oben:** Kontakte aus dem Krisenplan mit Anruf-Taste, „Was dir hilft“ und „Was dir wichtig ist“ aus dem
  Krisenplan, Telefonseelsorge und Notruf. Ohne Krisenplan ein Hinweis, ihn in ruhigeren Zeiten anzulegen.
- **„Ich bin in Gefahr“:** öffnet sofort Notruf 112, Telefonseelsorge und die Kontakte mit Telefonnummer. Nichts wird gespeichert.
- **Wie geht’s gerade?** Fünf große Felder (gespeichert als 1, 3, 5, 7, 9 auf der Skala 1–10), Angst und Antrieb nur auf Wunsch.
  Ohne Morgen-Check-in landen die Werte dort, sonst beim Abend – so passen Grafik und Bericht weiter.
- **Ein kleiner Schritt:** Getrunken, gegessen, Tabletten, Tageslicht, Zähne oder Dusche, jemandem geschrieben. Zum Abhaken,
  nichts davon ist Pflicht (Feld `steps` im Tageseintrag).

## Tabletten: Einnahmen mit Uhrzeit

In der Karte „Tabletten“ legst du unter „Medikamente verwalten“ deine Medikamente an: Name, Dosis und optional die geplanten
Uhrzeiten (z. B. `08:00, 20:00`; leer = bei Bedarf). Danach gilt:

- **„Jetzt eingenommen“** trägt die Einnahme mit der aktuellen Uhrzeit ein. Für vergangene Tage öffnet sich ein Formular mit der
  nächsten offenen geplanten Zeit.
- **„Andere Einnahme eintragen“** erfasst eine Einnahme mit frei wählbarer Uhrzeit, Datum, Dosis und Notiz (z. B. Nebenwirkungen).
- Pro Tag siehst du die geplanten Zeiten: ✓ mit der tatsächlichen Uhrzeit, „noch offen“ (überfällig) oder „nicht eingetragen“.
- Einnahmen antippen, um sie zu ändern oder zu löschen. Medikamente lassen sich archivieren; alte Einnahmen bleiben erhalten.
- Die Karte folgt dem Tag, der oben im Tagebuch gewählt ist.
- **Export:** „Einnahmen herunterladen (CSV)“ und ein eigener Abschnitt im PDF-Bericht. Der Abschnitt zeigt eine Übersicht je
  Medikament (Anzahl und Anteil der geplanten Einnahmen) und alle Einnahmen mit Uhrzeit.
- Alles ist Ende-zu-Ende verschlüsselt. Der Server sieht weder Datum noch Uhrzeit noch Medikament.

Der bisherige Tagesüberblick „Medikamente“ im Tagebucheintrag bleibt als grobe Angabe erhalten.

## Krisenplan

Über den Knopf **„Krisenplan“** oben rechts erreichbar, außerdem direkt aus dem Hinweis bei Frage 9 des PHQ-9. Aufbau nach dem
Vorbild des Safety Plans von Stanley & Brown in sieben Schritten: Warnzeichen, was ich selbst tun kann, Menschen und Orte zur
Ablenkung, Menschen, die ich um Hilfe bitten kann, fachliche Hilfe, Umgebung sicherer machen, was mir wichtig ist.
Telefonnummern sind antippbar. Telefonseelsorge, 116 117 und 112 stehen immer automatisch darin. „Als PDF speichern“ erzeugt
eine Seite zum Ausdrucken, damit der Plan auch ohne Handy greifbar ist. Gespeichert wird er verschlüsselt (`items`, ID `plan-crisis`).

## Muster

Die Karte „Muster“ zeigt, nur auf dem Gerät berechnet:
- eine **Jahresübersicht** als Kalender (eine Zelle pro Tag, gefärbt nach Stimmung),
- die durchschnittliche Stimmung **nach Wochentag** (30 Tage, 3 Monate oder 1 Jahr),
- **Aktivitäten**: Stimmung an Tagen mit und ohne die Aktivität, sortiert nach Unterschied. Angezeigt erst ab je drei Tagen mit und ohne.

Bewusst nur beschreibend: keine Diagnosen, keine Empfehlungen.

## Für die nächste Sitzung

Eine Liste mit Punkten, die du in der Therapie ansprechen willst. Abhaken verschiebt sie nach „Besprochen“. Offene Punkte
stehen im PDF-Bericht ganz oben, abschaltbar über „Offene Punkte einschließen“. Verschlüsselt in `items` (`sess-…`).

## Angst-Selbsttest (GAD-7)

Neben dem PHQ-9 und mit derselben Bedienung: sieben Fragen im Wortlaut der deutschen Fassung (Löwe et al.), Summe 0–21
(0–4 minimal, 5–9 leicht, 10–14 mäßig, 15–21 schwer), Verlauf, Erinnerung nach 14 Tagen und ein eigener Abschnitt im PDF-Bericht.
Gespeichert in `assessments` mit der ID `gad7-…` und `gad7:<id>` als AAD.

## Depressions-Selbsttest (PHQ-9)

Im Bereich „Depressions-Selbsttest“ beantwortest du die neun Fragen des PHQ-9 (deutsche Fassung PHQ-D) zu den letzten zwei Wochen,
plus die optionale Frage zur Beeinträchtigung im Alltag. Die Auswertung erfolgt nur auf dem Gerät:

| Summe | Schweregrad |
|---|---|
| 0–4 | minimal |
| 5–9 | mild |
| 10–14 | mittelgradig |
| 15–19 | ausgeprägt |
| 20–27 | schwer |

- Wird **Frage 9** (Gedanken an Tod oder Selbstverletzung) mit mehr als „überhaupt nicht“ beantwortet, erscheint unabhängig von
  der Summe ein deutlicher Hinweis mit Telefonseelsorge, 116 117 und 112 (in der App als direkt wählbare Nummern).
- Antworten und Ergebnis werden **Ende-zu-Ende verschlüsselt** gespeichert (Tabelle `assessments`, die ID ist als AAD gebunden).
- Verlauf mit Diagramm, Erinnerung „wieder fällig“ nach 14 Tagen, Vergleich mit dem letzten Test.
- Im **PDF-Bericht** erscheint ein eigener Abschnitt mit Datum, Summe, Schweregrad, Frage 9 und Beeinträchtigung.
- Beim Passwortwechsel werden Tests mit neu verschlüsselt.
- Der PHQ-9 ist frei verwendbar (Kroenke, Spitzer & Williams; deutsche Fassung Löwe, Spitzer, Zipfel & Herzog).

Mit dem Test hat sich die Einwilligung geändert (`PRIVACY_VERSION` in `legal.py`). Bestehende Konten werden beim nächsten Login
einmal gefragt. Ohne Zustimmung können sie ihre Daten nur ansehen, exportieren oder das Konto löschen.

## Apps für iOS und Android

Im Ordner `mobile/` liegt ein Capacitor-8-Projekt. Die Anleitung steht in [`mobile/README.md`](mobile/README.md).

## Icon und Startbildschirm

Favicon, Apple-Touch-Icon und ein Web-App-Manifest sind dabei (`static/icons/`). Am Handy kannst du die Seite über „Zum Home-Bildschirm“ wie eine App starten.

## Bericht für die Therapie (PDF)

Im Bereich „Bericht für die Therapie“ wählst du einen Zeitraum (14 Tage, 30 Tage, 3 Monate, alles oder eigener Zeitraum),
optional deinen Namen und ob die Notizen mit hinein sollen. Das PDF enthält:

- Durchschnitt, Spanne und Trend (ältere vs. neuere Hälfte) für Stimmung, Angst und Antrieb
- Einträge pro Zeitraum, Medikamenten-Einnahme in Prozent, Tage mit niedriger Stimmung und starker Angst
- Verlaufsdiagramm
- Aktivitäten mit der durchschnittlichen Stimmung an Tagen mit und ohne die Aktivität
- alle Tageseinträge als Tabelle, auf Wunsch ohne Notizen

Das PDF entsteht im Browser (jsPDF, lokal unter `static/vendor/` ausgeliefert, MIT-Lizenz). Die Einträge bleiben also
Ende-zu-Ende verschlüsselt. Das fertige PDF ist **unverschlüsselt**: Schick es am besten nicht per normaler E-Mail,
sondern bring es mit, gib es ausgedruckt ab oder nutze den sicheren Kanal deiner Praxis.
Emojis und andere Sonderzeichen außerhalb von Windows-1252 werden im PDF weggelassen.

## Wartung (im Container)

```bash
docker compose exec kopfwetter-app python app.py list-users
docker compose exec kopfwetter-app python app.py approve <name>      # Konto freigeben
docker compose exec kopfwetter-app python app.py disable <name>      # Konto sperren
docker compose exec kopfwetter-app python app.py make-admin <name>
docker compose exec kopfwetter-app python app.py reset-2fa <name>    # neues Handy: QR-Code im Terminal + neue Wiederherstellungscodes
docker compose exec kopfwetter-app python app.py unlock <name>       # Sperre nach Fehlversuchen aufheben
docker compose exec kopfwetter-app python app.py logout-all
```

`reset-2fa` berührt die Verschlüsselung nicht, denn die hängt nur am Passwort. Ein vergessenes Passwort kann **niemand**
zurücksetzen, auch du als Admin nicht. Das Konto lässt sich dann nur löschen und neu anlegen.

## Backup

Alles steckt in `data/kopfwetter-app.db` und ist Ciphertext. Das Backup taugt also auch für unsichere Speicherorte,
solange `APP_SECRET` getrennt aufbewahrt wird:

```bash
sqlite3 data/kopfwetter-app.db ".backup 'backup/kopfwetter-app-$(date +%F).db'"
```

Zum Wiederherstellen brauchst du die DB und `APP_SECRET`, jede Person außerdem ihr Passwort und ihre Authenticator-App (oder einen Wiederherstellungscode).

## APP_SECRET erneuern

Notwendig, wenn `APP_SECRET` bekannt geworden sein könnte (z. B. in Git, in einem Chat oder einem Screenshot).
Die Tagebuchinhalte hängen nicht daran. Es schützt die 2FA-Geheimnisse und die Salts für unbekannte Benutzernamen.
Mit diesem Ablauf muss niemand die Authenticator-App neu einrichten:

```bash
cp .env .env.bak && cp data/kopfwetter-app.db data/vor-secret-wechsel.db    # Sicherung (App vorher stoppen)
# in .env: bisherigen Wert als APP_SECRET_PREVIOUS eintragen, APP_SECRET neu setzen:
#   APP_SECRET_PREVIOUS=<alter Wert>
#   APP_SECRET=<Ausgabe von: openssl rand -hex 32>
docker compose up -d --build && docker compose logs kopfwetter-app | tail
#   -> "… TOTP-Geheimnis(se) auf den aktuellen Schlüssel umgestellt."
# Danach APP_SECRET_PREVIOUS aus der .env löschen und neu starten:
docker compose up -d
```

Lässt sich ein Geheimnis mit keinem der beiden Werte lesen, bricht der Start ab und **ändert nichts**.
Die alten Sicherungen (`.env.bak`, `vor-secret-wechsel.db` und frühere Backups) enthalten das alte Geheimnis bzw. damit
verschlüsselte Daten. Lösche sie nach erfolgreichem Test (`shred -u`). Lag das alte `APP_SECRET` in Git, zusätzlich
die Historie bereinigen (siehe [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md)).

## Sprachen

Die Oberfläche gibt es auf **Deutsch und Englisch**, einschließlich PDF-Bericht, Fehlermeldungen, Demo-Daten und der
Fragebögen. PHQ-9 und GAD-7 erscheinen dabei im englischen Originalwortlaut. Die Sprache folgt der Browsereinstellung
(Deutsch für `de`, sonst Englisch) und lässt sich unten auf der Seite umschalten. Die Wahl wird im Cookie `kw-lang`
gespeichert. Die Apps folgen der Gerätesprache. Datenschutzerklärung und Impressum gibt es als englische Übersetzung
(`?lang=en`); maßgeblich ist die deutsche Fassung.

Bei Krisennummern nennt die englische Fassung neben 112 und der deutschen Telefonseelsorge auch
[findahelpline.com](https://findahelpline.com) für andere Länder.

## Demo-Instanz

Eine eigene Instanz mit `DEMO_MODE=1` zeigt statt der Anmeldung einen Knopf „Demo starten“. Jeder Besuch bekommt
ein **eigenes** Wegwerf-Konto mit erfundenen Beispieldaten aus vier Wochen: Einträge, Muster, PHQ-9, GAD-7, Tabletten,
Krisenplan und eine Notiz. Verschlüsselt wird wie in der echten App, nur Passwort und 2FA entfallen. Niemand sieht
die Daten anderer Besucher. Das ist wichtig, weil manche doch Echtes eintippen.

- Konten werden nach `DEMO_HOURS` (Standard 24) gelöscht oder sofort über „Demo beenden“.
- Registrierung, Anmeldung, Passwort, Wiederherstellung und Verwaltung sind gesperrt.
- Höchstens 10 Demo-Konten pro Stunde und IP-Adresse, insgesamt höchstens `DEMO_MAX`.
- Die Datenschutzerklärung weist automatisch auf die Demo hin.
- **Eigene Datenbank:** Die Demo startet nicht, wenn die Datenbank echte Konten enthält.

```bash
cp .env.demo.example .env.demo          # eigenes APP_SECRET und Impressumsdaten eintragen
mkdir -p data-demo && sudo chown 1000:1000 data-demo
docker compose -f compose.demo.yaml up -d --build
```

Danach im Cloudflare-Tunnel `demo.kopfwetter.app` auf `http://127.0.0.1:8087` zeigen lassen. Damit beide Seiten aufeinander verweisen, in der `.env` der echten App `DEMO_URL=https://demo.kopfwetter.app` setzen (Link auf Anmelde- und Registrierungsseite) und in der `.env.demo` `APP_URL=https://kopfwetter.app` (Link zurück). Die Demo-Datenbank
braucht kein Backup.

## Umzug per Export

Unter **Sicherheit → Alles exportieren oder importieren** lädst du alle deine Daten als JSON-Datei herunter:
Einträge, PHQ-9 und GAD-7, Medikamente und Einnahmen, Krisenplan und Notizen. In einem anderen Konto oder auf einem
anderen Server importierst du die Datei dort, und alles wird mit dem dortigen Schlüssel neu verschlüsselt.
Gleiche Tage oder Kennungen werden überschrieben, der Rest bleibt.

Das ist auch der Weg aus Versionen vor 11/2026 (Datenbank `stimmung.db`, Kennungen `stimmung/…/v1`). Diese
Version startet mit einer solchen Datenbank nicht und lässt sie unverändert:

1. In der **alten** Version anmelden und „Alles exportieren (JSON)“ wählen. Die Übergangsversion hat diesen Knopf schon.
2. Die neue Version mit einem **leeren** `data/`-Ordner und einem neuen `APP_SECRET` starten, dann ein Konto anlegen (2FA neu einrichten).
3. Unter Sicherheit die Datei importieren und danach einen neuen Wiederherstellungsschlüssel anlegen.
4. Die Exportdatei und die alte Datenbank löschen (`shred -u`), denn die Exportdatei ist **unverschlüsselt**.

## API (nur Ciphertext)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/api/auth/state` | Status, angemeldetes Konto |
| POST | `/api/auth/salt` | KDF-Salt zu einem Benutzernamen (auch für unbekannte Namen) |
| POST | `/api/auth/register/begin`, `/finish` | Registrierung mit 2FA |
| POST | `/api/auth/login`, `/logout` | Anmeldung |
| POST | `/api/auth/change-password` | neues Passwort, Datenschlüssel neu verpackt (Einträge bleiben unverändert) |
| GET | `/api/account/keys` | verpackter Datenschlüssel und Status des Wiederherstellungsschlüssels |
| POST | `/api/account/recovery` | Wiederherstellungsschlüssel anlegen oder ersetzen (Passwort und 2FA nötig) |
| POST | `/api/auth/recover/begin`, `/finish` | Passwort vergessen: Schlüssel und 2FA prüfen, neues Passwort setzen |
| POST | `/api/account/delete` | eigenes Konto löschen |
| GET | `/api/records` | `[{id, iv, ct}]`: alle Inhalte des eigenen Kontos (Einträge, Tests, Medikamente, Einnahmen, Notizen, Krisenplan) |
| PUT / DELETE | `/api/records/{id}` | `{iv, ct}`; `id` = 32 Hex-Zeichen (HMAC), AAD `kopfwetter-app/record/v1:<id>` |
| POST | `/api/account/kdf` | einmalige Umstellung von PBKDF2 auf Argon2id direkt nach dem Login |
| GET / DELETE | `/api/legacy` | einmalige Umstellung der Datensätze aus Protokoll v1 |
| GET / POST | `/api/admin/users`, `/api/admin/users/{id}` | Verwaltung (nur Admins) |
| POST | `/api/account/consent` | aktualisierte Einwilligung bestätigen |

Die Apps senden `X-Client: native` und `Authorization: Bearer <token>` statt eines Cookies.

Schreibende Anfragen brauchen den Header `X-Requested-With: kopfwetter-app`.

## Tests

```bash
pip install -r requirements.txt pytest httpx && pytest -q          # Server: CSRF, Login mit TOTP, Trennung der Konten
(cd mobile && npm ci) && node tests/vectors/check.mjs              # Testvektoren: WebCrypto und noble-Ersatz
```

Die GitLab-CI (`.gitlab-ci.yml`) führt beides bei jedem Push aus und scannt zusätzlich mit gitleaks nach Geheimnissen.

## Lizenz

Copyright © 2026 Torsten Albrecht. Kopfwetter ist freie Software unter der
[GNU Affero General Public License v3.0 oder später](LICENSE). Wer eine veränderte Fassung als Webdienst betreibt,
muss den Quellcode dieser Fassung den Nutzer*innen zugänglich machen. Komponenten Dritter und ihre Lizenzen
stehen in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## In English

**Kopfwetter** is a self-hosted, end-to-end encrypted mood diary (German UI) for people living with depression or
anxiety. It tracks mood, anxiety and drive, activities, medication intake with timestamps, the PHQ-9 and GAD-7
self-assessments, a safety plan and notes for the next therapy session. It also exports a PDF report for therapists.

- **Stack:** FastAPI and SQLite in one container, vanilla JS frontend with a strict CSP, Capacitor apps for Android and iOS
- **Security:** Argon2id with TOTP 2FA, rate limits and lockout. Content is encrypted on the device with AES-256-GCM under a random data key, which is wrapped by a key derived from the password (Argon2id → HKDF) and optionally by a 160-bit recovery key. The server only ever stores ciphertext. See [docs/CRYPTO.md](docs/CRYPTO.md) for the key hierarchy, the threat model and its limits, and [tests/vectors](tests/vectors) for test vectors.
- **Security issues:** please report them privately, see [SECURITY.md](SECURITY.md).
- **License:** AGPL-3.0-or-later

