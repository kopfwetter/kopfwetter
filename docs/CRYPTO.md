# Kryptografie und Bedrohungsmodell

> Die Spezifikation wird auch eigenständig gepflegt, mit Testvektoren und Entwürfen für Teilen und
> Post-Quanten-Kryptografie: Repository **kopfwetter/crypto** (Apache-2.0).

Stand: Protokoll `kopfwetter-app/v2` (in der Datenbank unter `meta.protocol`).
Die Testvektoren in [`tests/vectors/vectors.json`](../tests/vectors/vectors.json) legen jedes Verfahren auf Bytes fest.
Erzeugt werden sie unabhängig mit Python (`argon2-cffi`, `cryptography`). Geprüft werden sie mit WebCrypto und mit
dem noble-Ersatz (`node tests/vectors/check.mjs`), Argon2id dabei jeweils mit hash-wasm wie in der App.

## Ziel

Der Server soll Tagebuchinhalte, Fragebögen, Medikamente, Krisenplan und Sitzungsnotizen **nie im Klartext** sehen,
auch nicht der Betreiber, ein Backup oder ein Angreifer mit Zugriff auf die Datenbank. Er soll außerdem möglichst wenig
darüber erfahren, **wann** und **was** jemand einträgt. Ver- und entschlüsselt wird ausschließlich auf dem Gerät.

## Schlüsselhierarchie

```
Passwort ──NFKC──► Argon2id (m = 64 MiB, t = 3, p = 1, 16-Byte-Salt pro Konto) ──► master (32 B)
master ──HKDF-SHA256 "kopfwetter-app/auth/v1"──► authKey ──► Server speichert nur Argon2id(authKey)
master ──HKDF-SHA256 "kopfwetter-app/kek/v1" ──► KEK (AES-256-GCM)

DEK (32 Zufallsbytes) ── wrappedKey      = AES-GCM(KEK,         DEK, AAD "kopfwetter-app/dek/v1")  ── auf dem Server
                      └─ recoveryWrapped = AES-GCM(recoveryKEK, DEK, AAD "kopfwetter-app/dek/v1")  ── optional
DEK ──► encKey = AES-256-GCM (nicht exportierbar)                 ── verschlüsselt alle Inhalte
DEK ──HKDF "kopfwetter-app/record-id/v1"──► idKey = HMAC-SHA256   ── bildet die Kennungen der Datensätze

Wiederherstellungsschlüssel: 160 Zufallsbits, 32 Zeichen aus ABCDEFGHJKLMNPQRSTUVWXYZ23456789, Vierergruppen
recovery ──HKDF "kopfwetter-app/recovery-auth/v1"──► recoveryAuth ──► Server speichert nur Argon2id(recoveryAuth)
recovery ──HKDF "kopfwetter-app/recovery-kek/v1" ──► recoveryKEK
```

HKDF nutzt ein leeres Salt (laut RFC 5869 gleichbedeutend mit 32 Nullbytes). Jede AES-GCM-Verschlüsselung erhält eine
frische 96-Bit-IV aus `crypto.getRandomValues`, der 128-Bit-Tag hängt am Chiffrat.

Die Parameter der Ableitung stehen pro Konto in `users.kdf` und kommen mit dem Salt vom Server. Der Client akzeptiert
nur Argon2id mit mindestens m = 64 MiB und t = 3 oder, ausschließlich zum Anmelden von v1-Konten, PBKDF2-SHA256 mit
mindestens 600 000 Runden. Schwächere Vorgaben eines manipulierten Servers lehnt er ab.

## Datensätze

Alle Inhalte liegen in einer Tabelle `records(user_id, id, iv, ct)`, ohne Zeitstempel.

```
id        = hex(HMAC-SHA256(idKey, Art + ":" + Schlüssel)[0:16])       z. B. Art "entry", Schlüssel "2026-11-04"
Klartext  = JSON {"k": Art, "key": Schlüssel, "d": Inhalt}, mit Leerzeichen aufgefüllt
ct        = AES-GCM(encKey, Klartext, AAD "kopfwetter-app/record/v1:" + id)
```

| Art | Schlüssel | Inhalt |
| --- | --- | --- |
| `entry` | Datum `YYYY-MM-DD` | Stimmung, Angst, Antrieb, Aktivitäten, Notiz |
| `assess` | Kennung des Tests (enthält Datum und Typ) | Antworten, Punktwert, Zeitpunkt |
| `item` | `med-…`, `dose-<Datum>-…`, `feel-<Datum>-…`, `crisis-<Datum>-…`, `sess-…`, `plan-crisis`, `prefs` | Medikament, Einnahme, Gefühl, Krisenmodus, Notiz, Krisenplan, Einstellungen (Add-ons) |

- **Kennung:** Sie ist deterministisch. Speichern überschreibt deshalb den Eintrag desselben Tages, ohne dass der Server das Datum kennt. Ohne `idKey` lässt sie sich nicht zurückrechnen.
- **Vertauschen:** Die Kennung steckt in der AAD. Beim Laden prüft der Client außerdem, dass `HMAC(Art:Schlüssel)` aus dem entschlüsselten Inhalt wieder die Kennung ergibt. Ein Datensatz lässt sich so weder auf einen anderen Tag noch in eine andere Art verschieben.
- **Auffüllen:** Der Klartext wird auf 256 Byte aufgefüllt, darüber auf die nächste Zweierpotenz bis 64 KiB, darüber auf Vielfache von 16 KiB. JSON erlaubt Leerzeichen am Ende.

## Abläufe

- **Registrierung:** Der Client erzeugt den DEK und schickt `authKey` sowie `wrappedKey`. Das Salt leitet der Server aus `APP_SECRET` und dem Benutzernamen ab (HMAC). So verrät die Salt-Abfrage nicht, ob ein Konto existiert.
- **Anmeldung:** `authKey` und ein TOTP-Code (Wiederholungsschutz pro Zeitschritt) oder einer von zehn Einmal-Codes. Der Server gibt `wrappedKey` zurück. Der Client packt den DEK aus und legt `encKey` und `idKey` als nicht exportierbare `CryptoKey` in IndexedDB ab, es sei denn, die Sperre steht auf „beim Schließen“.
- **Sperre:** Nach der eingestellten Zeit ohne Bedienung (5, 15 oder 60 Minuten, beim Schließen oder nie) löscht der Client beide Schlüssel und lädt die Seite neu. Die Sitzung bleibt gültig. Entsperrt wird mit dem Passwort: Der Client leitet den KEK ab und packt `wrappedKey` aus. Nach fünf falschen Passwörtern meldet er ab.
- **Passwortwechsel:** neuer `authKey` und neu verpackter DEK, die Inhalte bleiben unverändert. Erlaubt nur mit altem Passwort und zweitem Faktor.
- **Wiederherstellung:** Wiederherstellungsschlüssel und zweiter Faktor ergeben `recoveryWrapped` und damit den DEK. Danach setzt der Client ein neues Passwort und packt den DEK neu ein. Ohne Passwort und ohne Wiederherstellungsschlüssel sind die Daten verloren. Das ist Absicht, es gibt keine Hintertür.
- **Export und Import:** Der Client entschlüsselt alles in eine JSON-Datei und verschlüsselt sie beim Import mit dem DEK des Zielkontos neu. Der Server sieht dabei nur Chiffrate, die Datei selbst ist aber Klartext.

### Umstellung von Protokoll v1

v1 nutzte PBKDF2-SHA256 mit 600 000 Runden und drei Tabellen. Das Datum bzw. die Kennung (`dose-2026-11-03-…`) stand dort im Klartext und diente als AAD.

- **Server:** Beim ersten Start hebt er die Datenbank auf v2. Er setzt `users.kdf` auf PBKDF2 und lässt die alten Tabellen stehen.
- **Ableitung:** Beim nächsten Login leitet der Client mit PBKDF2 ab und packt den DEK aus. Danach leitet er mit Argon2id neu ab und schickt neuen `authKey` und neuen `wrappedKey` an `/api/account/kdf`. Der Server prüft dabei den alten `authKey`. Der DEK bleibt gleich.
- **Datensätze:** Der Client liest die alten Datensätze über `/api/legacy`, legt sie als `records` neu an und löscht sie danach. Sobald kein Konto mehr alte Daten hat, löscht der Server die alten Tabellen.

### Fehlende WebCrypto-Unterstützung

`mobile/src/subtle-polyfill.js` bildet die genutzten Teile von `crypto.subtle` (PBKDF2, HKDF, HMAC, AES-GCM) mit
`@noble/hashes` und `@noble/ciphers` nach. Beide sind extern auditiert. Der Ersatz wird nur aktiv, wenn das WebView
kein WebCrypto anbietet. Argon2id kommt immer aus hash-wasm (WebAssembly). Dafür erlaubt die CSP `'wasm-unsafe-eval'`,
das ausschließlich das Übersetzen von WebAssembly zulässt, kein `eval` von JavaScript.

## Was der Server sieht

| Sieht der Server | Sieht der Server nicht |
| --- | --- |
| Benutzername, Zeitpunkt von Registrierung, Einwilligung und letzter Anmeldung, IP-Adressen (Rate-Limits, nur im Speicher) | Passwort, `master`, KEK, DEK, `idKey` |
| Anzahl der Datensätze und ihre Größenklasse | Datum, Art und Änderungszeitpunkt eines Datensatzes |
| wann gespeichert wird, solange er Anfragen mitschneidet (ein mitlesender Server sieht den Zeitpunkt jedes Speicherns) | Stimmung, Notizen, Aktivitäten, Medikamente, Einnahmezeiten |
| TOTP-Geheimnis (Fernet, Schlüssel = SHA-256(`kopfwetter-app/totp/v1:` + `APP_SECRET`), wechselbar über `APP_SECRET_PREVIOUS`) | Antworten und Punktwerte von PHQ-9/GAD-7, Krisenplan, Sitzungsnotizen |

## Bedrohungsmodell

**Geschützt gegen:**
- **Diebstahl der Datenbank oder eines Backups:** Die Inhalte bleiben verschlüsselt. Offline lässt sich nur das Passwort raten, und jeder Versuch kostet eine Argon2id-Berechnung mit 64 MiB Speicher. Das bremst Grafikkarten und Spezialhardware deutlich stärker als PBKDF2.
- Neugierige Betreiber mit Datenbankzugriff, auch was Datum und Art der Einträge angeht
- Vertauschen oder Verschieben verschlüsselter Datensätze (AAD mit Kennung, Prüfung der Kennung beim Laden)
- **Online-Raten von Passwörtern:** Argon2id, Rate-Limits pro IP, Sperre nach fünf Fehlversuchen, zweiter Faktor
- **Unbeaufsichtigtes, entsperrtes Gerät:** automatische Sperre nach einstellbarer Zeit
- **CSRF:** eigener Header, Origin-Prüfung, `SameSite=Strict`, `__Host-`-Cookie
- **Fremdes Skript:** strikte CSP ohne Inline-Code und ohne externe Quellen

**Nicht geschützt gegen:**
- **Einen bösartigen oder kompromittierten Server im Web-Betrieb.** Er kann veränderten JavaScript-Code ausliefern, der das Passwort abgreift. Das gilt grundsätzlich für Ende-zu-Ende-Verschlüsselung im Browser. Die Apps bringen ihren Code mit und sind davon weniger betroffen.
- Ein kompromittiertes Endgerät (Schadsoftware, Tastatur-Mitschnitt)
- Sehr schwache Passwörter, wenn die Datenbank gestohlen wurde
- **Verkehrsanalyse:** Ein mitlesender Server oder Netzbetreiber sieht, wann gespeichert wird. Gespeicherte Daten verraten das nicht mehr.

## Bekannte Grenzen und geplante Verbesserungen

- **Sicherheitsschlüssel:** Entsperren mit Passkey oder Sicherheitsschlüssel (WebAuthn PRF) würde das Raten von Passwörtern ganz ausschließen.
- **Biometrie in den Apps:** Entsperren per Fingerabdruck oder Gesicht ist noch nicht eingebaut. Dort gilt dieselbe Sperre wie im Browser.
- **Audit:** Bisher gibt es kein externes Audit. Befunde bitte nach [SECURITY.md](../SECURITY.md) melden.
