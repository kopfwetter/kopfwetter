# Kopfwetter für iOS und Android (Capacitor 8)

Die App enthält dieselbe Oberfläche wie die Website (`../static`). Sie wird beim Bauen in die App kopiert, statt nur die
Website anzuzeigen. Die App spricht über HTTPS mit deinem Server. Einträge und Tests sind wie im Browser
Ende-zu-Ende verschlüsselt.

| | Web | App |
|---|---|---|
| Anmeldung | HttpOnly-Cookie, 12 h | Bearer-Token im **Keychain / Android Keystore**, 7 Tage (`NATIVE_SESSION_HOURS`) |
| Verschlüsselung | WebCrypto | WebCrypto, bei Bedarf ein bitgleicher Ersatz (noble, auditiert) |
| PDF/CSV | Download | Teilen-Menü (Dateien, Mail, AirDrop, Drucken …). Die Kopie im App-Cache wird nach 2 Minuten gelöscht |
| Cloud-Backup | – | auf Android abgeschaltet (Schlüssel bleiben auf dem Gerät) |

## Voraussetzungen

- Node.js 20 oder neuer
- **iOS:** ein Mac mit aktuellem Xcode. Für echte Geräte und den App Store: Apple Developer Program (99 USD/Jahr). Der Simulator ist kostenlos.
- **Android:** Android Studio (SDK 36). Für Google Play: einmalig 25 USD.
- Dein Server muss per **HTTPS mit gültigem Zertifikat** erreichbar sein (zum Beispiel über den Cloudflare Tunnel).

## Einrichten

1. **Server-Adresse** in `app.config.json`: voreingestellt ist `"server": "https://kopfwetter.app"`.
2. **App-ID** in `capacitor.config.json` prüfen (`app.kopfwetter`). Nimm eine Domain, die dir gehört, in umgekehrter
   Schreibweise. Nach der ersten Veröffentlichung lässt sie sich nicht mehr ändern. Wenn du sie änderst, auch in
   `android/app/build.gradle` (`applicationId`, `namespace`) und im Xcode-Projekt (Bundle Identifier) anpassen.
3. Bauen und öffnen:

```bash
npm install
npm run ios        # baut www/, synchronisiert und öffnet Xcode
npm run android    # baut www/, synchronisiert und öffnet Android Studio
```

In Xcode: Team unter *Signing & Capabilities* wählen und dann Run (Simulator oder iPhone).
In Android Studio: Run (Emulator oder Gerät).

**Teste zuerst im Simulator,** ob die Anmeldung klappt und oben „Ende-zu-Ende verschlüsselt“ steht.

Nach jeder Änderung an der Weboberfläche (`../static`) genügt `npm run sync` und ein neuer Build.

## Server-Einstellungen für die App

In der `.env` des Servers (die Standardwerte passen meistens):

```
NATIVE_ORIGINS=capacitor://localhost,https://localhost   # iOS bzw. Android
NATIVE_SESSION_HOURS=168                                 # Anmeldedauer in der App
```

**Cloudflare Access:** Wenn vor deinem Server eine Access-Policy mit Browser-Login liegt, kommt die App nicht durch.
Nimm dann `/api/*` von der Policy aus (oder verzichte auf Access). Die App hat ohnehin eine eigene Anmeldung mit 2FA.

## Icons und Startbildschirm

Die Quellen liegen in `assets/` und sind aus dem Favicon-Design erzeugt. Nach Änderungen:

```bash
npm run assets && npx cap sync
```

## In die Stores bringen – worauf achten

- **Datenschutz-URL:** `https://kopfwetter.app/datenschutz` (wird bei Apple und Google verlangt).
- **Konto löschen in der App:** ist vorhanden (Sicherheit → Konto löschen). Apple verlangt das für Apps mit Registrierung.
- **Zugang für das Review:** Lege vorab ein freigegebenes Testkonto an und gib in den Review-Notizen Benutzername, Passwort und
  einen **Wiederherstellungscode** oder das 2FA-Geheimnis an. Sonst kann das Review die App nicht testen. Lösche das Konto danach.
- **Gesundheit:** In App Store Connect bei *App-Datenschutz* Gesundheitsdaten angeben. Bei Google Play die Erklärung für
  Gesundheits-Apps und den Abschnitt *Datensicherheit* ausfüllen. In der App stehen Hinweise, dass sie keine Diagnose stellt
  und keine Behandlung ersetzt, und es gibt Krisennummern. Das gehört bei Mental-Health-Apps dazu.
- **Altersfreigabe:** Wegen der Themen Depression und Suizidgedanken (PHQ-9, Frage 9) die Fragebögen entsprechend beantworten.
- Wenn die App nur für dich und wenige Menschen gedacht ist, ist **TestFlight** (iOS) bzw. ein **interner Test-Track** (Android)
  einfacher als eine öffentliche Veröffentlichung.

## Was hier nicht getestet werden konnte

Die native Kompilierung (Xcode, Gradle) konnte nicht hier laufen, weil dafür macOS und das Android-SDK fehlen. Getestet sind:
die Anbindung über einen fremden Origin mit Bearer-Token und ohne Cookies, die CORS-Regeln, das Speichern über die
Plattform-Schicht und die Bit-Gleichheit des Krypto-Ersatzes mit WebCrypto, auch im echten App-Ablauf.

## Mögliche nächste Schritte

- App-Sperre mit Face ID / Fingerabdruck beim Öffnen
- tägliche Erinnerung per lokaler Benachrichtigung (`@capacitor/local-notifications`), etwa alle 14 Tage für den PHQ-9
