# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Landingpage für kopfwetter.app: Funktionen, Sicherheit, Apps, Roadmap, Fragen. Die Web-App liegt unter WEB_URL (sonst /app).

Serverseitig erzeugt, ohne JavaScript. Links zu Stores, Quellcode, Blog und Demo kommen aus der .env und
erscheinen nur, wenn sie gesetzt sind (nie erfundene Adressen)."""
from __future__ import annotations

import os
from html import escape

env = os.environ.get


def _https(key: str) -> str:
    v = env(key, "").strip()
    return v if v.startswith("https://") and not any(c in v for c in ' "<>') else ""


def _heat() -> str:
    """Jahresübersicht als Beispielmuster (immer gleich): leerer Anfang, dann langsam besser werdende Wochen."""
    seed, cells = 7, []

    def rnd():
        nonlocal seed
        seed = (seed * 1103515245 + 12345) % 2147483648
        return seed / 2147483648
    for i in range(182):
        week, level = i // 7, 0
        if not (week < 6 and rnd() < 0.85):
            level = max(1, min(5, round(1.6 + week / 9 + (rnd() - 0.5) * 2.6)))
            if rnd() < 0.08:
                level = 0
        cells.append(f'<span class="h{level}"></span>')
    return "".join(cells)


# Roadmap: (Status, Titel, Text). Status: done | doing | next
ROADMAP = {
    "de": [
        ("done", "Add-ons und Krisenmodus", "Ein schlichter Kern; Gefühle, Fragebögen, Tabletten, Muster und Therapie lassen sich einschalten. Ein Krisenmodus für schwere Phasen."),
        ("done", "Morgen-Check-in, Gefühle und Abend-Check-out", "Ein einfacher Tagesablauf mit Tagesübersicht und Fragebögen als Monatsverlauf."),
        ("done", "Englische Fassung", "Oberfläche, Fragebögen im Originalwortlaut, PDF-Bericht und Rechtstexte."),
        ("done", "Stärkere Verschlüsselung", "Argon2id statt PBKDF2, zufälliger Datenschlüssel, Kennungen und Längen verraten nichts mehr."),
        ("doing", "Apps für Android und iOS", "Die Apps sind gebaut und werden für Google Play, F-Droid und den App Store vorbereitet."),
        ("next", "Entsperren per Fingerabdruck oder Face ID", "Schnell entsperren, ohne jedes Mal das Passwort einzugeben. Der Schlüssel bleibt im sicheren Speicher des Geräts."),
        ("next", "Erinnerungen", "Auf Wunsch eine leise Erinnerung an Check-in, Check-out und den nächsten Fragebogen, direkt auf dem Gerät."),
        ("next", "Add-on Journal", "Ausführlich über Gefühle und den Tag schreiben, mit Impulsen und Suche nur auf dem Gerät."),
        ("next", "Add-on Teilen", "Ausgewählte Einträge über einen verschlüsselten Link mit zweitem Code für Psychiaterin oder Psychologen freigeben."),
        ("next", "Post-Quanten-Kryptografie", "Hybride, quantensichere Verfahren überall dort, wo öffentliche Schlüssel im Spiel sind."),
    ],
    "en": [
        ("done", "Add-ons and crisis mode", "A simple core; feelings, questionnaires, medication, patterns and therapy can be turned on. A crisis mode for hard times."),
        ("done", "Morning check-in, feelings and evening check-out", "A simple daily flow with a day overview and questionnaires as a monthly chart."),
        ("done", "English version", "Interface, questionnaires in their original wording, PDF report and legal pages."),
        ("done", "Stronger encryption", "Argon2id instead of PBKDF2, a random data key, and record IDs and sizes no longer reveal anything."),
        ("doing", "Apps for Android and iOS", "The apps are built and are being prepared for Google Play, F-Droid and the App Store."),
        ("next", "Unlock with fingerprint or Face ID", "Unlock quickly without typing your password every time. The key stays in the device's secure storage."),
        ("next", "Reminders", "If you like, a gentle reminder for check-in, check-out and the next questionnaire, right on your device."),
        ("next", "Journal add-on", "Write at length about feelings and your day, with prompts and search only on your device."),
        ("next", "Share add-on", "Give your psychiatrist or psychologist access to selected entries through an encrypted link with a second code."),
        ("next", "Post-quantum cryptography", "Hybrid, quantum-safe methods wherever public keys are involved."),
    ],
}

T = {
    "de": {
        "title": "Kopfwetter – ein Stimmungstagebuch, das nur du lesen kannst",
        "desc": "Kopfwetter ist ein schlichtes, Ende-zu-Ende-verschlüsseltes Stimmungstagebuch mit Morgen-Check-in, Abend-Check-out und Krisenplan. Add-ons: Gefühle, Fragebögen, Tabletten, Muster, Therapie. Open Source.",
        "nav": ["Funktionen", "Add-ons", "Sicherheit", "Apps", "Roadmap", "Fragen"],
        "open": "Web-Version öffnen", "demo": "Demo ausprobieren",
        "eyebrow": "Open Source · Ende-zu-Ende-verschlüsselt",
        "h1": "Ein Stimmungstagebuch, das nur du lesen kannst.",
        "lead": "Morgens kurz einchecken, abends auf den Tag zurückschauen. Alles Weitere schaltest du als Add-on dazu: Gefühle, Fragebögen, Tabletten, Muster und Therapie.",
        "day_h": "Ein Tag mit Kopfwetter",
        "day": [("Morgens", "Stimmung, Angst und Antrieb antippen, dazu das Eine, das heute zählt. Dauert eine halbe Minute."),
                ("Tagsüber", "Mit dem Add-on Gefühle: antippen, Stärke wählen, Auslöser notieren. Es wird mit Uhrzeit gespeichert."),
                ("Abends", "Noch einmal Stimmung, Angst und Antrieb, dazu was du gemacht hast und ob das Vorhaben geklappt hat.")],
        "feat_h": "Funktionen",
        "feat": [
            ("Morgen-Check-in und Abend-Check-out", "Stimmung, Angst und Antrieb zweimal am Tag, dazu ein Vorhaben, Aktivitäten und eine Notiz."),
            ("Tagesübersicht", "Alles vom Tag in zeitlicher Reihenfolge. Du siehst, wann was war."),
            ("Verlauf", "Die letzten 30 Tage als Grafik und alle Einträge im Überblick."),
            ("Krisenplan", "Warnzeichen, was dir hilft und wen du anrufen kannst, nach dem Safety Plan von Stanley und Brown."),
            ("Krisenmodus", "Für schwere Phasen: nur noch Hilfe, eine Frage zum Befinden und kleine Schritte."),
            ("Deutsch und Englisch", "Die ganze App in beiden Sprachen, Export jederzeit."),
        ],
        "addons_h": "Add-ons",
        "addons_lead": "Kopfwetter bleibt schlicht. Was du zusätzlich brauchst, schaltest du in der App ein. Die Einstellung gilt in der App und im Browser.",
        "more": "Mehr erfahren",
        "sec_h": "Sicherheit",
        "sec_lead": "Deine Einträge werden auf deinem Gerät verschlüsselt, bevor sie den Server erreichen. Der Server speichert nur Datensätze, die er nicht lesen kann.",
        "sec": [
            ("Ende-zu-Ende verschlüsselt", "AES-256-GCM mit einem zufälligen Datenschlüssel, geschützt durch dein Passwort (Argon2id). Der Server sieht weder Inhalt noch Datum oder Art eines Eintrags."),
            ("Zwei-Faktor-Anmeldung", "Anmeldung nur mit Passwort und Code aus einer Authenticator-App. Optional ein Wiederherstellungsschlüssel zum Ausdrucken."),
            ("Kein Tracking", "Keine Werbung, keine Analyse-Dienste, keine Skripte oder Schriften von fremden Servern."),
            ("Offen und prüfbar", "Der Quellcode steht unter AGPL-3.0. Du kannst Kopfwetter auch auf deinem eigenen Server betreiben."),
        ],
        "apps_h": "Apps",
        "apps_lead": "Kopfwetter läuft im Browser auf jedem Gerät. Die Apps für Android und iOS folgen.",
        "web": ("Web-Version", "Im Browser auf Computer, Tablet und Handy. Mit Anmeldung und Zwei-Faktor-Code."),
        "android": ("Android", "Bald bei Google Play und F-Droid."), "ios": ("iPhone und iPad", "Bald im App Store."),
        "soon": "Bald verfügbar", "play": "Bei Google Play", "fdroid": "Bei F-Droid", "appstore": "Im App Store",
        "road_h": "Roadmap", "st": {"done": "Erledigt", "doing": "In Arbeit", "next": "Geplant"},
        "faq_h": "Fragen",
        "faq": [
            ("Wer kann meine Einträge lesen?", "Nur du. Die Einträge werden mit einem Schlüssel verschlüsselt, der nur mit deinem Passwort entsteht. Auch wer den Server betreibt, kann sie nicht lesen."),
            ("Was passiert, wenn ich mein Passwort vergesse?", "Mit einem Wiederherstellungsschlüssel kannst du ein neues Passwort setzen. Ohne ihn lassen sich die Einträge nicht wiederherstellen, das ist der Preis der Verschlüsselung. Lege ihn in der App unter „Sicherheit“ an."),
            ("Ersetzt Kopfwetter eine Therapie?", "Nein. Kopfwetter ist ein Tagebuch zur Selbstbeobachtung. Es stellt keine Diagnosen und ersetzt keine ärztliche oder psychotherapeutische Behandlung. Es kann aber helfen, Gespräche mit deiner Ärztin oder deinem Therapeuten vorzubereiten."),
            ("Kann ich meine Daten mitnehmen?", "Ja. Du kannst alles als Datei exportieren und in ein anderes Konto oder auf einen anderen Server importieren, dazu CSV-Dateien und den PDF-Bericht."),
            ("Kann ich Kopfwetter selbst betreiben?", "Ja. Kopfwetter ist ein einzelner Container mit SQLite und steht unter der AGPL-3.0."),
        ],
        "crisis": "<strong>In einer akuten Krise</strong> erreichst du die Telefonseelsorge rund um die Uhr, kostenlos und anonym: "
                  '<a href="tel:08001110111">0800 111 0 111</a> oder <a href="tel:08001110222">0800 111 0 222</a>. Im Notfall: <a href="tel:112">112</a>.',
        "nomed": "Kopfwetter ist kein Medizinprodukt. Es stellt keine Diagnosen und ersetzt keine Behandlung.",
        "foot": ["Impressum", "Datenschutz", "Blog", "Quellcode"], "switch": ("en", "English"),
        "shot_alt": ["Tagesübersicht mit Check-in, Gefühlen und Check-out", "Monatsverlauf des PHQ-9"],
    },
    "en": {
        "title": "Kopfwetter – a mood diary only you can read",
        "desc": "Kopfwetter is a simple, end-to-end encrypted mood diary with morning check-in, evening check-out and a crisis plan. Add-ons: feelings, questionnaires, medication, patterns, therapy. Open source.",
        "nav": ["Features", "Add-ons", "Security", "Apps", "Roadmap", "FAQ"],
        "open": "Open the web version", "demo": "Try the demo",
        "eyebrow": "Open source · End-to-end encrypted",
        "h1": "A mood diary only you can read.",
        "lead": "Check in briefly in the morning, look back in the evening. Add everything else as an add-on: feelings, questionnaires, medication, patterns and therapy.",
        "day_h": "A day with Kopfwetter",
        "day": [("Morning", "Tap your mood, anxiety and drive, plus the one thing that matters today. Takes half a minute."),
                ("During the day", "With the Feelings add-on: tap a feeling, choose how strong it is, note the trigger. It is saved with the time."),
                ("Evening", "Mood, anxiety and drive once more, plus what you did and whether your intention worked out.")],
        "feat_h": "Features",
        "feat": [
            ("Morning check-in and evening check-out", "Mood, anxiety and drive twice a day, plus an intention, activities and a note."),
            ("Day overview", "Everything from your day in order. You can see what happened when."),
            ("History", "The last 30 days as a chart and all entries at a glance."),
            ("Crisis plan", "Warning signs, what helps you and whom you can call, based on the Safety Plan by Stanley and Brown."),
            ("Crisis mode", "For hard times: only help, one question about how you are and small steps."),
            ("German and English", "The whole app in both languages, export at any time."),
        ],
        "addons_h": "Add-ons",
        "addons_lead": "Kopfwetter stays simple. Turn on what else you need in the app. The setting applies in the app and in the browser.",
        "more": "Learn more",
        "sec_h": "Security",
        "sec_lead": "Your entries are encrypted on your device before they reach the server. The server only stores records it cannot read.",
        "sec": [
            ("End-to-end encrypted", "AES-256-GCM with a random data key, protected by your password (Argon2id). The server sees neither the content nor the date or type of an entry."),
            ("Two-factor sign-in", "Sign-in only with your password and a code from an authenticator app. Optionally a recovery key to print out."),
            ("No tracking", "No ads, no analytics, no scripts or fonts from third-party servers."),
            ("Open and auditable", "The source code is licensed under AGPL-3.0. You can also run Kopfwetter on your own server."),
        ],
        "apps_h": "Apps",
        "apps_lead": "Kopfwetter runs in the browser on any device. Apps for Android and iOS are on their way.",
        "web": ("Web version", "In the browser on computer, tablet and phone. With sign-in and two-factor code."),
        "android": ("Android", "Coming soon to Google Play and F-Droid."), "ios": ("iPhone and iPad", "Coming soon to the App Store."),
        "soon": "Coming soon", "play": "On Google Play", "fdroid": "On F-Droid", "appstore": "On the App Store",
        "road_h": "Roadmap", "st": {"done": "Done", "doing": "In progress", "next": "Planned"},
        "faq_h": "FAQ",
        "faq": [
            ("Who can read my entries?", "Only you. Entries are encrypted with a key that can only be derived from your password. Not even the person running the server can read them."),
            ("What if I forget my password?", "With a recovery key you can set a new password. Without it, your entries cannot be recovered; that is the price of encryption. Create one in the app under “Security”."),
            ("Does Kopfwetter replace therapy?", "No. Kopfwetter is a diary for self-observation. It does not diagnose and does not replace medical or psychotherapeutic treatment. It can help you prepare for conversations with your doctor or therapist."),
            ("Can I take my data with me?", "Yes. You can export everything as a file and import it into another account or onto another server, as well as CSV files and the PDF report."),
            ("Can I run Kopfwetter myself?", "Yes. Kopfwetter is a single container with SQLite and is licensed under the AGPL-3.0."),
        ],
        "crisis": "<strong>In an acute crisis</strong>: in Germany, TelefonSeelsorge is available around the clock, free and anonymous, at "
                  '<a href="tel:08001110111">0800 111 0 111</a> or <a href="tel:08001110222">0800 111 0 222</a>. Elsewhere, '
                  '<a href="https://findahelpline.com" rel="noopener noreferrer">findahelpline.com</a> lists free helplines. In an emergency: 112 (EU) or your local emergency number.',
        "nomed": "Kopfwetter is not a medical device. It does not diagnose and does not replace treatment.",
        "foot": ["Legal notice", "Privacy", "Blog", "Source code"], "switch": ("de", "Deutsch"),
        "shot_alt": ["Day overview with check-in, feelings and check-out", "Monthly PHQ-9 chart"],
    },
}

IDS = ["funktionen", "addons", "sicherheit", "apps", "roadmap", "fragen"]


def landing_html(lang: str = "de", app_url: str = "/app") -> str:
    t = T[lang]
    q = "?lang=en" if lang == "en" else ""
    app_url = escape(app_url)
    demo, blog, src = _https("DEMO_URL"), _https("BLOG_URL"), _https("SOURCE_URL")
    play, fdroid, appstore = _https("PLAY_URL"), _https("FDROID_URL"), _https("APPSTORE_URL")
    ext = 'rel="noopener noreferrer"'
    e = escape

    def store(url, label):
        return f'<a class="btn" href="{e(url)}" {ext}>{e(label)}</a>' if url else ""

    nav = "".join(f'<a href="#{i}">{e(n)}</a>' for i, n in zip(IDS, t["nav"]))
    cta = f'<a class="btn primary big" href="{app_url}">{e(t["open"])}</a>'
    if demo:
        cta += f' <a class="btn big" href="{e(demo)}" {ext}>{e(t["demo"])}</a>'
    day = "".join(f'<li><span class="step-n">{n}</span><div><h3>{e(h)}</h3><p>{e(p)}</p></div></li>' for n, (h, p) in enumerate(t["day"], 1))
    feat = "".join(f'<li class="card"><h3>{e(h)}</h3><p>{e(p)}</p></li>' for h, p in t["feat"])
    sec = "".join(f'<li><h3>{e(h)}</h3><p>{e(p)}</p></li>' for h, p in t["sec"])
    badge = lambda a: f' <span class="badge-planned">{e(AT[lang]["planned"])}</span>' if a.get("planned") else ""
    addons = "".join(f'<li class="card{" planned" if a.get("planned") else ""}"><h3>{e(a[lang]["name"])}{badge(a)}</h3><p>{e(a[lang]["tagline"])}</p>'
                     f'<p><a href="{e(addon_url(slug, lang))}">{e(t["more"])}</a></p></li>' for slug, a in ADDON_INFO.items())
    android_btns = store(play, t["play"]) + store(fdroid, t["fdroid"]) or f'<span class="soon">{e(t["soon"])}</span>'
    ios_btns = store(appstore, t["appstore"]) or f'<span class="soon">{e(t["soon"])}</span>'
    android_text = t["android"][1] if not (play or fdroid) else ""
    ios_text = t["ios"][1] if not appstore else ""
    road = "".join(f'<li class="rm rm-{s}"><span class="rm-st">{e(t["st"][s])}</span><div><h3>{e(h)}</h3><p>{e(p)}</p></div></li>' for s, h, p in ROADMAP[lang])
    faq = "".join(f'<details><summary>{e(qq)}</summary><p>{e(a)}</p></details>' for qq, a in t["faq"])
    imprint, privacy, blog_l, src_l = t["foot"]
    foot = [f'<a href="/impressum{q}">{e(imprint)}</a>', f'<a href="/datenschutz{q}">{e(privacy)}</a>']
    if blog:
        foot.append(f'<a href="{e(blog)}" {ext}>{e(blog_l)}</a>')
    if src:
        foot.append(f'<a href="{e(src)}" {ext}>{e(src_l)}</a>')
    sw_lang, sw_label = t["switch"]
    foot.append(f'<a href="/?lang={sw_lang}" lang="{sw_lang}">{sw_label}</a>')
    shot = lambda n, alt: f'<figure class="phone"><img src="/static/landing/{n}-{lang}.png" alt="{e(alt)}" width="390" loading="lazy"></figure>'
    shots = shot("tag", t["shot_alt"][0]) + shot("verlauf", t["shot_alt"][1])
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>{e(t["title"])}</title>
<meta name="description" content="{e(t["desc"])}">
<link rel="alternate" hreflang="de" href="/?lang=de"><link rel="alternate" hreflang="en" href="/?lang=en">
<link rel="icon" href="/static/icons/icon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<meta name="theme-color" content="#3f5e8c">
<link rel="stylesheet" href="/static/app.css">
<link rel="stylesheet" href="/static/landing.css">
</head>
<body class="site">
<header class="site-nav">
  <a class="brand" href="/{q}"><img src="/static/icons/icon.svg" alt="" width="30" height="30"><span>Kopfwetter</span></a>
  <nav aria-label="{e(t["nav"][0])}">{nav}</nav>
  <a class="btn primary" href="{app_url}">{e(t["open"])}</a>
</header>
<main>
<section class="hero site-hero">
  <div class="hero-in">
    <div class="heat-hero" aria-hidden="true">{_heat()}</div>
    <div class="hero-text">
      <p class="hero-eyebrow">{e(t["eyebrow"])}</p>
      <h1 class="hero-title">{e(t["h1"])}</h1>
      <p class="lead">{e(t["lead"])}</p>
      <p class="cta">{cta}</p>
    </div>
  </div>
</section>

<section class="band" aria-labelledby="day-h">
  <div class="band-in split">
    <div>
      <h2 id="day-h">{e(t["day_h"])}</h2>
      <ol class="steps">{day}</ol>
    </div>
    <div class="phones">{shots}</div>
  </div>
</section>

<section class="band" id="funktionen" aria-labelledby="feat-h">
  <div class="band-in"><h2 id="feat-h">{e(t["feat_h"])}</h2><ul class="features">{feat}</ul></div>
</section>

<section class="band" id="addons" aria-labelledby="addons-h">
  <div class="band-in"><h2 id="addons-h">{e(t["addons_h"])}</h2><p class="lead">{e(t["addons_lead"])}</p><ul class="features addon-list">{addons}</ul></div>
</section>

<section class="band alt" id="sicherheit" aria-labelledby="sec-h">
  <div class="band-in"><h2 id="sec-h">{e(t["sec_h"])}</h2><p class="lead">{e(t["sec_lead"])}</p><ul class="secs">{sec}</ul></div>
</section>

<section class="band" id="apps" aria-labelledby="apps-h">
  <div class="band-in">
    <h2 id="apps-h">{e(t["apps_h"])}</h2><p class="lead">{e(t["apps_lead"])}</p>
    <ul class="apps">
      <li class="card now"><h3>{e(t["web"][0])}</h3><p>{e(t["web"][1])}</p><p class="cta"><a class="btn primary" href="{app_url}">{e(t["open"])}</a></p></li>
      <li class="card"><h3>{e(t["android"][0])}</h3><p>{e(android_text)}</p><p class="cta">{android_btns}</p></li>
      <li class="card"><h3>{e(t["ios"][0])}</h3><p>{e(ios_text)}</p><p class="cta">{ios_btns}</p></li>
    </ul>
  </div>
</section>

<section class="band alt" id="roadmap" aria-labelledby="road-h">
  <div class="band-in"><h2 id="road-h">{e(t["road_h"])}</h2><ol class="roadmap">{road}</ol></div>
</section>

<section class="band" id="fragen" aria-labelledby="faq-h">
  <div class="band-in"><h2 id="faq-h">{e(t["faq_h"])}</h2><div class="faq">{faq}</div></div>
</section>
</main>
<footer class="site-foot">
  <div class="band-in">
    <p class="crisis">{t["crisis"]}</p>
    <p class="small">{e(t["nomed"])}</p>
    <p class="links">{" · ".join(foot)}</p>
  </div>
</footer>
</body>
</html>"""


# ---------------------------------------------------------------- Add-ons: Infoseiten (<name>.kopfwetter.app bzw. /addon/<name>)
# Eingeschaltet werden Add-ons in der App; diese Seiten erklären nur, was sie tun. Schlüssel = Subdomain.
ADDON_INFO = {
    "gefuehle": {"k": "feel",
        "de": {"name": "Gefühle", "tagline": "Gefühle festhalten, wenn sie da sind.",
               "lead": "Tagsüber ein Gefühl bemerkt? Antippen, Stärke wählen, wenn du magst den Auslöser notieren. Kopfwetter speichert es mit Uhrzeit.",
               "points": ["16 Gefühle, die in einer Depression häufig sind, 8 leichtere und eigene Gefühle",
                          "Stärke leicht, mittel oder stark, dazu ein Auslöser und die Uhrzeit",
                          "In der Tagesübersicht siehst du, wann was war",
                          "Mit dem Add-on Therapie auch im PDF-Bericht, außerdem als CSV-Datei"]},
        "en": {"name": "Feelings", "tagline": "Capture feelings when they happen.",
               "lead": "Noticed a feeling during the day? Tap it, choose how strong it is and, if you like, note the trigger. Kopfwetter saves it with the time.",
               "points": ["16 feelings that are common in depression, 8 lighter ones and your own",
                          "Intensity mild, moderate or strong, plus a trigger and the time",
                          "The day overview shows what happened when",
                          "With the Therapy add-on also in the PDF report, and as a CSV file"]}},
    "fragebogen": {"k": "tests",
        "de": {"name": "Fragebögen", "tagline": "Sehen, wie es dir über Wochen geht.",
               "lead": "Zwei anerkannte Fragebögen zu Depression (PHQ-9) und Angst (GAD-7), sinnvoll alle zwei Wochen. Ein Screening, keine Diagnose.",
               "points": ["PHQ-9 und GAD-7 im Wortlaut der deutschen und englischen Fassungen",
                          "Verlauf als Monatsbalken, mit Hinweis, wann der nächste Fragebogen fällig ist",
                          "Ausgewertet nur auf deinem Gerät",
                          "Bei Gedanken an Selbstverletzung sofort Hinweise auf Hilfe und deinen Krisenplan"]},
        "en": {"name": "Questionnaires", "tagline": "See how you are over the weeks.",
               "lead": "Two established questionnaires on depression (PHQ-9) and anxiety (GAD-7), best every two weeks. A screening, not a diagnosis.",
               "points": ["PHQ-9 and GAD-7 in their original wording",
                          "Progress as monthly bars, with a note when the next one is due",
                          "Scored only on your device",
                          "If you report thoughts of self-harm, help and your crisis plan appear right away"]}},
    "tabletten": {"k": "meds",
        "de": {"name": "Tabletten", "tagline": "Jede Einnahme mit einem Tipp.",
               "lead": "Lege deine Medikamente einmal mit Dosis und geplanten Zeiten an. Danach trägst du jede Einnahme mit einem Tipp ein.",
               "points": ["„Jetzt eingenommen“ für geplante Zeiten",
                          "Einnahmen nachtragen, mit Uhrzeit und Notiz, zum Beispiel zu Nebenwirkungen",
                          "Tagesüberblick im Abend-Check-out",
                          "Als CSV-Datei und mit dem Add-on Therapie im PDF-Bericht"]},
        "en": {"name": "Medication", "tagline": "Every dose with a single tap.",
               "lead": "Add your medication once with dose and planned times. After that you log every dose with a single tap.",
               "points": ["“Taken now” for planned times",
                          "Add doses afterwards, with time and a note, for example on side effects",
                          "A daily overview in the evening check-out",
                          "As a CSV file and, with the Therapy add-on, in the PDF report"]}},
    "muster": {"k": "patterns",
        "de": {"name": "Muster", "tagline": "Zusammenhänge sehen.",
               "lead": "Muster zeigt, was in deinen Einträgen gemeinsam auftritt. Es zeigt Zusammenhänge, keine Ursachen.",
               "points": ["Deine Stimmung im letzten Jahr als Übersicht",
                          "Stimmung nach Wochentag",
                          "Stimmung an Tagen mit und ohne bestimmte Aktivitäten",
                          "Berechnet nur auf deinem Gerät"]},
        "en": {"name": "Patterns", "tagline": "See what goes together.",
               "lead": "Patterns shows what tends to occur together in your entries. It shows links, not causes.",
               "points": ["Your mood over the last year at a glance",
                          "Mood by weekday",
                          "Mood on days with and without certain activities",
                          "Calculated only on your device"]}},
    "therapie": {"k": "therapy",
        "de": {"name": "Therapie", "tagline": "Gut vorbereitet in die Sitzung.",
               "lead": "Sammle, was du in der Therapie ansprechen willst, und nimm einen Bericht über die letzten Wochen mit.",
               "points": ["Notizen für die nächste Sitzung, nach dem Gespräch abhaken",
                          "PDF-Bericht mit Verlauf, Check-ins und den Daten deiner anderen Add-ons",
                          "Zeitraum frei wählbar",
                          "Der Bericht entsteht in deinem Browser, es gehen keine Daten an den Server"]},
        "en": {"name": "Therapy", "tagline": "Well prepared for your session.",
               "lead": "Collect what you want to bring up in therapy and take a report on the last weeks with you.",
               "points": ["Notes for your next session, ticked off after the conversation",
                          "PDF report with trends, check-ins and the data of your other add-ons",
                          "Any time range you like",
                          "The report is created in your browser; no data goes to the server"]}},
    # Geplant (noch nicht in der App): Infoseite ohne „Einschalten“, mit Hinweis auf die Roadmap
    "journal": {"k": "journal", "planned": True,
        "de": {"name": "Journal", "tagline": "Ausführlich schreiben, was dich bewegt.",
               "lead": "Ein Tagebuch für das, was Skalen nicht zeigen: wie der Tag war, was dich beschäftigt, was schwer war und was trotzdem ging. Nur du kannst es lesen.",
               "points": ["Beliebig viele Einträge pro Tag, mit einfacher Formatierung",
                          "Schreibimpulse für Tage, an denen der Anfang schwerfällt, zum Übernehmen oder Wegtippen",
                          "Verknüpft mit Check-in und Gefühlen des Tages",
                          "Suche nur auf deinem Gerät, der Server bekommt keinen Suchindex",
                          "Entwürfe werden laufend verschlüsselt zwischengespeichert, auch ohne Netz",
                          "Einträge lassen sich als „nur für mich“ markieren und werden dann nie geteilt"]},
        "en": {"name": "Journal", "tagline": "Write at length about what moves you.",
               "lead": "A diary for what scales don't show: how your day was, what is on your mind, what was hard and what still worked. Only you can read it.",
               "points": ["As many entries per day as you like, with simple formatting",
                          "Writing prompts for days when starting is hard, to use or dismiss",
                          "Linked to that day's check-in and feelings",
                          "Search runs only on your device; the server gets no search index",
                          "Drafts are saved encrypted as you type, even offline",
                          "Entries can be marked “only for me” and are then never shared"]}},
    "teilen": {"k": "share", "planned": True,
        "de": {"name": "Teilen", "tagline": "Sicher zeigen, wie es dir ging.",
               "lead": "Gib deiner Psychiaterin oder deinem Psychologen ausgewählte Einträge über einen verschlüsselten Link frei. Sie brauchen kein Konto, und der Server kann nicht mitlesen.",
               "points": ["Du wählst Zeitraum und Inhalte, zum Beispiel Check-ins, Journal und Fragebögen",
                          "Der Schlüssel ist zweigeteilt: ein Teil im Link, der andere als kurzer Code, den du mündlich weitergibst",
                          "Wer nur den Link abfängt, kann nichts lesen",
                          "Jeder Link läuft ab, lässt sich nur begrenzt oft öffnen und jederzeit widerrufen",
                          "Du siehst, wann ein Link geöffnet wurde",
                          "Ausgelegt auf Post-Quanten-Sicherheit: der Link kommt ohne angreifbare Public-Key-Verfahren aus, dauerhafte Freigaben an eine Praxis werden hybrid quantensicher"]},
        "en": {"name": "Share", "tagline": "Safely show how you have been.",
               "lead": "Give your psychiatrist or psychologist access to selected entries through an encrypted link. They need no account, and the server cannot read along.",
               "points": ["You choose the time range and content, for example check-ins, journal and questionnaires",
                          "The key is split in two: one part in the link, the other as a short code you pass on in person",
                          "Anyone who only intercepts the link cannot read anything",
                          "Every link expires, can only be opened a limited number of times and can be revoked at any time",
                          "You see when a link was opened",
                          "Designed for post-quantum security: the link needs no vulnerable public-key methods, and long-term shares with a practice use hybrid quantum-safe encryption"]}},
}

AT = {
    "de": {"planned_eyebrow": "Geplantes Add-on für Kopfwetter", "planned": "In Planung", "roadmap": "Zur Roadmap",
           "planned_h": "Wann es kommt",
           "planned_text": "Dieses Add-on ist in Planung und noch nicht in der App. Den Stand siehst du in der Roadmap. Sobald es fertig ist, schaltest du es wie alle Add-ons unter „Verlauf & mehr“ → „Add-ons“ ein.",
           "private_planned": "Auch die Einträge dieses Add-ons werden auf deinem Gerät verschlüsselt, bevor sie den Server erreichen. Ausgeschaltet bleiben sie erhalten.",
"eyebrow": "Add-on für Kopfwetter", "on": "In Kopfwetter einschalten", "back": "Zu Kopfwetter",
           "how": "Was es kann", "how_planned": "Was es können soll", "shot_alt": "Bildschirmfoto: Add-on {} mit Beispieldaten", "private_h": "Privat wie alles in Kopfwetter",
           "private": "Auch die Einträge dieses Add-ons werden auf deinem Gerät verschlüsselt, bevor sie den Server erreichen. Ausschalten blendet es aus, die Einträge bleiben erhalten.",
           "steps_h": "So schaltest du es ein",
           "steps": ["Melde dich in Kopfwetter an, im Browser oder in der App.", "Öffne „Verlauf & mehr“ und dort „Add-ons“.", "Schalte das Add-on ein. Es gilt dann in der App und im Browser."],
           "others": "Weitere Add-ons"},
    "en": {"planned_eyebrow": "Planned add-on for Kopfwetter", "planned": "In planning", "roadmap": "See the roadmap",
           "planned_h": "When it is coming",
           "planned_text": "This add-on is being planned and is not yet in the app. You can follow its progress on the roadmap. Once it is ready, you turn it on like any add-on under “History & more” → “Add-ons”.",
           "private_planned": "The entries of this add-on will also be encrypted on your device before they reach the server. If you turn it off, they are kept.",
           "eyebrow": "Add-on for Kopfwetter", "on": "Turn on in Kopfwetter", "back": "To Kopfwetter",
           "how": "What it does", "how_planned": "What it will do", "shot_alt": "Screenshot: {} add-on with sample data", "private_h": "Private like everything in Kopfwetter",
           "private": "The entries of this add-on are encrypted on your device before they reach the server, too. Turning it off hides it; your entries are kept.",
           "steps_h": "How to turn it on",
           "steps": ["Sign in to Kopfwetter, in the browser or in the app.", "Open “History & more” and then “Add-ons”.", "Turn the add-on on. It then applies in the app and in the browser."],
           "others": "More add-ons"},
}


def addon_url(slug: str, lang: str = "de") -> str:
    dom = env("ADDON_DOMAIN", "").strip().lower().strip(".")
    q = "?lang=en" if lang == "en" else ""
    return (f"https://{slug}.{dom}/" if dom else f"/addon/{slug}") + q


def addon_html(slug: str, lang: str = "de", app_url: str = "/app") -> str:
    a, t, at = ADDON_INFO[slug][lang], T[lang], AT[lang]
    e = escape
    q = "?lang=en" if lang == "en" else ""
    site = (_https("SITE_URL") or "") + "/" + q
    sep = "&" if "?" in app_url else "?"
    on_url = e(f"{app_url}{sep}addon={slug}")
    points = "".join(f"<li>{e(p)}</li>" for p in a["points"])
    steps = "".join(f"<li>{e(p)}</li>" for p in at["steps"])
    others = " · ".join(f'<a href="{e(addon_url(s, lang))}">{e(x[lang]["name"])}</a>' for s, x in ADDON_INFO.items() if s != slug)
    planned = ADDON_INFO[slug].get("planned", False)
    eyebrow = at["planned_eyebrow"] if planned else at["eyebrow"]
    cta = (f'<span class="soon big-soon">{e(at["planned"])}</span> <a class="btn big" href="{e(site)}#roadmap">{e(at["roadmap"])}</a>' if planned
           else f'<a class="btn primary big" href="{on_url}">{e(at["on"])}</a> <a class="btn big" href="{e(site)}">{e(at["back"])}</a>')
    second = (f'<div><h2>{e(at["planned_h"])}</h2><p class="lead">{e(at["planned_text"])}</p></div>' if planned
              else f'<div><h2>{e(at["steps_h"])}</h2><ol class="addon-steps">{steps}</ol></div>')
    private = at["private_planned"] if planned else at["private"]
    # Bildschirmfoto aus der Demo (nur fertige Add-ons): static/landing/addon-<name>-<sprache>.png
    shot_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "landing", f"addon-{slug}-{lang}.png")
    shot = (f'<figure class="phone addon-shot"><img src="/static/landing/addon-{slug}-{lang}.png" alt="{e(at["shot_alt"].format(a["name"]))}" '
            f'width="390" loading="lazy"></figure>') if not planned and os.path.exists(shot_file) else ""
    imprint, privacy, _, _ = t["foot"]
    sw_lang, sw_label = t["switch"]
    foot = " · ".join([f'<a href="/impressum{q}">{e(imprint)}</a>', f'<a href="/datenschutz{q}">{e(privacy)}</a>',
                       f'<a href="?lang={sw_lang}" lang="{sw_lang}">{sw_label}</a>'])
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>{e(a["name"])} · Kopfwetter</title>
<meta name="description" content="{e(a["tagline"] + " " + a["lead"])}">
<link rel="icon" href="/static/icons/icon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="any">
<meta name="theme-color" content="#3f5e8c">
<link rel="stylesheet" href="/static/app.css">
<link rel="stylesheet" href="/static/landing.css">
</head>
<body class="site">
<header class="site-nav">
  <a class="brand" href="{e(site)}"><img src="/static/icons/icon.svg" alt="" width="30" height="30"><span>Kopfwetter</span></a>
  <a class="btn primary push" href="{e(app_url)}">{e(t["open"])}</a>
</header>
<main>
<section class="band addon-hero">
  <div class="band-in narrow">
    <p class="hero-eyebrow">{e(eyebrow)} · {e(a["name"])}</p>
    <h1 class="hero-title">{e(a["tagline"])}</h1>
    <p class="lead">{e(a["lead"])}</p>
    <p class="cta">{cta}</p>
  </div>
</section>
<section class="band alt">
  <div class="band-in{" narrow" if not shot else " addon-how"}">
    <div><h2>{e(at["how_planned"] if planned else at["how"])}</h2>
    <ul class="addon-points">{points}</ul></div>
    {shot}
  </div>
</section>
<section class="band">
  <div class="band-in narrow split-2">
    <div><h2>{e(at["private_h"])}</h2><p class="lead">{e(private)}</p></div>
    {second}
  </div>
</section>
<section class="band alt">
  <div class="band-in narrow"><p><strong>{e(at["others"])}:</strong> {others}</p></div>
</section>
</main>
<footer class="site-foot">
  <div class="band-in">
    <p class="crisis">{t["crisis"]}</p>
    <p class="small">{e(t["nomed"])}</p>
    <p class="links">{foot}</p>
  </div>
</footer>
</body>
</html>"""
