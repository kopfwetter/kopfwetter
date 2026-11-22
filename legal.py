# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Datenschutzerklärung und Impressum – serverseitig aus den Angaben in der .env erzeugt.

Kein Rechtsrat: Die Texte sind eine sorgfältige Vorlage für dieses konkrete Projekt (privat betrieben,
Ende-zu-Ende verschlüsselt, Registrierung mit Freigabe). Prüfe sie vor dem Livegang.
"""
from __future__ import annotations

import os
from html import escape

PRIVACY_VERSION = "2026-11-04"  # bei inhaltlichen Änderungen erhöhen; wird bei der Einwilligung gespeichert

env = os.environ.get


def cfg():
    return {
        "name": env("OPERATOR_NAME", "").strip(),
        "street": env("OPERATOR_STREET", "").strip(),
        "city": env("OPERATOR_CITY", "").strip(),
        "email": env("OPERATOR_EMAIL", "").strip(),
        "phone": env("OPERATOR_PHONE", "").strip(),
        "hoster": env("HOSTER", "").strip(),
        "cloudflare": env("USE_CLOUDFLARE", "1") != "0",
        "authority": env("SUPERVISORY_AUTHORITY", "").strip(),
        "backup_days": env("BACKUP_RETENTION_DAYS", "30").strip(),
        "pending_days": env("PENDING_DAYS", "14"),
        "session_hours": env("SESSION_HOURS", "12"),
        "site_name": env("TOTP_ISSUER", "Kopfwetter"),
        "native_hours": env("NATIVE_SESSION_HOURS", "168"),
        "demo": env("DEMO_MODE", "0") == "1",
        "demo_hours": env("DEMO_HOURS", "24"),
    }


def missing() -> list[str]:
    c = cfg()
    keys = {"OPERATOR_NAME": c["name"], "OPERATOR_STREET": c["street"], "OPERATOR_CITY": c["city"], "OPERATOR_EMAIL": c["email"], "HOSTER": c["hoster"]}
    return [k for k, v in keys.items() if not v]


def _v(value: str, key: str, lang: str = "de") -> str:
    if value:
        return escape(value)
    return f'<mark class="todo">[{key} in der .env eintragen]</mark>' if lang == "de" else f'<mark class="todo">[set {key} in .env]</mark>'


def _page(title: str, site: str, body: str, lang: str = "de") -> str:
    blog_url = env("BLOG_URL", "").strip()
    blog = f'<a href="{escape(blog_url)}">Blog</a> · ' if blog_url.startswith("https://") else ""
    if lang == "en":
        links = '<a href="/datenschutz?lang=en">Privacy</a> · <a href="/impressum?lang=en">Legal notice</a> · <a href="?lang=de" lang="de">Deutsch</a>'
        home = "/?lang=en"
    else:
        links = '<a href="/datenschutz">Datenschutz</a> · <a href="/impressum">Impressum</a> · <a href="?lang=en" lang="en">English</a>'
        home = "/"
    return f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>{escape(title)} · {escape(site)}</title>
<link rel="icon" href="/static/icons/icon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/static/icons/apple-touch-icon.png">
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<div class="wrap legal">
  <header class="top"><div class="titles"><p class="sub"><a href="{home}">← {escape(site)}</a></p><h1>{escape(title)}</h1></div></header>
  <article class="card prose">
{body}
  </article>
  <footer><p>{blog}{links}</p></footer>
</div>
</body>
</html>"""


def _operator_block(c, lang: str = "de") -> str:
    lines = [_v(c["name"], "OPERATOR_NAME", lang), _v(c["street"], "OPERATOR_STREET", lang), _v(c["city"], "OPERATOR_CITY", lang)]
    contact = f'{"E-Mail" if lang == "de" else "Email"}: {_v(c["email"], "OPERATOR_EMAIL", lang)}'
    if c["phone"]:
        contact += f"<br>{'Telefon' if lang == 'de' else 'Phone'}: {escape(c['phone'])}"
    return "<p>" + "<br>".join(lines) + "</p>\n<p>" + contact + "</p>"


TRANSLATION_NOTE = ('<p class="small"><em>This is a translation for your convenience. Only the '
                    '<a href="?lang=de" lang="de">German version</a> is legally binding.</em></p>')


def imprint_html(lang: str = "de") -> str:
    c = cfg()
    if lang == "en":
        return _imprint_en(c)
    body = f"""
    <h2>Angaben gemäß § 5 DDG</h2>
    {_operator_block(c)}

    <h2>Art des Angebots</h2>
    <p>{escape(c["site_name"])} ist ein privat betriebenes, nicht kommerzielles Angebot. Es wird keine Werbung gezeigt,
    und es werden keine Daten verkauft.</p>

    <h2>Kein medizinisches Angebot</h2>
    <p>{escape(c["site_name"])} ist ein Stimmungstagebuch und ein Hilfsmittel zur Selbstbeobachtung. Es stellt keine Diagnosen, gibt keine
    Behandlungsempfehlungen und ersetzt keine ärztliche oder psychotherapeutische Behandlung.</p>
    <p><strong>In einer akuten Krise</strong> erreichst du die Telefonseelsorge rund um die Uhr, kostenlos und anonym unter
    0800 111 0 111 oder 0800 111 0 222. Im Notfall wähle 112.</p>

    <h2>Haftung für Inhalte und Links</h2>
    <p>Die Inhalte dieser Seite wurden mit Sorgfalt erstellt. Für die Richtigkeit, Vollständigkeit und Aktualität kann
    keine Gewähr übernommen werden. Für die Inhalte verlinkter externer Seiten sind ausschließlich deren Betreiber
    verantwortlich. Bei Bekanntwerden von Rechtsverletzungen werden entsprechende Inhalte oder Links umgehend entfernt.</p>

    <h2>Datenschutz</h2>
    <p>Wie mit deinen Daten umgegangen wird, steht in der <a href="/datenschutz">Datenschutzerklärung</a>.</p>
"""
    return _page("Impressum", c["site_name"], body)


def privacy_html(lang: str = "de") -> str:
    c = cfg()
    if lang == "en":
        return _privacy_en(c)
    v = PRIVACY_VERSION.split("-")[:3]
    stand = f"{v[2]}.{v[1]}.{v[0]}"
    authority = escape(c["authority"]) if c["authority"] else "die Datenschutz-Aufsichtsbehörde des Bundeslandes, in dem du wohnst, oder die für den Betreiber zuständige Behörde"
    cf_recipient = ""
    cf_basis = ""
    if c["cloudflare"]:
        cf_recipient = """
    <h3>Cloudflare (Verbindung zum Server)</h3>
    <p>Die Verbindung zwischen deinem Browser und dem Server läuft über <strong>Cloudflare, Inc.</strong>,
    101 Townsend St., San Francisco, CA 94107, USA. Cloudflare leitet die Anfragen weiter und schützt vor Angriffen.
    Dabei verarbeitet Cloudflare technische Verbindungsdaten wie deine IP-Adresse, Zeitpunkt und angefragte Adresse
    sowie den Inhalt der Anfragen. Deine Tagebucheinträge sind dabei bereits in deinem Browser verschlüsselt und für
    Cloudflare nicht lesbar. Benutzernamen sind für Cloudflare technisch sichtbar.</p>
    <p>Cloudflare ist unter dem EU-U.S. Data Privacy Framework zertifiziert. Die Übermittlung in die USA stützt sich auf den
    Angemessenheitsbeschluss der EU-Kommission vom 10. Juli 2023 (Art. 45 DSGVO). Mit Cloudflare besteht ein
    Auftragsverarbeitungsvertrag nach Art. 28 DSGVO. Mehr dazu:
    <a href="https://www.cloudflare.com/de-de/privacypolicy/" rel="noopener noreferrer">Datenschutzerklärung von Cloudflare</a>.</p>"""
        cf_basis = "<tr><td>Weiterleitung und Schutz der Verbindung über Cloudflare</td><td>Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an einem sicheren und erreichbaren Dienst)</td></tr>"

    blog_url = env("BLOG_URL", "").strip()
    blog_section = ""
    if blog_url.startswith("https://"):
        blog_section = f"""
    <h3>Blog</h3>
    <p>Der Blog unter <a href="{escape(blog_url)}">{escape(blog_url.removeprefix("https://").rstrip("/"))}</a> ist eine
    statische Website. Er setzt keine Cookies, verwendet kein Tracking und bindet keine Inhalte fremder Anbieter ein.
    Der Webserver schreibt keine Zugriffsprotokolle. Beim Aufruf werden technisch notwendige Verbindungsdaten
    (IP-Adresse, Zeitpunkt, aufgerufene Seite) nur für die Dauer der Verbindung verarbeitet
    (Art. 6 Abs. 1 lit. f DSGVO){" und über Cloudflare ausgeliefert (siehe oben)" if c["cloudflare"] else ""}.</p>"""
    body = f"""
    <p class="small">Stand: {stand} · Version {escape(PRIVACY_VERSION)}</p>

    <h2>Das Wichtigste in Kürze</h2>
    <ul>
      {f'<li><strong>Dies ist eine Demo.</strong> Jede Besucherin und jeder Besucher bekommt ein eigenes, anonymes Konto mit Beispieldaten. Es wird nach {escape(c["demo_hours"])} Stunden samt allen Daten automatisch gelöscht. <strong>Bitte gib keine echten Gesundheitsdaten ein.</strong></li>' if c["demo"] else ""}
      <li>Deine Tagebucheinträge werden <strong>in deinem Browser verschlüsselt</strong>, bevor sie den Server erreichen. Der Schlüssel entsteht aus deinem Passwort. Weder der Betreiber noch Admins können deine Einträge lesen.</li>
      <li>Es gibt <strong>keine Werbung, kein Tracking, keine Analyse-Dienste</strong> und keine eingebundenen Inhalte fremder Anbieter. Schriften und Programmteile kommen vom eigenen Server.</li>
      <li>Deine Einträge enthalten <strong>Gesundheitsdaten</strong>. Sie werden nur mit deiner ausdrücklichen Einwilligung gespeichert, die du jederzeit widerrufen kannst, indem du dein Konto löschst.</li>
      <li>Du kannst dein Konto mit allen Einträgen <strong>jederzeit selbst löschen</strong> und deine Einträge vorher als CSV oder PDF herunterladen.</li>
    </ul>

    <h2>1. Verantwortlicher</h2>
    {_operator_block(c)}

    <h2>2. Welche Daten verarbeitet werden</h2>
    <h3>Kontodaten</h3>
    <ul>
      <li>dein Benutzername</li>
      <li>ein aus deinem Passwort abgeleiteter Anmeldeschlüssel, gespeichert nur als Argon2id-Hash. Dein Passwort selbst erreicht den Server nie.</li>
      <li>das Geheimnis für die Zwei-Faktor-Anmeldung (verschlüsselt) und deine Wiederherstellungscodes (nur als Hash)</li>
      <li>Kontostatus (wartet auf Freigabe, aktiv, gesperrt), gegebenenfalls Admin-Rolle</li>
      <li>Zeitpunkt der Registrierung, deiner Einwilligung (mit Version dieser Erklärung) und deiner letzten Anmeldung</li>
      <li>die Zahl fehlgeschlagener Anmeldeversuche (für eine kurze Sperre nach mehreren Fehlversuchen)</li>
    </ul>
    <h3>Tagebucheinträge, Selbsttests, Krisenplan (Gesundheitsdaten)</h3>
    <p>Stimmung, Angst, Antrieb, Aktivitäten, Angaben zur Medikamenteneinnahme (Tagesüberblick sowie deine Medikamente mit Dosis,
    geplanten Zeiten und einzelnen Einnahmen mit Uhrzeit), Notizen, Notizen für die nächste Therapiesitzung, dein persönlicher
    Krisenplan (einschließlich der Namen und Telefonnummern, die du dort einträgst) sowie deine Antworten und Ergebnisse in den
    Selbsttests PHQ-9 (Depression) und GAD-7 (Angst). Diese Angaben sind
    Gesundheitsdaten im Sinne von Art. 9 DSGVO. Sie werden in deinem Browser mit AES-256-GCM verschlüsselt und nur verschlüsselt
    gespeichert. Für den Server sichtbar ist lediglich, <strong>wie viele</strong> verschlüsselte Datensätze es gibt und in welche
    grobe Größenklasse sie fallen. Datum, Art (Eintrag, Test, Medikament, Einnahme, Notiz, Krisenplan) und Zeitpunkt der
    Änderung sind mitverschlüsselt. Die Auswertung der Tests findet nur in deinem Browser bzw. in der App statt.</p>
    <h3>Sitzungs-Cookie</h3>
    <p>Nach der Anmeldung setzt der Server ein technisch notwendiges Cookie, damit du angemeldet bleibst. Es gilt höchstens
    {escape(c["session_hours"])} Stunden und wird beim Abmelden gelöscht. Auf dem Server liegt davon nur ein Hash.</p>
    <h3>Apps für iOS und Android</h3>
    <p>Die Apps verwenden statt eines Cookies ein Anmelde-Token. Es liegt im geschützten Schlüsselspeicher deines Geräts
    (Keychain bzw. Android Keystore), gilt höchstens {escape(c["native_hours"])} Stunden und wird beim Abmelden gelöscht.
    Die Apps enthalten keine Analyse- oder Werbe-Bibliotheken. Berichte und Sicherheitskopien speichert die App über das
    Teilen-Menü deines Geräts. Wohin du sie dort weitergibst, entscheidest du.</p>
    <h3>Speicher in deinem Browser</h3>
    <p>Damit du nach dem Neuladen nicht dein Passwort erneut eingeben musst, liegt der Schlüssel für deine Einträge bis zum
    Abmelden oder bis zur automatischen Sperre im Speicher deines Browsers (IndexedDB). Er lässt sich dort nicht auslesen. Außerdem merkt sich der Browser
    deine Einstellungen für den PDF-Bericht (Name, Notizen ja/nein). Diese Angaben verlassen dein Gerät nicht.</p>
    <h3>Verbindungsdaten</h3>
    <p>Zum Schutz vor Missbrauch (Begrenzung von Registrierungen und Anmeldeversuchen) hält der Server deine IP-Adresse
    kurzzeitig im Arbeitsspeicher, höchstens eine Stunde. Sie wird nicht dauerhaft gespeichert. Die Anwendung schreibt keine
    Zugriffsprotokolle.</p>
    <h3>Berichte und Sicherheitskopien</h3>
    <p>PDF-Berichte, CSV-Sicherheitskopien und der vollständige JSON-Export entstehen vollständig in deinem Browser und werden nicht an den Server übertragen.
    Diese Dateien sind unverschlüsselt. Bewahre sie entsprechend sorgfältig auf.</p>

    <h3>Angaben über andere Menschen</h3>
    <p>Trägst du im Krisenplan Namen und Telefonnummern von Vertrauenspersonen ein, sind auch diese Ende-zu-Ende verschlüsselt und
    nur für dich lesbar. Sie werden nicht verwendet, um diese Personen zu kontaktieren.</p>

    <h2>3. Zwecke und Rechtsgrundlagen</h2>
    <div class="tablewrap"><table>
      <thead><tr><th>Zweck</th><th>Rechtsgrundlage</th></tr></thead>
      <tbody>
        <tr><td>Konto bereitstellen, Anmeldung, Freigabe durch Admins</td><td>Art. 6 Abs. 1 lit. b DSGVO (Nutzungsverhältnis)</td></tr>
        <tr><td>Speichern deiner Tagebucheinträge und Selbsttests (Gesundheitsdaten)</td><td>Art. 9 Abs. 2 lit. a i. V. m. Art. 6 Abs. 1 lit. a DSGVO (ausdrückliche Einwilligung bei der Registrierung)</td></tr>
        <tr><td>Schutz vor Missbrauch und Angriffen, Sperre nach Fehlversuchen</td><td>Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an einem sicheren Dienst)</td></tr>
        {cf_basis}
        <tr><td>Sitzungs-Cookie und Speicher im Browser</td><td>§ 25 Abs. 2 Nr. 2 TDDDG (unbedingt erforderlich für den von dir gewünschten Dienst)</td></tr>
      </tbody>
    </table></div>

    <h2>4. Einwilligung und Widerruf</h2>
    <p>Die Einwilligung ist freiwillig. Ohne sie kann das Tagebuch nicht genutzt werden, weil es ausschließlich der Speicherung
    dieser Angaben dient. Du kannst die Einwilligung jederzeit mit Wirkung für die Zukunft widerrufen: am einfachsten, indem du
    in der App unter „Sicherheit“ → „Konto löschen“ dein Konto löschst, oder per E-Mail an {_v(c["email"], "OPERATOR_EMAIL")}.
    Die Rechtmäßigkeit der Verarbeitung bis zum Widerruf bleibt davon unberührt.</p>

    <h2>5. Empfänger</h2>
    <p>Deine Daten werden nicht verkauft und nicht zu Werbezwecken weitergegeben. Admins dieser Installation sehen in der
    Verwaltung deinen Benutzernamen, deinen Kontostatus sowie die Zeitpunkte der Registrierung und der letzten Anmeldung,
    aber <strong>keine</strong> Inhalte deiner Einträge.</p>
    <h3>Hosting</h3>
    <p>Der Server wird betrieben bei: {_v(c["hoster"], "HOSTER")}. Mit dem Anbieter besteht ein Auftragsverarbeitungsvertrag nach
    Art. 28 DSGVO. Der Anbieter hat Zugriff nur auf verschlüsselte Einträge.</p>
    {cf_recipient}

    {blog_section}
    <h2>6. Speicherdauer</h2>
    <ul>
      {f'<li>Demo-Konten: automatische Löschung nach {escape(c["demo_hours"])} Stunden oder sofort über „Demo beenden“</li>' if c["demo"] else '<li>Konto und Einträge: bis du dein Konto löschst oder es von einem Admin gelöscht wird</li>'}
      <li>nicht freigegebene Konten: automatische Löschung nach {escape(c["pending_days"])} Tagen</li>
      <li>abgebrochene Registrierungen: Löschung nach 15 Minuten</li>
      <li>Sitzungen: höchstens {escape(c["session_hours"])} Stunden im Browser, {escape(c["native_hours"])} Stunden in den Apps</li>
      <li>IP-Adressen im Arbeitsspeicher: höchstens eine Stunde</li>
      <li>Datensicherungen (enthalten Einträge nur verschlüsselt): höchstens {escape(c["backup_days"])} Tage. Gelöschte Konten verschwinden spätestens dann auch aus den Sicherungen.</li>
    </ul>

    <h2>7. Sicherheit</h2>
    <p>Verbindungen sind per TLS verschlüsselt. Einträge sind zusätzlich Ende-zu-Ende verschlüsselt (Argon2id und HKDF zur
    Schlüsselableitung, AES-256-GCM). Nach einer einstellbaren Zeit ohne Nutzung sperrt sich die App auf deinem Gerät. Die Anmeldung erfordert einen zweiten Faktor. Nach mehreren Fehlversuchen
    wird die Anmeldung vorübergehend gesperrt. Deine Inhalte sind mit einem zufälligen Datenschlüssel verschlüsselt; der Server
    speichert ihn nur verpackt mit deinem Passwort und, wenn du einen anlegst, mit deinem Wiederherstellungsschlüssel. Vom
    Wiederherstellungsschlüssel speichert der Server nur einen Argon2id-Hash. <strong>Ohne Passwort und ohne
    Wiederherstellungsschlüssel kann niemand deine Einträge wiederherstellen.</strong></p>

    <h2>8. Deine Rechte</h2>
    <p>Du hast das Recht auf Auskunft (Art. 15 DSGVO), Berichtigung (Art. 16), Löschung (Art. 17), Einschränkung der Verarbeitung
    (Art. 18), Datenübertragbarkeit (Art. 20) und Widerspruch gegen Verarbeitungen auf Grundlage berechtigter Interessen (Art. 21).
    Vieles kannst du direkt in der App erledigen: Einträge ansehen und ändern, als CSV oder PDF herunterladen und dein Konto
    löschen. Für alles andere schreib an {_v(c["email"], "OPERATOR_EMAIL")}.</p>
    <p>Du hast außerdem das Recht, dich bei einer Datenschutz-Aufsichtsbehörde zu beschweren (Art. 77 DSGVO), zum Beispiel bei
    {authority}.</p>

    <h2>9. Keine automatisierten Entscheidungen</h2>
    <p>Es findet keine automatisierte Entscheidungsfindung und kein Profiling statt. Die Auswertungen in der App und im PDF-Bericht
    (Durchschnitte, Verläufe) werden nur für dich in deinem Browser berechnet.</p>

    <h2>10. Kein medizinisches Angebot</h2>
    <p>Das Tagebuch ist ein Hilfsmittel zur Selbstbeobachtung und ersetzt keine Behandlung. PHQ-9 und GAD-7 sind anerkannte
    Screening-Fragebögen, aber keine Diagnose. Die Muster-Auswertungen beschreiben Zusammenhänge und stellen keine Diagnose. In einer akuten Krise erreichst du
    die Telefonseelsorge rund um die Uhr unter 0800 111 0 111 oder 0800 111 0 222, im Notfall die 112.</p>

    <h2>11. Änderungen</h2>
    <p>Wenn sich diese Erklärung inhaltlich ändert, wird die Version oben angepasst. Bei wesentlichen Änderungen der Verarbeitung
    deiner Gesundheitsdaten wirst du um eine neue Einwilligung gebeten.</p>
"""
    return _page("Datenschutzerklärung", c["site_name"], body)


# ---------------------------------------------------------------- Englische Fassung (Übersetzung, maßgeblich ist Deutsch)
def _imprint_en(c) -> str:
    body = f"""
    {TRANSLATION_NOTE}
    <h2>Information pursuant to § 5 DDG (German Digital Services Act)</h2>
    {_operator_block(c, "en")}

    <h2>Nature of this service</h2>
    <p>{escape(c["site_name"])} is a privately run, non-commercial service. It shows no advertising and sells no data.</p>

    <h2>Not a medical service</h2>
    <p>{escape(c["site_name"])} is a mood diary and a tool for self-observation. It does not diagnose, does not give treatment
    recommendations and does not replace medical or psychotherapeutic treatment.</p>
    <p><strong>In an acute crisis</strong>, call 112 (emergency number in the EU). In Germany, TelefonSeelsorge is available around
    the clock, free and anonymous, at 0800 111 0 111 or 0800 111 0 222. In other countries,
    <a href="https://findahelpline.com" rel="noopener noreferrer">findahelpline.com</a> lists free helplines.</p>

    <h2>Liability for content and links</h2>
    <p>The content of this site was created with care. No guarantee can be given for its accuracy, completeness or timeliness.
    The operators of linked external sites are solely responsible for their content. Content or links that infringe the law
    are removed promptly once known.</p>

    <h2>Privacy</h2>
    <p>How your data is handled is described in the <a href="/datenschutz?lang=en">privacy policy</a>.</p>
"""
    return _page("Legal notice", c["site_name"], body, "en")


def _privacy_en(c) -> str:
    v = PRIVACY_VERSION.split("-")[:3]
    stand = f"{v[2]}/{v[1]}/{v[0]}"
    authority = escape(c["authority"]) if c["authority"] else "the data protection authority of the German federal state you live in, or the authority responsible for the operator"
    email = _v(c["email"], "OPERATOR_EMAIL", "en")
    cf_recipient = cf_basis = ""
    if c["cloudflare"]:
        cf_recipient = """
    <h3>Cloudflare (connection to the server)</h3>
    <p>The connection between your browser and the server runs through <strong>Cloudflare, Inc.</strong>,
    101 Townsend St., San Francisco, CA 94107, USA. Cloudflare forwards the requests and protects against attacks.
    In doing so, Cloudflare processes technical connection data such as your IP address, the time and the requested address,
    as well as the content of the requests. Your diary entries are already encrypted in your browser at that point and cannot
    be read by Cloudflare. Usernames are technically visible to Cloudflare.</p>
    <p>Cloudflare is certified under the EU-U.S. Data Privacy Framework. The transfer to the USA is based on the European
    Commission's adequacy decision of 10 July 2023 (Art. 45 GDPR). A data processing agreement under Art. 28 GDPR is in place
    with Cloudflare. More information:
    <a href="https://www.cloudflare.com/privacypolicy/" rel="noopener noreferrer">Cloudflare's privacy policy</a>.</p>"""
        cf_basis = "<tr><td>Forwarding and protecting the connection via Cloudflare</td><td>Art. 6(1)(f) GDPR (legitimate interest in a secure and available service)</td></tr>"
    blog_url = env("BLOG_URL", "").strip()
    blog_section = ""
    if blog_url.startswith("https://"):
        blog_section = f"""
    <h3>Blog</h3>
    <p>The blog at <a href="{escape(blog_url)}">{escape(blog_url.removeprefix("https://").rstrip("/"))}</a> is a static website.
    It sets no cookies, uses no tracking and embeds no third-party content. The web server keeps no access logs. When you visit it,
    technically necessary connection data (IP address, time, page requested) is processed only for the duration of the connection
    (Art. 6(1)(f) GDPR){" and delivered via Cloudflare (see above)" if c["cloudflare"] else ""}.</p>"""
    demo = (f'<li><strong>This is a demo.</strong> Every visitor gets their own anonymous account with sample data. It is deleted '
            f'automatically together with all data after {escape(c["demo_hours"])} hours. <strong>Please do not enter any real health data.</strong></li>') if c["demo"] else ""
    retention = (f'<li>Demo accounts: deleted automatically after {escape(c["demo_hours"])} hours or immediately via “End demo”</li>' if c["demo"]
                 else "<li>Account and entries: until you delete your account or an admin deletes it</li>")
    body = f"""
    {TRANSLATION_NOTE}
    <p class="small">As of {stand} · version {escape(PRIVACY_VERSION)}</p>

    <h2>The essentials</h2>
    <ul>
      {demo}
      <li>Your diary entries are <strong>encrypted in your browser</strong> before they reach the server. The key is derived from your password. Neither the operator nor admins can read your entries.</li>
      <li>There is <strong>no advertising, no tracking, no analytics</strong> and no embedded third-party content. Fonts and program code come from this server.</li>
      <li>Your entries contain <strong>health data</strong>. They are only stored with your explicit consent, which you can withdraw at any time by deleting your account.</li>
      <li>You can <strong>delete your account with all entries yourself at any time</strong> and download your entries beforehand as CSV, JSON or PDF.</li>
    </ul>

    <h2>1. Controller</h2>
    {_operator_block(c, "en")}

    <h2>2. What data is processed</h2>
    <h3>Account data</h3>
    <ul>
      <li>your username</li>
      <li>a sign-in key derived from your password, stored only as an Argon2id hash. Your password itself never reaches the server.</li>
      <li>the secret for two-factor sign-in (encrypted) and your recovery codes (hashes only)</li>
      <li>account status (waiting for approval, active, disabled) and, if applicable, the admin role</li>
      <li>the time of registration, of your consent (with the version of this policy) and of your last sign-in</li>
      <li>the number of failed sign-in attempts (for a short lock after several failures)</li>
    </ul>
    <h3>Diary entries, questionnaires, crisis plan (health data)</h3>
    <p>Mood, anxiety, drive, activities, information on medication intake (daily overview as well as your medications with dose,
    planned times and individual doses with time), notes, notes for your next therapy session, your personal crisis plan
    (including the names and phone numbers you enter there) and your answers and results in the PHQ-9 (depression) and GAD-7
    (anxiety) questionnaires. This information is health data within the meaning of Art. 9 GDPR. It is encrypted in your browser
    with AES-256-GCM and stored only in encrypted form. The server can only see <strong>how many</strong> encrypted records there
    are and their rough size class. Date, type (entry, questionnaire, medication, dose, note, crisis plan) and time of change are
    encrypted too. Questionnaires are scored only in your browser or in the app.</p>
    <h3>Session cookie</h3>
    <p>After you sign in, the server sets a technically necessary cookie to keep you signed in. It is valid for at most
    {escape(c["session_hours"])} hours and is deleted when you sign out. The server stores only a hash of it. A second cookie
    (<code>kw-lang</code>) stores your language choice if you switch languages.</p>
    <h3>Apps for iOS and Android</h3>
    <p>Instead of a cookie, the apps use a sign-in token. It is kept in your device's protected key storage (Keychain or Android
    Keystore), is valid for at most {escape(c["native_hours"])} hours and is deleted when you sign out. The apps contain no analytics
    or advertising libraries. The app saves reports and backup copies via your device's share menu; where you send them from there
    is up to you.</p>
    <h3>Storage in your browser</h3>
    <p>So that you don't have to enter your password again after reloading, the key for your entries stays in your browser's
    storage (IndexedDB) until you sign out or the automatic lock kicks in. It cannot be read out there. Your browser also remembers
    your settings for the PDF report (name, notes yes/no), the lock setting and your language. This information never leaves your device.</p>
    <h3>Connection data</h3>
    <p>To protect against abuse (limiting registrations and sign-in attempts), the server keeps your IP address briefly in memory,
    for at most one hour. It is not stored permanently. The application keeps no access logs.</p>
    <h3>Reports and backup copies</h3>
    <p>PDF reports, CSV backup copies and the full JSON export are created entirely in your browser and are not sent to the server.
    These files are unencrypted. Keep them safe accordingly.</p>
    <h3>Information about other people</h3>
    <p>If you enter names and phone numbers of people you trust in your crisis plan, these are also end-to-end encrypted and readable
    only by you. They are not used to contact those people.</p>

    <h2>3. Purposes and legal bases</h2>
    <div class="tablewrap"><table>
      <thead><tr><th>Purpose</th><th>Legal basis</th></tr></thead>
      <tbody>
        <tr><td>Providing the account, sign-in, approval by admins</td><td>Art. 6(1)(b) GDPR (user relationship)</td></tr>
        <tr><td>Storing your diary entries and questionnaires (health data)</td><td>Art. 9(2)(a) in conjunction with Art. 6(1)(a) GDPR (explicit consent at registration)</td></tr>
        <tr><td>Protection against abuse and attacks, lock after failed attempts</td><td>Art. 6(1)(f) GDPR (legitimate interest in a secure service)</td></tr>
        {cf_basis}
        <tr><td>Session cookie, language cookie and storage in the browser</td><td>§ 25(2) no. 2 TDDDG (strictly necessary for the service you requested)</td></tr>
      </tbody>
    </table></div>

    <h2>4. Consent and withdrawal</h2>
    <p>Consent is voluntary. Without it the diary cannot be used, because its only purpose is storing this information. You can
    withdraw your consent at any time with effect for the future: most easily by deleting your account in the app under
    “Security” → “Delete account”, or by email to {email}. The lawfulness of processing up to the withdrawal remains unaffected.</p>

    <h2>5. Recipients</h2>
    <p>Your data is not sold and not passed on for advertising. Admins of this installation see your username, your account status
    and the times of registration and last sign-in in the administration area, but <strong>no</strong> content of your entries.</p>
    <h3>Hosting</h3>
    <p>The server is operated by: {_v(c["hoster"], "HOSTER", "en")}. A data processing agreement under Art. 28 GDPR is in place
    with the provider. The provider only has access to encrypted entries.</p>
    {cf_recipient}

    {blog_section}
    <h2>6. Retention</h2>
    <ul>
      {retention}
      <li>accounts not approved: deleted automatically after {escape(c["pending_days"])} days</li>
      <li>abandoned registrations: deleted after 15 minutes</li>
      <li>sessions: at most {escape(c["session_hours"])} hours in the browser, {escape(c["native_hours"])} hours in the apps</li>
      <li>IP addresses in memory: at most one hour</li>
      <li>backups (contain entries only in encrypted form): at most {escape(c["backup_days"])} days. Deleted accounts disappear from the backups by then at the latest.</li>
    </ul>

    <h2>7. Security</h2>
    <p>Connections are encrypted with TLS. Entries are additionally end-to-end encrypted (Argon2id and HKDF for key derivation,
    AES-256-GCM). After a configurable period of inactivity, the app locks itself on your device. Sign-in requires a second factor.
    After several failed attempts, sign-in is temporarily blocked. Your content is encrypted with a random data key; the server
    stores it only wrapped with your password and, if you create one, with your recovery key. Of the recovery key, the server stores
    only an Argon2id hash. <strong>Without your password and without a recovery key, nobody can recover your entries.</strong></p>

    <h2>8. Your rights</h2>
    <p>You have the right of access (Art. 15 GDPR), rectification (Art. 16), erasure (Art. 17), restriction of processing (Art. 18),
    data portability (Art. 20) and to object to processing based on legitimate interests (Art. 21). You can do much of this directly
    in the app: view and change entries, download them as CSV, JSON or PDF and delete your account. For anything else, write to {email}.</p>
    <p>You also have the right to lodge a complaint with a data protection supervisory authority (Art. 77 GDPR), for example with
    {authority}.</p>

    <h2>9. No automated decision-making</h2>
    <p>There is no automated decision-making and no profiling. The evaluations in the app and in the PDF report (averages, trends)
    are calculated only for you, in your browser.</p>

    <h2>10. Not a medical service</h2>
    <p>The diary is a tool for self-observation and does not replace treatment. PHQ-9 and GAD-7 are recognised screening
    questionnaires, not a diagnosis. The pattern evaluations describe connections and are not a diagnosis. In an acute crisis, call 112.
    In Germany, TelefonSeelsorge is available around the clock at 0800 111 0 111 or 0800 111 0 222; in other countries,
    findahelpline.com lists free helplines.</p>

    <h2>11. Changes</h2>
    <p>If this policy changes in substance, the version above is updated. If the processing of your health data changes
    significantly, you will be asked for new consent.</p>
"""
    return _page("Privacy policy", c["site_name"], body, "en")
