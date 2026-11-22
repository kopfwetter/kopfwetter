// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
"use strict";
// PDF-Bericht für die Therapie. Läuft komplett im Browser (jsPDF, lokal ausgeliefert).
// window.KopfwetterReport.build({ entries: Map<date, entry>, from, to, name, withNotes }) -> { blob, filename }
(() => {
  const { t: $t, T: $T } = window.KW_I18N;   // Übersetzung (static/i18n.js)
  const LOC = window.KW_I18N.locale;
  const ACTS = ["Bewegung", "Draußen", "Soziale Kontakte", "Arbeit", "Hobby", "Haushalt", "Ruhe & Erholung", "Therapie"];
  const FEELS = ["Traurig", "Leer", "Hoffnungslos", "Erschöpft", "Antriebslos", "Wertlos", "Schuldig", "Beschämt", "Einsam", "Gereizt", "Frustriert",
    "Überfordert", "Überreizt", "Ängstlich", "Unruhig", "Gefühllos", "Ruhig", "Erleichtert", "Zufrieden", "Froh", "Dankbar", "Verbunden", "Motiviert", "Konzentriert"];
  const feelName = (n) => (FEELS.includes(n) ? $t(n) : n);
  const LVL = { 1: $t("leicht"), 2: $t("mittel"), 3: $t("stark") };
  const INTENT = { ja: $t("geschafft"), teilweise: $t("teilweise"), nein: $t("nicht geschafft") };
  const MEDLABEL = { ja: $t("Eingenommen"), teilweise: $t("Teilweise"), nein: $t("Vergessen/Nein"), keine: $t("Keine geplant") };
  const C = {
    ink: [29, 39, 51], muted: [91, 104, 120], line: [213, 219, 227], soft: [238, 241, 245], head: [227, 233, 241],
    mood: [63, 94, 140], anx: [176, 86, 106], drive: [79, 138, 110],
  };
  const SERIES = [["mood", $t("Stimmung"), C.mood], ["anxiety", $t("Angst"), C.anx], ["drive", $t("Antrieb"), C.drive]];
  const PW = 210, PH = 297, M = 16, CW = PW - 2 * M, BOTTOM = PH - 18;

  const pad = (n) => String(n).padStart(2, "0");
  const iso = (d) => d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  const parse = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d); };
  const EN = LOC !== "de-DE";
  const de = (s) => { const d = parse(s); return EN ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}` : `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}`; };
  const WD = ["So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"].map((d) => $t(d));
  const deShort = (s) => { const d = parse(s); return EN ? `${WD[d.getDay()]} ${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : `${WD[d.getDay()]} ${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`; };
  const num = (v) => typeof v === "number";
  const avg = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
  const f1 = (v) => (v == null ? "–" : LOC === "de-DE" ? v.toFixed(1).replace(".", ",") : v.toFixed(1));

  // Die eingebaute PDF-Schrift kennt nur Windows-1252. Alles andere wird ersetzt oder entfernt (z. B. Emojis).
  const CP1252 = new Set("€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ");
  const REPL = { "→": "->", "←": "<-", "≤": "<=", "≥": ">=", "≠": "!=", "✓": "ja", " ": " " };
  function clean(s) {
    let out = "";
    for (const ch of String(s || "").normalize("NFC")) {
      if (REPL[ch]) out += REPL[ch];
      else if (ch === "\n" || ch === "\t") out += ch === "\t" ? " " : "\n";
      else if ((ch.codePointAt(0) >= 32 && ch.codePointAt(0) < 127) || (ch.codePointAt(0) >= 160 && ch.codePointAt(0) <= 255) || CP1252.has(ch)) out += ch;
    }
    return out.replace(/[ ]{2,}/g, " ").trim();
  }

  function stats(list, key) {
    const v = list.map((e) => e[key]).filter(num);
    return { n: v.length, avg: avg(v), min: v.length ? Math.min(...v) : null, max: v.length ? Math.max(...v) : null };
  }

  const PHQ_SEV = [$t("minimal"), $t("mild"), $t("mittelgradig"), $t("ausgeprägt"), $t("schwer")];
  const PHQ_FREQ = [$t("überhaupt nicht"), $t("an einzelnen Tagen"), $t("an mehr als der Hälfte der Tage"), $t("beinahe jeden Tag")];
  const PHQ_DIFF = [$t("überhaupt nicht erschwert"), $t("etwas erschwert"), $t("relativ stark erschwert"), $t("sehr stark erschwert")];
  const phqSev = (score) => (score <= 4 ? 0 : score <= 9 ? 1 : score <= 14 ? 2 : score <= 19 ? 3 : 4);

  function build({ entries, assessments, items, sessNotes, from, to, name, withNotes }) {
    const jsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!jsPDF) throw new Error($t("Das PDF-Modul ist nicht geladen."));
    const days = [];
    for (let d = parse(from); iso(d) <= to; d.setDate(d.getDate() + 1)) days.push(iso(d));
    const all = items || [];
    const feels = all.filter((i) => i.kind === "feel" && i.date >= from && i.date <= to).sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time));
    const feelDays = new Set(feels.map((f) => f.date));
    // Tageswerte: Abend-Check-out, ohne Check-out der Morgen-Check-in (ab v2, gleiche Skala 1–10); fromAm markiert solche Tage
    const list = days.filter((d) => entries.has(d) || feelDays.has(d)).map((d) => {
      const e = { ...(entries.get(d) || {}), date: d }, a = e.am;
      if (a && a.v === 2 && !["mood", "anxiety", "drive"].some((k) => num(e[k]))) {
        ["mood", "anxiety", "drive"].forEach((k) => { if (num(a[k])) e[k] = a[k]; });
        e.fromAm = ["mood", "anxiety", "drive"].some((k) => num(e[k]));
      }
      return e;
    });
    const byDate = new Map(list.map((e) => [e.date, e]));
    const tests = (assessments || []).filter((a) => (a.type === "phq9" || a.type === "gad7") && a.date >= from && a.date <= to)
      .sort((a, b) => (a.at || a.date).localeCompare(b.at || b.date));
    const notes = sessNotes || [];
    const doses = all.filter((i) => i.kind === "dose" && i.date >= from && i.date <= to).sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time));
    if (!list.length && !tests.length && !doses.length && !notes.length && !feels.length) throw new Error($t("Im gewählten Zeitraum gibt es keine Einträge."));

    const doc = new jsPDF({ unit: "mm", format: "a4", compress: true });
    doc.setProperties({ title: $t("Kopfwetter – Bericht"), subject: `${de(from)} bis ${de(to)}`, creator: $t("Kopfwetter") });
    doc.setLineCap("round"); doc.setLineJoin("round");
    const font = (size, style = "normal", color = C.ink) => { doc.setFont("helvetica", style); doc.setFontSize(size); doc.setTextColor(...color); };
    let y = M;
    const ensure = (h) => { if (y + h > BOTTOM) { doc.addPage(); y = M; return true; } return false; };

    // ---- Kopf
    font(20, "bold", C.mood); doc.text($t("Kopfwetter"), M, y + 6);
    font(10.5, "normal", C.muted); doc.text($t("Stimmungstagebuch · Bericht für die Therapie"), M, y + 12);
    font(9.5, "normal", C.ink);
    const right = [];
    if (name) right.push(clean(name));
    right.push($T`Zeitraum: ${de(from)} – ${de(to)}`);
    right.push($T`Erstellt am ${de(iso(new Date()))}`);
    right.forEach((t, i) => { if (i === 0 && name) font(10.5, "bold"); else font(9.5, "normal", i === 0 ? C.ink : C.muted); doc.text(t, PW - M, y + 5 + i * 5, { align: "right" }); });
    y += 21;
    doc.setDrawColor(...C.line); doc.setLineWidth(0.3); doc.line(M, y, PW - M, y);
    y += 7;

    // ---- Für die nächste Sitzung (offene Punkte zuerst: das ist, worüber gesprochen werden soll)
    if (notes.length) {
      font(12, "bold"); doc.text($t("Für die nächste Sitzung"), M, y); y += 6;
      notes.forEach((n) => {
        doc.setFontSize(10);
        const lines = doc.splitTextToSize(clean(n.text), CW - 8);
        ensure(lines.length * 4.6 + 3);
        doc.setDrawColor(...C.mood); doc.setLineWidth(0.4); doc.rect(M + 0.5, y - 3, 3, 3);
        font(10, "normal"); doc.text(lines, M + 6, y);
        font(7.5, "normal", C.muted); doc.text(de(String(n.created).slice(0, 10)), PW - M, y, { align: "right" });
        y += lines.length * 4.6 + 2.2;
      });
      y += 5;
      doc.setDrawColor(...C.line); doc.setLineWidth(0.3); doc.line(M, y, PW - M, y); y += 7;
    }

    // ---- Kennzahlen
    // Trend: erste vs. zweite Hälfte der Einträge (chronologisch)
    const half = Math.ceil(list.length / 2);
    const firstHalf = list.slice(0, half), secondHalf = list.slice(half);
    const bw = (CW - 8) / 3, bh = 30;
    SERIES.forEach(([key, label, col], i) => {
      const s = stats(list, key), x = M + i * (bw + 4);
      doc.setDrawColor(...C.line); doc.setFillColor(...C.soft); doc.roundedRect(x, y, bw, bh, 2, 2, "FD");
      doc.setFillColor(...col); doc.rect(x, y + 3, 1.2, bh - 6, "F");
      font(9.5, "bold", col); doc.text(label, x + 5, y + 6.5);
      font(20, "bold", C.ink); doc.text(f1(s.avg), x + 5, y + 16);
      font(8, "normal", C.muted); doc.text($t("Durchschnitt (1–10)"), x + 5 + doc.getStringUnitWidth(f1(s.avg)) * 20 / doc.internal.scaleFactor + 2.5, y + 16);
      doc.text(s.n ? $T`Spanne ${s.min}–${s.max} · ${s.n} Werte` : $t("keine Werte"), x + 5, y + 21.5);
      const a1 = avg(firstHalf.map((e) => e[key]).filter(num)), a2 = avg(secondHalf.map((e) => e[key]).filter(num));
      if (list.length > 1) doc.text($T`1. Hälfte ${f1(a1)} / 2. Hälfte ${f1(a2)}`, x + 5, y + 26);
    });
    y += bh + 6;

    const medDays = list.filter((e) => e.meds && e.meds !== $t("keine"));
    const medTaken = medDays.filter((e) => e.meds === "ja").length;
    const medPartial = medDays.filter((e) => e.meds === "teilweise").length;
    const lowDays = list.filter((e) => num(e.mood) && e.mood <= 3).length;
    const highAnx = list.filter((e) => num(e.anxiety) && e.anxiety >= 8).length;
    const facts = [
      [$t("Einträge"), $T`${list.length} von ${days.length} Tagen`],
      [$t("Medikamente"), medDays.length ? $T`an ${medTaken} von ${medDays.length} Tagen eingenommen (${Math.round((medTaken / medDays.length) * 100)} %)${medPartial ? $T`, ${medPartial}× teilweise` : ""}` : $t("keine Angaben")],
      [$t("Niedrige Stimmung (1–3)"), `${lowDays} ${lowDays === 1 ? $t("Tag") : $t("Tage")}`],
      [$t("Starke Angst (8–10)"), `${highAnx} ${highAnx === 1 ? $t("Tag") : $t("Tage")}`],
    ];
    facts.forEach(([k, v]) => { font(9.5, "bold"); doc.text(k, M, y); font(9.5, "normal"); doc.text(v, M + 48, y); y += 5.2; });
    y += 1;
    font(8, "normal", C.muted);
    doc.text($t("„1. / 2. Hälfte“ vergleicht die ältere mit der neueren Hälfte der Einträge im Zeitraum."), M, y); y += 4;
    doc.text($t("Skalen: Stimmung 1 = sehr schlecht, 10 = sehr gut · Angst 1 = keine, 10 = sehr stark · Antrieb 1 = kaum, 10 = viel"), M, y);
    y += 8;

    // ---- Diagramm
    ensure(78);
    font(12, "bold"); doc.text($t("Verlauf"), M, y);
    let lx = PW - M;
    [...SERIES].reverse().forEach(([, label, col]) => {
      font(8.5, "normal", C.muted); const w = doc.getTextWidth(label); lx -= w;
      doc.text(label, lx, y); doc.setDrawColor(...col); doc.setLineWidth(0.8); doc.line(lx - 6.5, y - 1.1, lx - 1.5, y - 1.1); lx -= 11;
    });
    y += 4;
    const cx0 = M + 7, cx1 = PW - M - 2, cy0 = y + 2, cy1 = y + 58;
    const n = days.length;
    const X = (i) => (n === 1 ? (cx0 + cx1) / 2 : cx0 + (i * (cx1 - cx0)) / (n - 1));
    const Y = (v) => cy0 + ((10 - v) * (cy1 - cy0)) / 9;
    doc.setLineWidth(0.2); doc.setDrawColor(...C.line);
    [1, 3, 5, 7, 10].forEach((v) => { doc.line(cx0, Y(v), cx1, Y(v)); font(7.5, "normal", C.muted); doc.text(String(v), cx0 - 2, Y(v) + 1, { align: "right" }); });
    const ticks = Math.min(6, n);
    for (let k = 0; k < ticks; k++) {
      const i = ticks === 1 ? 0 : Math.round((k * (n - 1)) / (ticks - 1));
      const d = parse(days[i]);
      doc.text(EN ? `${pad(d.getDate())}/${pad(d.getMonth() + 1)}` : `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`, X(i), cy1 + 5, { align: k === 0 ? "left" : k === ticks - 1 ? "right" : "center" });
    }
    const dots = n <= 120;
    SERIES.forEach(([key, , col]) => {
      doc.setDrawColor(...col); doc.setFillColor(...col); doc.setLineWidth(0.55);
      let prev = null;
      days.forEach((d, i) => {
        const e = byDate.get(d); const v = e && num(e[key]) ? e[key] : null;
        if (v == null) { prev = null; return; }
        const pt = [X(i), Y(v)];
        if (prev) doc.line(prev[0], prev[1], pt[0], pt[1]);
        if (dots) doc.circle(pt[0], pt[1], 0.75, "F");
        prev = pt;
      });
    });
    y = cy1 + 12;

    // ---- Aktivitäten
    const actRows = ACTS.map((a) => {
      const yes = list.filter((e) => (e.activities || []).includes(a));
      const no = list.filter((e) => !(e.activities || []).includes(a));
      return [a, yes.length, avg(yes.map((e) => e.mood).filter(num)), avg(no.map((e) => e.mood).filter(num))];
    }).filter((r) => r[1] > 0);
    if (actRows.length) {
      ensure(16 + actRows.length * 6);
      font(12, "bold"); doc.text($t("Aktivitäten und Stimmung"), M, y); y += 5;
      const cols = [M, M + 52, M + 72, M + 125];
      doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F");
      font(8.5, "bold"); [$t("Aktivität"), $t("Tage"), $t("Ø Stimmung an diesen Tagen"), $t("Ø Stimmung an anderen Tagen")].forEach((h, i) => doc.text(h, cols[i] + 2, y + 4.5));
      y += 6.5;
      actRows.forEach((r) => {
        font(9, "normal"); doc.text($t(r[0]), cols[0] + 2, y + 4.3); doc.text(String(r[1]), cols[1] + 2, y + 4.3);
        doc.text(f1(r[2]), cols[2] + 2, y + 4.3); doc.text(f1(r[3]), cols[3] + 2, y + 4.3);
        y += 6; doc.setDrawColor(...C.line); doc.setLineWidth(0.2); doc.line(M, y, PW - M, y);
      });
      font(7.5, "normal", C.muted); doc.text($t("Zeigt Zusammenhänge, keine Ursachen."), M, y + 4); y += 11;
    }

    // ---- Gefühle (über den Tag eingetragen, mit Stärke 1–3)
    if (feels.length) {
      const by = new Map();
      feels.forEach((f) => { if (!by.has(f.name)) by.set(f.name, []); by.get(f.name).push(f); });
      const rows = [...by.entries()].map(([n, fs]) => [feelName(n), fs.length, avg(fs.map((f) => f.level).filter(num)), new Set(fs.map((f) => f.date)).size])
        .sort((a, b) => b[1] - a[1]).slice(0, 15);
      ensure(16 + rows.length * 6);
      font(12, "bold"); doc.text($t("Gefühle"), M, y); y += 5;
      const fc = [M, M + 60, M + 84, M + 124];
      doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F");
      font(8.5, "bold"); [$t("Gefühl"), $t("Anzahl"), $t("Ø Stärke (1–3)"), $t("an Tagen")].forEach((h, i) => doc.text(h, fc[i] + 2, y + 4.5));
      y += 6.5;
      rows.forEach((r) => {
        font(9, "normal"); doc.text(clean(r[0]), fc[0] + 2, y + 4.3); doc.text(String(r[1]), fc[1] + 2, y + 4.3);
        doc.text(f1(r[2]), fc[2] + 2, y + 4.3); doc.text(String(r[3]), fc[3] + 2, y + 4.3);
        y += 6; doc.setDrawColor(...C.line); doc.setLineWidth(0.2); doc.line(M, y, PW - M, y);
      });
      font(7.5, "normal", C.muted); doc.text($t("Die einzelnen Gefühle mit Uhrzeit und Auslöser stehen bei den Tageseinträgen."), M, y + 4); y += 11;
    }

    // ---- Selbsttests (PHQ-9 und GAD-7)
    const TESTDEF = {
      phq9: { title: $t("Depressions-Selbsttest (PHQ-9)"), max: 27, bands: [4, 9, 14, 19], sev: PHQ_SEV, safety: 8,
        legend: [$t("Summe 0–27: 0–4 minimal, 5–9 mild, 10–14 mittelgradig, 15–19 ausgeprägt, 20–27 schwer (Kroenke et al. 2001). Screening, keine Diagnose."),
          $t("Deutsche Fassung: Gesundheitsfragebogen für Patienten (PHQ-D), Löwe, Spitzer, Zipfel & Herzog.")] },
      gad7: { title: $t("Angst-Selbsttest (GAD-7)"), max: 21, bands: [4, 9, 14], sev: [$t("minimal"), $t("leicht"), $t("mäßig"), $t("schwer")], safety: null,
        legend: [$t("Summe 0–21: 0–4 minimal, 5–9 leicht, 10–14 mäßig, 15–21 schwer (Spitzer et al. 2006). Screening, keine Diagnose."),
          $t("Deutsche Fassung: Löwe et al. (2008).")] },
    };
    for (const [type, T] of Object.entries(TESTDEF)) {
      const rows = tests.filter((t) => t.type === type);
      if (!rows.length) continue;
      const sevOf = (sc) => { const i = T.bands.findIndex((b) => sc <= b); return i < 0 ? T.bands.length : i; };
      ensure(26 + rows.length * 6.5);
      font(12, "bold"); doc.text(T.title, M, y); y += 5;
      const tc = T.safety != null ? [M, M + 26, M + 46, M + 76, M + 124] : [M, M + 26, M + 46, null, M + 76];
      const heads = [$t("Datum"), $t("Summe"), $t("Schweregrad"), T.safety != null ? $t("Frage 9 (Tod/Selbstverletzung)") : null, $t("Beeinträchtigung im Alltag")];
      const head = () => { doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F"); font(8.5, "bold"); heads.forEach((h, i) => { if (h) doc.text(h, tc[i] + 1.5, y + 4.5); }); y += 6.5; };
      head();
      rows.forEach((t, idx) => {
        if (ensure(6.5)) head();
        if (idx % 2 === 1) { doc.setFillColor(...C.soft); doc.rect(M, y, CW, 6.2, "F"); }
        const sv = sevOf(t.score), hi = t.score >= 15;
        font(9, "normal"); doc.text(de(t.date), tc[0] + 1.5, y + 4.3);
        font(9.5, "bold", hi ? C.anx : C.ink); doc.text(`${t.score} / ${T.max}`, tc[1] + 1.5, y + 4.3);
        font(9, "normal", hi ? C.anx : C.ink); doc.text(T.sev[sv], tc[2] + 1.5, y + 4.3);
        if (T.safety != null) {
          const q = t.answers ? t.answers[T.safety] : null;
          font(9, q > 0 ? "bold" : "normal", q > 0 ? C.anx : C.ink); doc.text(q == null ? "–" : `${q} – ${PHQ_FREQ[q]}`, tc[3] + 1.5, y + 4.3);
        }
        font(8.5, "normal", C.ink); doc.text(t.difficulty == null ? "–" : PHQ_DIFF[t.difficulty], tc[4] + 1.5, y + 4.3);
        y += 6.2;
      });
      font(7.5, "normal", C.muted);
      doc.text(T.legend[0], M, y + 4); doc.text(T.legend[1], M, y + 7.5);
      y += 14;
    }

    // ---- Medikamenteneinnahme
    if (doses.length) {
      const meds = all.filter((i) => i.kind === "med");
      // Übersicht je Medikament: Einnahmen und – bei geplanten Zeiten – Anteil der geplanten Einnahmen
      const byMed = new Map();
      doses.forEach((d) => { const k = d.medId || d.name; if (!byMed.has(k)) byMed.set(k, []); byMed.get(k).push(d); });
      const rows = [...byMed.entries()].map(([k, ds]) => {
        const m = meds.find((x) => x.id === k);
        const label = clean(ds[0].name + (ds[0].dose ? " " + ds[0].dose : ""));
        let planText = $t("bei Bedarf");
        if (m && m.times && m.times.length) {
          let planned = 0, hit = 0;
          const start = [m.created, ds[0].date].filter(Boolean).sort()[0];   // nachgetragene Tage zählen mit
          const nowD = new Date(), today = iso(nowD), nowHM = pad(nowD.getHours()) + ":" + pad(nowD.getMinutes());
          for (const day of days) {
            if (start && day < start) continue;
            if (m.archivedAt && day > m.archivedAt) continue;
            const due = day === today ? m.times.filter((t) => t <= nowHM).length : m.times.length;   // heute nur bereits fällige
            const n = ds.filter((d) => d.date === day).length;
            planned += due; hit += Math.min(n, due);
          }
          planText = planned ? $T`${hit} von ${planned} geplanten (${Math.round((hit / planned) * 100)} %) · ${m.times.join(", ")} Uhr` : m.times.join(", ") + $t(" Uhr");
        }
        return { label, n: ds.length, planText };
      });
      ensure(22 + rows.length * 6);
      font(12, "bold"); doc.text($t("Medikamenteneinnahme"), M, y); y += 5;
      const mc = [M, M + 70, M + 92];
      doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F");
      font(8.5, "bold"); [$t("Medikament"), $t("Einnahmen"), $t("Geplant / eingenommen")].forEach((h, i) => doc.text(h, mc[i] + 1.5, y + 4.5));
      y += 6.5;
      rows.forEach((r) => {
        font(9, "bold"); doc.text(doc.splitTextToSize(r.label, 66)[0], mc[0] + 1.5, y + 4.3);
        font(9, "normal"); doc.text(String(r.n), mc[1] + 1.5, y + 4.3); doc.text(r.planText, mc[2] + 1.5, y + 4.3);
        y += 6; doc.setDrawColor(...C.line); doc.setLineWidth(0.2); doc.line(M, y, PW - M, y);
      });
      y += 5;
      // Einzelne Einnahmen
      const dc = [M, M + 24, M + 40, M + 100, M + 124];
      const head = () => { doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F"); font(8.5, "bold");
        [$t("Datum"), $t("Uhrzeit"), $t("Medikament"), $t("Dosis"), $t("Notiz")].forEach((h, i) => doc.text(h, dc[i] + 1.5, y + 4.5)); y += 6.5; };
      ensure(14); head();
      doses.forEach((d, idx) => {
        doc.setFontSize(8.5);
        const note = d.note ? doc.splitTextToSize(clean(d.note), PW - M - dc[4] - 3) : [];
        const h = Math.max(1, note.length) * 3.9 + 2.4;
        if (ensure(h)) head();
        if (idx % 2 === 1) { doc.setFillColor(...C.soft); doc.rect(M, y, CW, h, "F"); }
        const ty = y + 4;
        const prev = doses[idx - 1];
        font(9, "normal", prev && prev.date === d.date ? C.muted : C.ink); doc.text(deShort(d.date), dc[0] + 1.5, ty);
        font(9, "bold"); doc.text(d.time, dc[1] + 1.5, ty);
        font(9, "normal"); doc.text(doc.splitTextToSize(clean(d.name), 58)[0], dc[2] + 1.5, ty);
        doc.text(clean(d.dose || "–"), dc[3] + 1.5, ty);
        if (note.length) { font(8.5, "normal", C.muted); doc.text(note, dc[4] + 1.5, ty); }
        y += h;
      });
      y += 8;
    }

    // ---- Tageseinträge
    const cols = [M, M + 20, M + 33, M + 46, M + 60, M + 88];
    const textW = PW - M - cols[5] - 5;
    const tableHead = () => {
      doc.setFillColor(...C.head); doc.rect(M, y, CW, 6.5, "F");
      font(8.5, "bold");
      [$t("Datum"), $t("Stimmung"), $t("Angst"), $t("Antrieb"), $t("Medikamente"), withNotes ? $t("Aktivitäten · Notiz") : $t("Aktivitäten")].forEach((h, i) => {
        if (i >= 1 && i <= 3) doc.text(h, cols[i] + 6.5, y + 4.5, { align: "center" }); else doc.text(h, cols[i] + 1.5, y + 4.5);
      });
      y += 6.5;
    };
    if (list.length) { ensure(30);
    font(12, "bold"); doc.text($t("Tageseinträge"), M, y); y += 5;
    tableHead(); }
    const LH = 3.9;
    list.forEach((e, idx) => {
      doc.setFont("helvetica", "normal"); doc.setFontSize(8.5);
      const acts = (e.activities || []).map((a) => $t(a)).join(", ");
      const actLines = acts ? doc.splitTextToSize(clean(acts), textW) : [];
      doc.setFontSize(9);
      const noteLines = withNotes && e.note ? doc.splitTextToSize(clean(e.note), textW) : [];
      doc.setFontSize(8.5);
      const am = e.am || {}, amParts = [];
      if (e.fromAm) amParts.push($t("Werte vom Morgen (kein Check-out)"));
      else if (am.v === 2) {
        if (num(am.mood)) amParts.push($T`Morgens Stimmung ${am.mood}/10`);
        if (num(am.anxiety)) amParts.push($T`Angst ${am.anxiety}/10`);
        if (num(am.drive)) amParts.push($T`Antrieb ${am.drive}/10`);
      } else {
        if (num(am.mood)) amParts.push($T`Morgens Stimmung ${am.mood}/5`);
        if (num(am.energy)) amParts.push($T`Energie ${am.energy}/5`);
      }
      if (am.intent) amParts.push($t("Vorhaben: ") + am.intent + (e.intentDone ? " (" + INTENT[e.intentDone] + ")" : ""));
      const amLines = amParts.length ? doc.splitTextToSize(clean(amParts.join(" · ")), textW) : [];
      const dayFeels = feels.filter((f) => f.date === e.date).map((f) => f.time + " " + feelName(f.name) + " (" + LVL[f.level] + ")" + (withNotes && f.trigger ? ": " + f.trigger : ""));
      const feelLines = dayFeels.length ? doc.splitTextToSize(clean(dayFeels.join(" · ")), textW) : [];
      const lines = Math.max(1, amLines.length + actLines.length + noteLines.length + feelLines.length);
      const h = lines * LH + 3.2;
      if (ensure(h)) tableHead();
      if (idx % 2 === 1) { doc.setFillColor(...C.soft); doc.rect(M, y, CW, h, "F"); }
      const ty = y + 4.3;
      font(9, "normal"); doc.text(deShort(e.date), cols[0] + 1.5, ty);
      SERIES.forEach(([key, , col], i) => { font(9.5, "bold", num(e[key]) ? col : C.muted); doc.text(num(e[key]) ? String(e[key]) : "–", cols[1 + i] + 6.5, ty, { align: "center" }); });
      font(8.5, "normal", e.meds === "nein" ? C.anx : C.ink); doc.text(e.meds ? MEDLABEL[e.meds] || e.meds : "–", cols[4] + 1.5, ty);
      let ly = ty;
      if (amLines.length) { font(8.5, "normal", C.mood); doc.text(amLines, cols[5] + 1.5, ly); ly += amLines.length * LH; }
      if (actLines.length) { font(8.5, "normal", C.muted); doc.text(actLines, cols[5] + 1.5, ly); ly += actLines.length * LH; }
      if (noteLines.length) { font(9, "normal", C.ink); doc.text(noteLines, cols[5] + 1.5, ly); ly += noteLines.length * LH; }
      if (feelLines.length) { font(8.5, "normal", C.anx); doc.text(feelLines, cols[5] + 1.5, ly); }
      if (!amLines.length && !actLines.length && !noteLines.length && !feelLines.length) { font(8.5, "normal", C.muted); doc.text("–", cols[5] + 1.5, ty); }
      y += h;
    });

    // ---- Fußzeile
    const pages = doc.getNumberOfPages();
    for (let p = 1; p <= pages; p++) {
      doc.setPage(p);
      doc.setDrawColor(...C.line); doc.setLineWidth(0.2); doc.line(M, PH - 13, PW - M, PH - 13);
      font(7.5, "normal", C.muted);
      doc.text($t("Selbstauskunft aus einem persönlichen Stimmungstagebuch. Keine Diagnose. Vertraulich."), M, PH - 9);
      doc.text($T`Seite ${p} von ${pages}`, PW - M, PH - 9, { align: "right" });
    }
    return { blob: doc.output("blob"), filename: EN ? `kopfwetter-report_${from}_to_${to}.pdf` : `kopfwetter-bericht_${from}_bis_${to}.pdf` };
  }

  // ---------------------------------------------------------------- Krisenplan als PDF (eine Seite zum Ausdrucken)
  function crisisPlan({ plan, sections, fixed, name }) {
    const jsPDF = window.jspdf && window.jspdf.jsPDF;
    if (!jsPDF) throw new Error($t("Das PDF-Modul ist nicht geladen."));
    if (!plan) throw new Error($t("Es gibt noch keinen Krisenplan."));
    const doc = new jsPDF({ unit: "mm", format: "a4", compress: true });
    doc.setProperties({ title: $t("Mein Krisenplan"), creator: $t("Kopfwetter") });
    const font = (size, style = "normal", color = C.ink) => { doc.setFont("helvetica", style); doc.setFontSize(size); doc.setTextColor(...color); };
    let y = M;
    const ensure = (h) => { if (y + h > BOTTOM) { doc.addPage(); y = M; } };
    font(20, "bold", C.anx); doc.text($t("Mein Krisenplan"), M, y + 6);
    font(9.5, "normal", C.muted);
    doc.text([name ? clean(name) : "", $T`Stand: ${de(String(plan.updated).slice(0, 10))}`].filter(Boolean), PW - M, y + 3, { align: "right" });
    y += 12;
    font(9.5, "normal", C.ink);
    const intro = doc.splitTextToSize($t("Wenn es mir sehr schlecht geht, gehe ich diesen Plan Schritt für Schritt durch. Hilft ein Schritt nicht, nehme ich den nächsten."), CW);
    doc.text(intro, M, y); y += intro.length * 4.3 + 4;
    const contactLine = (c) => clean([c.name, c.phone].filter(Boolean).join(": ") + (c.note ? ` (${c.note})` : ""));
    sections.forEach((sec, i) => {
      let lines = [];
      if (sec.type === "list") lines = (plan[sec.k] || []).map((x) => "•  " + clean(x));
      else lines = [...(plan[sec.k] || []), ...(sec.fixed ? fixed : [])].filter((c) => c.name || c.phone).map((c) => "•  " + contactLine(c));
      doc.setFontSize(10);
      const wrapped = lines.length ? lines.flatMap((l) => doc.splitTextToSize(l, CW - 10)) : [$t("(noch leer)")];
      const h = 9 + wrapped.length * 4.6 + 5;
      ensure(h);
      doc.setFillColor(...C.anx); doc.circle(M + 3, y + 1.6, 3, "F");
      font(9, "bold", [255, 255, 255]); doc.text(String(i + 1), M + 3, y + 2.8, { align: "center" });
      font(12, "bold"); doc.text(sec.t, M + 9, y + 3);
      y += 8;
      font(10, "normal", lines.length ? C.ink : C.muted); doc.text(wrapped, M + 9, y);
      y += wrapped.length * 4.6 + 5;
    });
    const pages = doc.getNumberOfPages();
    for (let p = 1; p <= pages; p++) {
      doc.setPage(p); doc.setDrawColor(...C.line); doc.setLineWidth(0.2); doc.line(M, PH - 13, PW - M, PH - 13);
      font(8, "normal", C.muted);
      doc.text($t("In akuter Gefahr: 112 · Telefonseelsorge 0800 111 0 111 / 0800 111 0 222 (rund um die Uhr)"), M, PH - 9);
      if (pages > 1) doc.text($T`Seite ${p} von ${pages}`, PW - M, PH - 9, { align: "right" });
    }
    return { blob: doc.output("blob"), filename: EN ? "kopfwetter-crisis-plan.pdf" : "kopfwetter-krisenplan.pdf" };
  }

  window.KopfwetterReport = { build, clean, crisisPlan };
})();
