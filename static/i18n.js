// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
// Übersetzung: Deutsch ist die Quellsprache. Die Sprache der Seite steht in <html lang> (vom Server bzw. App-Build gesetzt).
// t("Deutscher Text {0}", wert) und T`Deutscher Text ${wert}` liefern den englischen Text aus window.KW_EN, sonst den deutschen.
(() => {
  const lang = document.documentElement.lang === "en" ? "en" : "de";
  const dict = (lang === "en" && window.KW_EN) || {};
  const missing = new Set();
  const fill = (s, v) => (v.length ? s.replace(/\{(\d+)\}/g, (m, i) => (v[i] === undefined ? m : String(v[i]))) : s);
  function t(s, ...v) {
    if (s == null) return s;
    let r = s;
    if (lang === "en") {
      if (Object.prototype.hasOwnProperty.call(dict, s)) r = dict[s];
      else if ((window.KW_EN_PATTERNS || []).some(([re, to]) => { const m = new RegExp(re).exec(s); if (m) r = s.replace(new RegExp(re), to); return !!m; })) { /* übersetzt */ }
      else if (!missing.has(s)) { missing.add(s); if (window.console) console.debug("i18n: fehlt", JSON.stringify(s)); }
    }
    return fill(r, v);
  }
  // Tagged Template: T`Noch ${n} Fragen` -> Schlüssel "Noch {0} Fragen"
  function T(strs, ...v) {
    let key = strs[0];
    for (let i = 1; i < strs.length; i++) key += "{" + (i - 1) + "}" + strs[i];
    return t(key, ...v);
  }
  function setLang(l) {
    if (l !== "de" && l !== "en") return;
    try { localStorage.setItem("kw-lang", l); } catch (e) { /* egal */ }
    document.cookie = "kw-lang=" + l + "; path=/; max-age=31536000; SameSite=Lax" + (location.protocol === "https:" ? "; Secure" : "");
    if (window.KopfwetterPlatform && window.KopfwetterPlatform.native) location.replace(l === "en" ? "en.html" : "index.html");
    else { const u = new URL(location.href); u.searchParams.delete("lang"); location.replace(u.toString()); }
  }
  window.KW_I18N = { lang, locale: lang === "en" ? "en-GB" : "de-DE", t, T, setLang, missing };
})();
