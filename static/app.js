// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
"use strict";
(() => {
  const { t: $t, T: $T } = window.KW_I18N;   // Übersetzung (static/i18n.js)
  const LOC = window.KW_I18N.locale;
  const $ = (id) => document.getElementById(id);
  // Versionsangabe aus der eigenen Skript-Adresse (app.js?v=…), für nachgeladene Module
  const ASSET_V = (() => { try { return new URL(document.currentScript.src).searchParams.get("v") || ""; } catch (e) { return ""; } })();
  const withV = (src) => (ASSET_V ? src + "?v=" + ASSET_V : src);
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = (buf) => { const a = new Uint8Array(buf); let s = ""; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const setStatus = (t) => { $("status").textContent = t || ""; };
  const msg = (id, t) => { $(id).textContent = t || ""; };

  // ================================================================ Plattform (Web oder iOS/Android-App)
  // In den Apps setzt static/native.js (aus mobile/) window.KopfwetterPlatform: Server-Adresse, Token im
  // Keychain/Keystore und Speichern über das Teilen-Menü. Im Browser gilt dieser Standard:
  const P = window.KopfwetterPlatform || {
    native: false,
    apiBase: "",
    async getToken() { return null; },
    async setToken() {},
    async clearToken() {},
    async saveFile(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = filename;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    },
  };
  let authToken = null;

  // ================================================================ API
  class ApiError extends Error { constructor(status, detail) { super(detail || $t("Fehler ") + status); this.status = status; } }
  async function api(method, path, body) {
    const headers = { "X-Requested-With": "kopfwetter-app" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (P.native) { headers["X-Client"] = "native"; if (authToken) headers.Authorization = "Bearer " + authToken; }
    let r;
    try {
      r = await fetch(P.apiBase + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: P.native ? "omit" : "same-origin", cache: "no-store" });
    } catch (e) { throw new ApiError(0, $t("Der Server ist nicht erreichbar. Prüfe deine Verbindung.")); }
    if (r.status === 204) return null;
    let data = null; try { data = await r.json(); } catch (e) { /* kein JSON */ }
    if (!r.ok) {
      // Meldungen des Servers sind deutsch; übersetzt wird hier (static/i18n/en.js enthält sie)
      const detail = data && typeof data.detail === "string" ? $t(data.detail) : (r.status === 422 ? $t("Ungültige Eingabe.") : null);
      if (r.status === 401 && !path.startsWith("/api/auth/")) sessionLost();
      throw new ApiError(r.status, detail);
    }
    return data;
  }

  // ================================================================ Schlüsselablage
  // Der AES-Schlüssel ist "non-extractable": Er kann im Browser benutzt, aber nicht ausgelesen werden.
  // Er liegt bis zum Abmelden in IndexedDB, damit ein Neuladen nicht sofort zum Login führt.
  let idbReady = null;
  function idb() {
    if (!idbReady) idbReady = new Promise((res, rej) => {
      const r = indexedDB.open("kopfwetter-app-keys", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("k");
      r.onsuccess = () => res(r.result); r.onerror = () => { idbReady = null; rej(r.error); };
    });
    return idbReady;
  }
  async function keyOp(mode, fn) {
    try {
      const d = await idb();
      return await new Promise((res, rej) => {
        const t = d.transaction("k", mode); const q = fn(t.objectStore("k"));
        t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error);
      });
    } catch (e) { return null; }
  }
  const keyGet = () => keyOp("readonly", (s) => s.get("enc"));
  const keySet = (k) => keyOp("readwrite", (s) => s.put(k, "enc"));
  const keyDel = () => keyOp("readwrite", (s) => s.delete("enc"));

  // ================================================================ Krypto
  // Schlüssel-Aufbau (Protokoll v2, docs/CRYPTO.md): Alle Inhalte sind mit einem zufälligen Datenschlüssel (DEK)
  // verschlüsselt. Der Server speichert ihn nur verpackt: mit einem Schlüssel aus dem Passwort (Argon2id, dann HKDF),
  // optional mit dem Wiederherstellungsschlüssel. Konten aus v1 (PBKDF2) werden beim Login auf Argon2id umgestellt.
  async function getSalt(username) { return api("POST", "/api/auth/salt", { username }); }   // -> { salt, kdf }
  const hkdfInfo = (s) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(s) });
  const isCurrentKdf = (k) => !!k && k.alg === "argon2id";
  async function deriveMaster(password, salt, kdf) {
    const pw = password.normalize("NFKC");
    // Untergrenzen, damit ein manipulierter Server keine schwachen Parameter unterschieben kann
    if (kdf && kdf.alg === "argon2id" && kdf.m >= 65536 && kdf.t >= 3 && kdf.p >= 1 && kdf.m <= 1048576 && kdf.t <= 20 && kdf.p <= 8) {
      if (!window.hashwasm || !window.hashwasm.argon2id) throw new Error($t("Argon2 ließ sich nicht laden. Bitte lade die Seite neu."));
      return window.hashwasm.argon2id({ password: pw, salt: unb64(salt), parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: "binary" });
    }
    if (kdf && kdf.alg === "pbkdf2-sha256" && kdf.i >= 600000) {   // nur noch für die Anmeldung von v1-Konten
      const base = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(salt), iterations: kdf.i, hash: "SHA-256" }, base, 256));
    }
    throw new Error($t("Unbekannte oder zu schwache Schlüsselableitung."));
  }
  async function deriveKeys(password, salt, kdf) {
    const master = await deriveMaster(password, salt, kdf);
    const hk = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
    const authBits = await crypto.subtle.deriveBits(hkdfInfo("kopfwetter-app/auth/v1"), hk, 256);
    const kek = await crypto.subtle.deriveKey(hkdfInfo("kopfwetter-app/kek/v1"), hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    master.fill(0);
    return { authKey: b64(authBits), kek };
  }
  const DEK_AAD = te.encode("kopfwetter-app/dek/v1");
  async function wrapDek(kek, raw) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv: b64(iv), ct: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: DEK_AAD }, kek, raw)) };
  }
  async function unwrapDek(kek, w) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(w.iv), additionalData: DEK_AAD }, kek, unb64(w.ct)));
  }
  // Aus dem DEK entstehen zwei nicht exportierbare Schlüssel: AES-GCM für die Inhalte und HMAC für die Kennungen.
  async function importDek(raw) {
    const enc = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const hk = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    const ids = await crypto.subtle.deriveKey(hkdfInfo("kopfwetter-app/record-id/v1"), hk, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
    raw.fill(0);                       // Rohbytes nicht länger als nötig im Speicher
    return { enc, ids };
  }
  async function adoptDek(raw) { const k = await importDek(raw); encKey = k.enc; idKey = k.ids; }
  async function persistKeys() {
    if (lockMode() === "session") return keyDel();     // „beim Schließen sperren“: Schlüssel nur im Arbeitsspeicher
    return keySet({ key: encKey, idKey, username: me.username, salt: me.salt, kdf: me.kdf });
  }

  // Wiederherstellungsschlüssel: 160 Zufallsbits als 32 Zeichen (ohne verwechselbare Zeichen), in Vierergruppen
  const RK = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";       // 32 Zeichen, ohne I, O, 0, 1
  function newRecoveryKey() {
    const b = crypto.getRandomValues(new Uint8Array(20)); let bits = "", out = "";
    b.forEach((x) => { bits += x.toString(2).padStart(8, "0"); });
    for (let i = 0; i < 160; i += 5) out += RK[parseInt(bits.slice(i, i + 5), 2)];
    return out.match(/.{4}/g).join("-");
  }
  function parseRecoveryKey(str) {
    const c = String(str || "").toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/I/g, "1");
    if (c.length !== 32 || [...c].some((ch) => !RK.includes(ch))) return null;
    let bits = ""; for (const ch of c) bits += RK.indexOf(ch).toString(2).padStart(5, "0");
    return Uint8Array.from(bits.match(/.{8}/g), (x) => parseInt(x, 2));
  }
  async function deriveRecovery(bytes) {
    const hk = await crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits", "deriveKey"]);
    const auth = await crypto.subtle.deriveBits(hkdfInfo("kopfwetter-app/recovery-auth/v1"), hk, 256);
    const kek = await crypto.subtle.deriveKey(hkdfInfo("kopfwetter-app/recovery-kek/v1"), hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    return { authKey: b64(auth), kek };
  }
  // Nur noch zum Lesen von v1-Datensätzen (AAD = Datum bzw. Kennung im Klartext), siehe migrateV1()
  async function unseal(key, date, rec) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.iv), additionalData: te.encode(date) }, key, unb64(rec.ct));
    return JSON.parse(td.decode(pt));
  }

  // ---------------------------------------------------------------- Datensätze (Protokoll v2)
  // Alles liegt in einer Tabelle. Kennung = HMAC(idKey, Art + ":" + Schlüssel), der Server sieht also weder Art noch
  // Datum. Klartext wird mit Leerzeichen auf feste Größen aufgefüllt (JSON erlaubt sie), damit die Länge wenig verrät.
  const REC_AAD = (id) => te.encode("kopfwetter-app/record/v1:" + id);
  async function rid(kind, key) {
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", idKey, te.encode(kind + ":" + key)));
    return [...sig.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function padded(text) {
    const n = te.encode(text).length;
    const size = n <= 256 ? 256 : n <= 65536 ? 2 ** Math.ceil(Math.log2(n)) : Math.ceil(n / 16384) * 16384;
    return text + " ".repeat(size - n);
  }
  async function putRecord(kind, key, data) {
    const id = await rid(kind, key), iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = te.encode(padded(JSON.stringify({ k: kind, key, d: data })));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: REC_AAD(id) }, encKey, pt);
    await api("PUT", "/api/records/" + id, { iv: b64(iv), ct: b64(ct) });
  }
  async function delRecord(kind, key) { await api("DELETE", "/api/records/" + (await rid(kind, key))); }
  async function loadAll() {
    const list = await api("GET", "/api/records");
    const e = new Map(), a = new Map(), it = new Map(); let bad = 0;
    for (const rec of list) {
      try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.iv), additionalData: REC_AAD(rec.id) }, encKey, unb64(rec.ct));
        const o = JSON.parse(td.decode(pt));
        if ((await rid(o.k, o.key)) !== rec.id) { bad++; continue; }   // vertauschter Datensatz
        if (o.k === "entry") e.set(o.key, { ...o.d, date: o.key });
        else if (o.k === "assess") a.set(o.key, { ...o.d, id: o.key });
        else if (o.k === "item") it.set(o.key, { ...o.d, id: o.key });
      } catch (err) { bad++; }
    }
    entries = e; assessments = a; items = it;
    return { total: list.length, bad };
  }
  // Einmalige Umstellung aus v1: alte Datensätze (Datum bzw. Kennung im Klartext) lesen, neu ablegen, alte löschen.
  async function migrateV1() {
    const old = await api("GET", "/api/legacy");
    const n = old.entries.length + old.assessments.length + old.items.length;
    if (!n) return 0;
    setStatus($T`Stelle ${n} Datensätze auf das neue Format um …`);
    for (const r of old.entries) await putRecord("entry", r.key, await unseal(encKey, r.key, r));
    for (const r of old.assessments) await putRecord("assess", r.key, await unseal(encKey, (r.key.startsWith("gad7-") ? "gad7:" : "phq9:") + r.key, r));
    for (const r of old.items) await putRecord("item", r.key, await unseal(encKey, "item:" + r.key, r));
    await api("DELETE", "/api/legacy");
    return n;
  }

  // ================================================================ Ansichten
  let encKey = null, idKey = null;
  let me = null;        // { username, isAdmin, salt }
  let authState = null;
  const normUser = (u) => u.trim().toLowerCase();
  const USER_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
  // Startseite: Kopfbereich mit Jahresübersicht (Beispielmuster, immer gleich) statt des kleinen Titels
  (() => {
    let seed = 7; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
    const box = $("hero-heat");
    for (let i = 0; i < 182; i++) {
      const week = Math.floor(i / 7); let level = 0;
      if (!(week < 6 && rnd() < 0.85)) {
        level = Math.max(1, Math.min(5, Math.round(1.6 + week / 9 + (rnd() - 0.5) * 2.6)));
        if (rnd() < 0.08) level = 0;
      }
      const c = document.createElement("span"); c.className = "h" + level; box.append(c);
    }
  })();
  const LANDING = ["register", "login", "recover", "demo"];
  function show(view) {
    const landing = LANDING.includes(view);
    $("hero").hidden = !landing; document.body.classList.toggle("landing", landing);
    ["register", "login", "recover", "consent", "lock", "demo", "app"].forEach((v) => { $("view-" + v).hidden = v !== view; });
    $("who-wrap").hidden = view !== "app";
    if (view === "app" && me) $("who").textContent = $t("Angemeldet als ") + me.username;
  }
  async function busy(btn, label, fn) {
    const old = btn.textContent; btn.disabled = true; btn.textContent = label;
    try { return await fn(); } finally { btn.disabled = false; btn.textContent = old; }
  }
  async function sessionLost(text) {
    encKey = null; idKey = null; me = null; entries = new Map(); assessments = new Map(); items = new Map(); readOnly = false; await keyDel();
    authToken = null; try { await P.clearToken(); } catch (e) { /* egal */ }
    $("admin-card").hidden = true; $("plan-card").hidden = true;
    if (authState && authState.demo) { showDemo(text ?? $t("Die Demo-Sitzung ist abgelaufen. Du kannst eine neue starten.")); return; }
    showLogin(text ?? $t("Deine Sitzung ist abgelaufen. Bitte melde dich neu an."));
  }
  function showLogin(text) {
    show("login"); setStatus("");
    $("reg-link").hidden = !(authState && authState.registrationOpen);
    msg("login-msg", text || "");
    ($("l-user").value ? $("l-pw") : $("l-user")).focus();
  }
  function showRegister() {
    const first = authState && authState.needsSetup;
    ["reg-1", "reg-2", "reg-3", "reg-4"].forEach((id) => { $(id).hidden = id !== "reg-1"; });
    $("reg-first").hidden = !first; $("reg-token-wrap").hidden = !first; $("r-token").required = !!first;
    $("reg-approval").hidden = first || !authState.requireApproval;
    $("reg-login-link").hidden = !!first;
    $("regTitle").textContent = first ? $t("Erstes Konto einrichten") : $t("Konto erstellen");
    if (first && !authState.setupEnabled) msg("reg-msg", $t("Setze SETUP_TOKEN in der .env und starte den Container neu, um das erste Konto anzulegen."));
    show("register"); setStatus(""); $("r-user").focus();
  }
  $("to-login").addEventListener("click", () => showLogin());
  $("to-login2").addEventListener("click", () => showLogin());
  $("to-register").addEventListener("click", () => { msg("reg-msg", ""); showRegister(); });
  $("to-recover").addEventListener("click", () => { $("rc-user").value = $("l-user").value; msg("rc-msg", ""); show("recover"); $("rc-user").value ? $("rc-key").focus() : $("rc-user").focus(); });
  $("rc-back").addEventListener("click", () => showLogin());

  function renderLinks(links) {
    // Infoseiten der Add-ons (ADDON_DOMAIN) und Landingpage (SITE_URL)
    addonBase = links && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(links.addonDomain || "") ? links.addonDomain : "";
    siteBase = links && /^https:\/\/[^\s"<>/]+$/.test(links.site || "") ? links.site : "";
    const p = $("links"); p.textContent = "";
    // Zur Landingpage (Funktionen, Roadmap, Apps): SITE_URL, in den Apps die Server-Adresse, ohne beides / neben /app
    { const site = links && /^https:\/\/[^\s"<>]+$/.test(links.site || "") ? links.site : (P.apiBase || "");
      if (site || location.pathname.startsWith("/app")) {
        const a = document.createElement("a"); a.href = site + "/" + (window.KW_I18N.lang === "en" ? "?lang=en" : ""); a.textContent = $t("Über Kopfwetter");
        if (P.native) { a.rel = "noopener noreferrer"; a.target = "_blank"; } p.append(a);
      } }
    [["blog", $t("Blog")], ["privacy", $t("Datenschutz")], ["imprint", $t("Impressum")]].forEach(([k, label]) => {
      let url = links && links[k];
      if (!url || !(/^https?:\/\//.test(url) || /^\/[a-z0-9/_-]*$/i.test(url))) return;
      if (url.startsWith("/") && window.KW_I18N.lang === "en" && k !== "blog") url += (url.includes("?") ? "&" : "?") + "lang=en";
      if (url.startsWith("/") && P.apiBase) url = P.apiBase + url;
      if (p.childNodes.length) p.append(" · ");
      const a = document.createElement("a"); a.href = url; a.textContent = label;
      if (url.startsWith("http")) { a.rel = "noopener noreferrer"; a.target = "_blank"; }
      p.append(a);
    });
    // Sprachwahl: Link zur jeweils anderen Sprache
    const other = window.KW_I18N.lang === "en" ? ["de", "Deutsch"] : ["en", "English"];
    const sw = document.createElement("button"); sw.type = "button"; sw.className = "link"; sw.lang = other[0]; sw.textContent = other[1];
    sw.addEventListener("click", () => window.KW_I18N.setLang(other[0]));
    if (p.childNodes.length) p.append(" · ");
    p.append(sw);
    if (window.KW_I18N.lang === "en") document.querySelectorAll('a[href^="/datenschutz"], a[href^="/impressum"]').forEach((x) => { if (!x.getAttribute("href").includes("lang=")) x.href = x.getAttribute("href") + "?lang=en"; });
    p.hidden = !p.childNodes.length;
    const ok = (u) => typeof u === "string" && /^https:\/\/[^\s"<>]+$/.test(u);
    if (ok(links && links.demo)) document.querySelectorAll("[data-demo-link]").forEach((x) => {
      x.hidden = false; const a = x.querySelector("a"); a.href = links.demo;
      if (P.native) { a.target = "_blank"; a.rel = "noopener noreferrer"; }
    });
    if (ok(links && links.app)) { $("app-link").hidden = false; $("app-url").href = links.app; }
  }

  async function boot() {
    if (!(P.native || window.isSecureContext) || !window.crypto || !crypto.subtle) {
      setStatus($t("Diese Seite braucht HTTPS, damit die Verschlüsselung im Browser funktioniert.")); return;
    }
    if (P.native) {
      try { authToken = await P.getToken(); } catch (e) { authToken = null; }
      if (P.apiBase) document.querySelectorAll('a[href^="/"]').forEach((a) => { a.href = P.apiBase + a.getAttribute("href"); });
    }
    try { authState = await api("GET", "/api/auth/state"); } catch (e) { setStatus(e.message); return; }
    renderLinks(authState.links);
    setStatus("");
    if (authState.demo) {
      document.body.classList.add("demo"); $("logout").textContent = $t("Demo beenden");
      $("demo-hours").textContent = authState.demo.hours;
      const stored = authState.user && await keyGet();
      if (stored && stored.key && stored.idKey && stored.username === authState.user.username) {
        encKey = stored.key; idKey = stored.idKey; me = { ...authState.user, salt: stored.salt, kdf: stored.kdf }; setDemoUntil(authState.demo.until);
        afterLogin(); return;
      }
      await keyDel(); showDemo(); return;
    }
    if (authState.needsSetup) { await keyDel(); showRegister(); return; }
    if (authState.user) {
      const stored = await keyGet();
      if (stored && stored.key && stored.idKey && stored.username === authState.user.username && !lockDue()) {
        encKey = stored.key; idKey = stored.idKey; me = { ...authState.user, salt: stored.salt, kdf: stored.kdf };
        touch(true); afterLogin(); return;
      }
      // Sitzung gültig, aber der Schlüssel ist weg (gesperrt, neu geladen, älteres Format): mit dem Passwort entsperren
      await keyDel(); showLock(authState.user); return;
    }
    await keyDel(); showLogin();
  }

  // ---------------------------------------------------------------- Registrierung
  let reg = null; // { regToken, keys, username, salt }
  $("reg-1").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const username = normUser($("r-user").value), pw = $("r-pw").value, pw2 = $("r-pw2").value;
    if (!USER_RE.test(username)) return msg("reg-msg", $t("Benutzername: 3–32 Zeichen, nur a–z, 0–9, Punkt, Unterstrich und Bindestrich."));
    if (pw.length < 12) return msg("reg-msg", $t("Das Passwort braucht mindestens 12 Zeichen."));
    if (pw !== pw2) return msg("reg-msg", $t("Die beiden Passwörter stimmen nicht überein."));
    if (!$("r-consent").checked) return msg("reg-msg", $t("Bitte bestätige die Einwilligung, sonst kann das Tagebuch nichts speichern."));
    msg("reg-msg", "");
    busy($("r-go"), $t("Leite Schlüssel ab …"), async () => {
      try {
        const { salt } = await getSalt(username);
        const keys = await deriveKeys(pw, salt, authState.kdf);
        const dek = crypto.getRandomValues(new Uint8Array(32));
        const wrappedKey = await wrapDek(keys.kek, dek);
        const r = await api("POST", "/api/auth/register/begin", { username, authKey: keys.authKey, setupToken: $("r-token").value.trim(), consent: $("r-consent").checked, wrappedKey });
        reg = { regToken: r.regToken, keys: await importDek(dek), username, salt };
        $("qr").src = r.qr; $("totp-secret").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
        $("r-pw").value = ""; $("r-pw2").value = ""; $("r-token").value = "";
        $("reg-1").hidden = true; $("reg-2").hidden = false; $("r-code").value = ""; msg("reg-msg2", ""); $("r-code").focus();
      } catch (e) { msg("reg-msg", e.message); }
    });
  });
  let regResult = null;
  $("reg-2").addEventListener("submit", (ev) => {
    ev.preventDefault();
    busy($("r-confirm"), $t("Prüfe …"), async () => {
      try {
        regResult = await api("POST", "/api/auth/register/finish", { regToken: reg.regToken, code: $("r-code").value.trim() });
        if (regResult.status === "active") {
          if (regResult.token) { authToken = regResult.token; await P.setToken(authToken); }
          encKey = reg.keys.enc; idKey = reg.keys.ids;
          me = { username: regResult.username, isAdmin: regResult.isAdmin, consentCurrent: true, salt: reg.salt, kdf: authState.kdf };
          await persistKeys(); touch(true);
          authState.needsSetup = false;
        }
        $("recovery").textContent = regResult.recoveryCodes.join("\n");
        $("reg-2").hidden = true; $("reg-3").hidden = false;
      } catch (e) {
        msg("reg-msg2", e.message);
        if (e.status === 400) { $("reg-2").hidden = true; $("reg-1").hidden = false; msg("reg-msg", e.message); }
      }
    });
  });
  $("copy-codes").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("recovery").textContent); $("copy-codes").textContent = $t("Kopiert"); }
    catch (e) { const r = document.createRange(); r.selectNodeContents($("recovery")); const s = getSelection(); s.removeAllRanges(); s.addRange(r); }
  });
  $("recovery-done").addEventListener("click", () => {
    $("recovery").textContent = "";
    if (regResult && regResult.status === "active") { enterApp(); }
    else { $("reg-name").textContent = "„" + reg.username + "“"; $("l-user").value = reg.username; $("reg-3").hidden = true; $("reg-4").hidden = false; }
    reg = null;
  });

  // ---------------------------------------------------------------- Anmeldung
  // Packt den DEK mit dem Passwort aus. Konten mit älterer Ableitung (PBKDF2) werden dabei auf Argon2id umgestellt:
  // gleiches Passwort, neuer Login-Schlüssel und neu verpackter DEK; die Inhalte bleiben unverändert.
  async function openWithPassword(pw, info, wrappedKey, k) {
    let dek;
    try { dek = await unwrapDek(k.kek, wrappedKey); }
    catch (e) { throw new Error($t("Der Schlüssel ließ sich nicht entpacken. Bitte melde dich noch einmal an.")); }
    let kdf = info.kdf;
    if (!isCurrentKdf(kdf)) {
      const nk = await deriveKeys(pw, info.salt, authState.kdf);
      await api("POST", "/api/account/kdf", { oldAuthKey: k.authKey, newAuthKey: nk.authKey, wrappedKey: await wrapDek(nk.kek, dek) });
      kdf = authState.kdf;
    }
    await adoptDek(dek);
    return kdf;
  }
  $("login-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const username = normUser($("l-user").value), pw = $("l-pw").value, code = $("l-code").value.trim();
    if (!USER_RE.test(username)) return msg("login-msg", $t("Benutzername, Passwort oder Code stimmt nicht."));
    msg("login-msg", "");
    busy($("l-go"), $t("Prüfe …"), async () => {
      try {
        const info = await getSalt(username);
        const k = await deriveKeys(pw, info.salt, info.kdf);
        const r = await api("POST", "/api/auth/login", { username, authKey: k.authKey, code });
        if (r.token) { authToken = r.token; await P.setToken(authToken); }
        const kdf = await openWithPassword(pw, info, r.wrappedKey, k);
        me = { username: r.username, isAdmin: r.isAdmin, consentCurrent: r.consentCurrent, salt: info.salt, kdf };
        await persistKeys(); touch(true);
        $("l-pw").value = ""; $("l-code").value = "";
        await afterLogin();
        if (r.usedRecovery) setStatus($T`Wiederherstellungscode verwendet. Es sind noch ${r.recoveryCodesLeft} übrig.`);
      } catch (e) { msg("login-msg", e.message); $("l-code").value = ""; }
    });
  });
  $("logout").addEventListener("click", async () => {
    if (authState && authState.demo) return endDemo();
    try { await api("POST", "/api/auth/logout"); } catch (e) { /* trotzdem lokal abmelden */ }
    await sessionLost("");
  });

  // ---------------------------------------------------------------- Automatische Sperre
  // Nach der eingestellten Zeit ohne Bedienung wird der Schlüssel aus dem Browser gelöscht und die Seite neu geladen.
  // Die Sitzung bleibt bestehen; zum Entsperren reicht das Passwort (der DEK wird damit neu ausgepackt).
  const LOCK_OPTS = [["5", $t("nach 5 Minuten ohne Nutzung")], ["15", $t("nach 15 Minuten ohne Nutzung")], ["60", $t("nach 1 Stunde ohne Nutzung")],
    ["session", $t("beim Schließen oder Neuladen")], ["never", $t("nie (nicht empfohlen)")]];
  const lsGet = (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* dann gilt der Standard */ } };
  function lockMode() {
    if (authState && authState.demo) return "never";
    const m = lsGet("kw-lock"); return LOCK_OPTS.some(([k]) => k === m) ? m : "15";
  }
  const lockMs = () => (/^\d+$/.test(lockMode()) ? Number(lockMode()) * 60000 : null);
  let lastTouch = 0;
  function touch(force) {
    const t = Date.now();
    if (force === true || t - lastTouch > 15000) { lastTouch = t; lsSet("kw-last", String(t)); }
  }
  function lockDue() {
    const ms = lockMs(); if (ms == null) return false;
    const last = Number(lsGet("kw-last") || 0); return !last || Date.now() - last > ms;
  }
  async function lockNow() { encKey = null; idKey = null; await keyDel(); location.reload(); }
  ["pointerdown", "keydown", "scroll", "touchstart"].forEach((ev) => addEventListener(ev, () => { if (encKey) touch(); }, { passive: true }));
  setInterval(() => { if (encKey && lockDue()) lockNow(); }, 20000);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && encKey && lockDue()) lockNow(); });
  (() => {
    const sel = $("lock-mode");
    LOCK_OPTS.forEach(([k, label]) => { const o = document.createElement("option"); o.value = k; o.textContent = label; sel.append(o); });
    sel.value = lockMode();
    sel.addEventListener("change", async () => { lsSet("kw-lock", sel.value); touch(true); if (encKey && me) await persistKeys(); });
  })();

  let lockFails = 0;
  function showLock(user) {
    show("lock"); setStatus(""); $("lock-user").textContent = user.username; $("lock-pw").value = ""; msg("lock-msg", "");
    setTimeout(() => $("lock-pw").focus(), 50);
  }
  $("lock-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    busy($("lock-go"), $t("Entsperre …"), async () => {
      try {
        const user = authState.user, pw = $("lock-pw").value;
        const info = await getSalt(user.username);
        const keys = await api("GET", "/api/account/keys");
        const k = await deriveKeys(pw, info.salt, info.kdf);
        let kdf;
        try { kdf = await openWithPassword(pw, info, keys.wrappedKey, k); }
        catch (e) {
          if (++lockFails >= 5) { try { await api("POST", "/api/auth/logout"); } catch (x) { /* egal */ } await sessionLost($t("Zu viele falsche Passwörter. Bitte melde dich neu an.")); return; }
          throw new Error($t("Das Passwort stimmt nicht."));
        }
        lockFails = 0; $("lock-pw").value = "";
        me = { ...user, salt: info.salt, kdf };
        await persistKeys(); touch(true); await afterLogin();
      } catch (e) { msg("lock-msg", e.message); }
    });
  });
  $("lock-logout").addEventListener("click", async () => {
    try { await api("POST", "/api/auth/logout"); } catch (e) { /* trotzdem lokal abmelden */ }
    await sessionLost("");
  });

  // ---------------------------------------------------------------- Demo (nur auf einer Demo-Instanz, DEMO_MODE=1)
  // Jeder Besuch bekommt ein eigenes Wegwerf-Konto: zufälliger Name, zufälliges Passwort, das nie angezeigt wird.
  // Verschlüsselt wird wie in der echten App; der Schlüssel liegt nur in diesem Browser.
  function showDemo(text) { show("demo"); setStatus(""); $("demo-consent").checked = false; msg("demo-msg", text || ""); }
  function setDemoUntil(iso) {
    $("demo-until").textContent = iso ? $T`am ${new Date(iso).toLocaleString(LOC, { dateStyle: "medium", timeStyle: "short" })} Uhr` : $T`nach ${authState.demo.hours} Stunden`;
  }
  $("demo-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!$("demo-consent").checked) return msg("demo-msg", $t("Bitte bestätige das Häkchen."));
    busy($("demo-go"), $t("Richte die Demo ein …"), async () => {
      try {
        const abc = "abcdefghijklmnopqrstuvwxyz0123456789";
        const username = "demo-" + [...crypto.getRandomValues(new Uint8Array(10))].map((b) => abc[b % 36]).join("");
        const pw = b64(crypto.getRandomValues(new Uint8Array(32)));
        const { salt } = await getSalt(username);
        const keys = await deriveKeys(pw, salt, authState.kdf);
        const dek = crypto.getRandomValues(new Uint8Array(32));
        const wrappedKey = await wrapDek(keys.kek, dek);
        const r = await api("POST", "/api/demo/start", { username, authKey: keys.authKey, wrappedKey, consent: true });
        if (r.token) { authToken = r.token; await P.setToken(authToken); }
        await adoptDek(dek); me = { username: r.username, isAdmin: false, consentCurrent: true, salt, kdf: authState.kdf };
        await persistKeys();
        authState.user = { username: r.username, isAdmin: false, consentCurrent: true }; setDemoUntil(r.until);
        msg("demo-msg", $t("Lege Beispieldaten an …"));
        await importData(sampleExport());
        await afterLogin();
      } catch (e) { msg("demo-msg", e.message); }
    });
  });
  async function endDemo() {
    try { await api("POST", "/api/demo/end"); } catch (e) { /* läuft ohnehin ab */ }
    authState.user = null; await sessionLost($t("Die Demo wurde beendet und alle Daten sind gelöscht."));
  }
  $("demo-end").addEventListener("click", () => busy($("demo-end"), $t("Lösche …"), endDemo));

  // Erfundene Beispieldaten für vier Wochen. Bewegung und Draußen-Tage sind etwas besser, damit „Muster“ etwas zeigt.
  function sampleExport() {
    let seed = 20261104; const rand = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
    const clamp = (v) => Math.max(1, Math.min(10, Math.round(v)));
    const day = (off) => { const d = new Date(); d.setDate(d.getDate() - off); return iso(d); };
    const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const notes = [$t("Schlecht geschlafen, alles zäh."), $t("Kurzer Spaziergang hat gutgetan."), $t("Telefonat mit einer Freundin."), $t("Viel Grübeln am Abend."),
      $t("Ganz okay. Mittags draußen gewesen."), $t("Therapiesitzung, anstrengend, aber hilfreich."), $t("Wenig Energie, nur das Nötigste geschafft."), $t("Erster richtig guter Tag seit Langem.")];
    const intents = [$t("Wäsche waschen"), $t("Arzttermin ausmachen"), $t("Eine halbe Stunde spazieren"), $t("Steuerunterlagen sortieren"), $t("Freundin anrufen")];
    const triggers = [$t("Volles Postfach"), $t("Lauter Supermarkt"), $t("Grübeln über die Arbeit"), $t("Nachricht von einer Freundin"), $t("Sonne beim Spaziergang")];
    const entries = [], feels = [];
    for (let off = 28; off >= 1; off--) {
      const date = day(off), wd = parse(date).getDay(), trend = (28 - off) / 14;    // leichte Besserung über die Wochen
      const acts = ACTS.filter((a) => rand() < ({ Bewegung: 0.4, Draußen: 0.5, "Soziale Kontakte": 0.3, Arbeit: wd > 0 && wd < 6 ? 0.8 : 0.1, Therapie: wd === 3 ? 0.9 : 0 }[a] ?? 0.25));
      const lift = (acts.includes("Bewegung") ? 1 : 0) + (acts.includes("Draußen") ? 1 : 0) + (wd === 0 || wd === 6 ? 0.5 : 0);
      const mood = clamp(3.5 + trend + lift + (rand() - 0.5) * 2);
      const at = (h, m) => new Date(parse(date).getTime() + (h * 60 + m) * 60e3).toISOString();
      const intent = rand() < 0.6 ? intents[Math.floor(rand() * intents.length)] : "";
      const am = { v: 2, mood: clamp(mood - 1 + (rand() - 0.5) * 2), anxiety: clamp(9 - mood + (rand() - 0.3) * 2), drive: clamp(mood - 1.5 + (rand() - 0.5) * 2), intent, at: at(7, 10 + Math.floor(rand() * 50)) };
      entries.push({ date, data: { am, mood, anxiety: clamp(9 - mood + (rand() - 0.5) * 2), drive: clamp(mood - 0.5 + (rand() - 0.5) * 2), activities: acts,
        meds: rand() < 0.85 ? "ja" : rand() < 0.5 ? "teilweise" : "nein", note: rand() < 0.45 ? notes[Math.floor(rand() * notes.length)] : "",
        intentDone: intent ? (rand() < 0.5 ? "ja" : rand() < 0.5 ? "teilweise" : "nein") : null, pmAt: at(21, Math.floor(rand() * 50)) } });
      const nFeel = Math.floor(rand() * 4);
      for (let f = 0; f < nFeel; f++) {
        const hard = rand() < (mood <= 5 ? 0.8 : 0.4), list = hard ? FEEL_HARD : FEEL_GOOD;
        const h = 9 + Math.floor(rand() * 11), m = Math.floor(rand() * 60);
        feels.push({ id: `feel-${date}-${hex(5)}`, data: { kind: "feel", date, time: pad(h) + ":" + pad(m), name: list[Math.floor(rand() * list.length)],
          level: 1 + Math.floor(rand() * 3), trigger: rand() < 0.5 ? (hard ? triggers.slice(0, 3) : triggers.slice(3))[Math.floor(rand() * (hard ? 3 : 2))] : "", at: at(h, m) } });
      }
    }
    const test = (type, off, answers) => ({ id: (type === "gad7" ? "gad7-" : "") + day(off) + "-" + hex(4),
      data: { v: 1, type, date: day(off), at: new Date(parse(day(off)).getTime() + 9 * 3600e3).toISOString(), answers, difficulty: 1, score: answers.reduce((a, b) => a + b, 0) } });
    const medId = "med-" + hex(5), items = [
      { id: medId, data: { kind: "med", name: $t("Beispielmedikament"), dose: $t("1 Tablette"), times: ["08:00"], archived: false, created: day(28) } },
      { id: PLAN_ID, data: { kind: "plan", v: 1, updated: new Date().toISOString(), warn: [$t("Ich ziehe mich zurück und sage Treffen ab"), $t("Ich schlafe kaum noch")],
        self: [$t("Eine Runde um den Block gehen"), $t("Lieblingsmusik hören"), $t("Kalt duschen")], places: [$t("Café an der Ecke"), $t("Bibliothek")],
        people: [{ name: $t("Beispiel: Freundin"), phone: "", note: "" }], pros: [{ name: $t("Beispiel: Praxis Dr. Muster"), phone: "", note: "" }],
        safe: [$t("Medikamente bei jemand anderem aufbewahren lassen")], reasons: [$t("Meine Katze"), $t("Die Radtour im Sommer")] } },
      { id: "sess-" + hex(5), data: { kind: "sess", text: $t("Schlaf ansprechen: seit zwei Wochen Einschlafprobleme"), created: new Date().toISOString(), done: false, doneAt: null } },
    ];
    for (let off = 7; off >= 1; off--) if (off !== 4)
      items.push({ id: `dose-${day(off)}-${hex(5)}`, data: { kind: "dose", medId, name: $t("Beispielmedikament"), dose: $t("1 Tablette"), date: day(off), time: "08:" + pad(Math.floor(rand() * 40)), note: "", at: new Date().toISOString() } });
    items.push(...feels, { id: "prefs", data: { kind: "prefs", addons: { feel: true, tests: true, meds: true, patterns: true, therapy: true } } });
    return { format: EXPORT_FORMAT, version: 1, entries,
      assessments: [test("phq9", 21, [2, 2, 1, 2, 1, 1, 2, 1, 0]), test("gad7", 14, [2, 1, 2, 1, 1, 1, 1]), test("phq9", 3, [1, 1, 1, 1, 1, 0, 1, 1, 0])], items };
  }

  // ---------------------------------------------------------------- Passwort vergessen (Wiederherstellungsschlüssel)
  $("recover-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const username = normUser($("rc-user").value), bytes = parseRecoveryKey($("rc-key").value);
    const code = $("rc-code").value.trim(), pw = $("rc-pw").value, pw2 = $("rc-pw2").value;
    if (!USER_RE.test(username)) return msg("rc-msg", $t("Bitte gib deinen Benutzernamen ein."));
    if (!bytes) return msg("rc-msg", $t("Der Wiederherstellungsschlüssel hat 32 Zeichen (Buchstaben und Ziffern 2–9). Bindestriche und Leerzeichen sind egal."));
    if (pw.length < 12) return msg("rc-msg", $t("Das neue Passwort braucht mindestens 12 Zeichen."));
    if (pw !== pw2) return msg("rc-msg", $t("Die beiden Passwörter stimmen nicht überein."));
    msg("rc-msg", "");
    busy($("rc-go"), $t("Prüfe …"), async () => {
      try {
        const rk = await deriveRecovery(bytes); bytes.fill(0);
        const b = await api("POST", "/api/auth/recover/begin", { username, recoveryAuth: rk.authKey, code });
        let dek;
        try { dek = await unwrapDek(rk.kek, b.recoveryWrapped); } catch (e) { throw new Error($t("Der Schlüssel passt nicht zu diesem Konto.")); }
        const nk = await deriveKeys(pw, b.salt, authState.kdf);
        const wrappedKey = await wrapDek(nk.kek, dek);
        const r = await api("POST", "/api/auth/recover/finish", { recoverToken: b.recoverToken, newAuthKey: nk.authKey, wrappedKey });
        if (r.token) { authToken = r.token; await P.setToken(authToken); }
        await adoptDek(dek); me = { username: r.username, isAdmin: r.isAdmin, consentCurrent: r.consentCurrent, salt: b.salt, kdf: authState.kdf };
        await persistKeys(); touch(true);
        ["rc-key", "rc-code", "rc-pw", "rc-pw2"].forEach((id) => { $(id).value = ""; });
        await afterLogin();
        setStatus($t("Neues Passwort gesetzt. Dein Wiederherstellungsschlüssel bleibt gültig. Andere Geräte wurden abgemeldet."));
      } catch (e) { msg("rc-msg", e.message); $("rc-code").value = ""; }
    });
  });

  // ---------------------------------------------------------------- Wiederherstellungsschlüssel erstellen
  let recoveryInfo = null, pendingRk = null;
  const bannerKey = () => "rk-later-" + (me ? me.username : "");
  function renderRecovery() {
    const set = recoveryInfo && recoveryInfo.set;
    $("rk-status").textContent = "";
    if (set) {
      const ok = el("span", "rk-ok", $t("Eingerichtet"));
      $("rk-status").append(ok, $T` am ${new Date(recoveryInfo.createdAt).toLocaleDateString(LOC)}. Damit kannst du ein neues Passwort setzen, falls du deines vergisst.`);
    } else $("rk-status").textContent = $t("Noch nicht eingerichtet. Ohne Schlüssel sind deine Einträge bei einem vergessenen Passwort verloren.");
    $("rk-new").textContent = set ? $t("Neuen Schlüssel erstellen") : $t("Schlüssel erstellen");
    let later = false; try { later = sessionStorage.getItem(bannerKey()) === "1"; } catch (e) { /* egal */ }
    $("rk-banner").hidden = set || later;
  }
  function rkReset() { pendingRk = null; $("rk-form").hidden = true; $("rk-show").hidden = true; $("rk-new").hidden = false; $("rk-key").textContent = ""; $("rk-form").reset(); $("rk-verify").value = ""; }
  function rkOpen() { setTab("more"); rkReset(); $("rk-new").hidden = true; $("rk-form").hidden = false; msg("rk-msg", ""); $("rk-box").scrollIntoView({ behavior: "smooth", block: "start" }); $("rk-pw").focus(); }
  $("rk-new").addEventListener("click", rkOpen);
  $("rk-banner-go").addEventListener("click", rkOpen);
  $("rk-banner-later").addEventListener("click", () => { try { sessionStorage.setItem(bannerKey(), "1"); } catch (e) { /* egal */ } $("rk-banner").hidden = true; });
  $("rk-cancel").addEventListener("click", rkReset);
  $("rk-abort").addEventListener("click", rkReset);
  $("rk-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    busy($("rk-make"), $t("Prüfe …"), async () => {
      try {
        const k = await deriveKeys($("rk-pw").value, me.salt, me.kdf);
        const keys = await api("GET", "/api/account/keys");
        try { (await unwrapDek(k.kek, keys.wrappedKey)).fill(0); } catch (e) { throw new Error($t("Das Passwort stimmt nicht.")); }
        const key = newRecoveryKey();
        pendingRk = { key, k, code: $("rk-code").value.trim() };   // erst nach der Kontrolle wird gespeichert
        $("rk-key").textContent = key;
        $("rk-form").hidden = true; $("rk-show").hidden = false; msg("rk-msg2", ""); $("rk-verify").focus();
      } catch (e) { msg("rk-msg", e.message); }
    });
  });
  $("rk-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("rk-key").textContent); $("rk-copy").textContent = $t("Kopiert"); }
    catch (e) { const r = document.createRange(); r.selectNodeContents($("rk-key")); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); }
  });
  $("rk-file").addEventListener("click", async () => {
    const text = $T`Kopfwetter – Wiederherstellungsschlüssel\r\n\r\nBenutzername: ${me.username}\r\nSchlüssel:    ${pendingRk.key}\r\nErstellt:     ${new Date().toLocaleString(LOC)}\r\n\r\n` +
      $t("Damit setzt du ein neues Passwort, falls du deines vergisst (Anmeldung → „Passwort vergessen?“).\r\n") +
      $t("Du brauchst zusätzlich den Code aus der Authenticator-App oder einen der zehn Wiederherstellungscodes.\r\n") +
      $t("Bewahre diese Datei getrennt von deinem Passwort auf. Wer Schlüssel und zweiten Faktor hat, kann dein Tagebuch öffnen.\r\n");
    try { await P.saveFile(new Blob([text], { type: "text/plain;charset=utf-8" }), `kopfwetter-wiederherstellung-${me.username}.txt`); }
    catch (e) { msg("rk-msg2", $t("Die Datei ließ sich nicht speichern.")); }
  });
  $("rk-save").addEventListener("click", () => {
    const want = pendingRk.key.slice(-4), got = $("rk-verify").value.trim().toUpperCase();
    if (got !== want) return msg("rk-msg2", $t("Die letzten vier Zeichen stimmen nicht. Schau noch einmal auf deine Abschrift."));
    busy($("rk-save"), $t("Speichere …"), async () => {
      try {
        const keys = await api("GET", "/api/account/keys");
        const dek = await unwrapDek(pendingRk.k.kek, keys.wrappedKey);
        const rk = await deriveRecovery(parseRecoveryKey(pendingRk.key));
        const recoveryWrapped = await wrapDek(rk.kek, dek); dek.fill(0);
        const r = await api("POST", "/api/account/recovery", { authKey: pendingRk.k.authKey, code: pendingRk.code, recoveryAuth: rk.authKey, recoveryWrapped });
        recoveryInfo = { set: true, createdAt: r.createdAt };
        rkReset(); renderRecovery();
        msg("rk-msg", ""); setStatus($t("Wiederherstellungsschlüssel aktiviert. Bewahre ihn gut auf."));
      } catch (e) {
        msg("rk-msg2", e.status === 401 ? $t("Der Code aus der App war abgelaufen oder schon benutzt. Bitte starte noch einmal mit einem neuen Code.") : e.message);
        if (e.status === 401) { rkOpen(); msg("rk-msg", $t("Bitte gib Passwort und einen neuen Code ein. Der angezeigte Schlüssel war noch nicht aktiv.")); }
      }
    });
  });

  // ---------------------------------------------------------------- Verwaltung (Admins)
  const STATUS_LABEL = { pending: $t("wartet auf Freigabe"), active: "aktiv", disabled: "gesperrt" };
  const fmtDate = (s) => (s ? new Date(s).toLocaleDateString(LOC) : $t("nie"));
  async function loadAdmin() {
    $("admin-card").hidden = !(me && me.isAdmin);
    if (!me || !me.isAdmin) return;
    let users;
    try { users = await api("GET", "/api/admin/users"); } catch (e) { msg("admin-msg", e.message); return; }
    const pending = users.filter((u) => u.status === "pending").length;
    $("pending-badge").hidden = !pending; $("pending-badge").textContent = pending + " wartend";
    const list = $("users"); list.textContent = "";
    users.forEach((u) => {
      const li = document.createElement("li");
      const name = document.createElement("span"); name.className = "uname"; name.textContent = u.username + (u.isMe ? $t(" (du)") : "");
      const pill = document.createElement("span"); pill.className = "pill " + u.status; pill.textContent = STATUS_LABEL[u.status];
      li.append(name, pill);
      if (u.isAdmin) { const a = document.createElement("span"); a.className = "pill admin"; a.textContent = $t("Admin"); li.append(a); }
      const meta = document.createElement("span"); meta.className = "meta";
      meta.textContent = `angelegt ${fmtDate(u.createdAt)} · zuletzt angemeldet ${fmtDate(u.lastLogin)}`;
      li.append(meta);
      const acts = document.createElement("span"); acts.className = "acts";
      const add = (label, action, cls) => {
        const b = document.createElement("button"); b.type = "button"; b.className = "btn" + (cls ? " " + cls : ""); b.textContent = label;
        b.addEventListener("click", () => adminAction(u, action, b)); acts.append(b);
      };
      if (!u.isMe) {
        if (u.status === "pending") add($t("Freigeben"), "approve", "primary");
        if (u.status === "active") add($t("Sperren"), "disable");
        if (u.status === "disabled") add($t("Entsperren"), "enable");
        if (u.status === "active" && !u.isAdmin) add($t("Zum Admin machen"), "make-admin");
        if (u.isAdmin) add($t("Admin entziehen"), "remove-admin");
        add(u.status === "pending" ? $t("Ablehnen") : $t("Löschen"), "delete", "danger");
      }
      li.append(acts); list.append(li);
    });
  }
  const armed = new WeakSet();
  async function adminAction(u, action, btn) {
    if (action === "delete" && !armed.has(btn)) {   // Bestätigung im Knopf selbst
      armed.add(btn); btn.textContent = u.status === "pending" ? $t("Wirklich ablehnen?") : $t("Konto und Einträge löschen?"); return;
    }
    msg("admin-msg", "");
    try {
      await api("POST", "/api/admin/users/" + u.id, { action });
      const done = { approve: "freigegeben", enable: "entsperrt", disable: "gesperrt", "make-admin": $t("ist jetzt Admin"), "remove-admin": $t("ist kein Admin mehr"), delete: u.status === "pending" ? "abgelehnt" : $t("gelöscht") };
      msg("admin-msg", `${u.username} ${done[action]}.`);
    } catch (e) { msg("admin-msg", e.message); }
    loadAdmin();
  }

  // ---------------------------------------------------------------- Konto löschen
  $("del-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!$("d-sure").checked) return msg("del-msg", $t("Bitte bestätige das Löschen."));
    msg("del-msg", "");
    busy($("d-go"), $t("Lösche …"), async () => {
      try {
        const k = await deriveKeys($("d-pw").value, me.salt, me.kdf);
        await api("POST", "/api/account/delete", { authKey: k.authKey, code: $("d-code").value.trim() });
        ["d-pw", "d-code"].forEach((id) => { $(id).value = ""; }); $("d-sure").checked = false;
        $("l-user").value = "";
        await sessionLost($t("Dein Konto und alle Einträge wurden gelöscht."));
      } catch (e) { msg("del-msg", e.message); }
    });
  });

  // ================================================================ Tagebuch
  const ACTS = ["Bewegung", "Draußen", "Soziale Kontakte", "Arbeit", "Hobby", "Haushalt", "Ruhe & Erholung", "Therapie"];
  const MEDS = [["ja", $t("Eingenommen")], ["teilweise", $t("Teilweise")], ["nein", $t("Vergessen/Nein")], ["keine", $t("Keine geplant")]];
  const MEDLABEL = Object.fromEntries(MEDS);
  const pad = (n) => String(n).padStart(2, "0");
  const iso = (d) => d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
  const parse = (s) => { const [y, m, d] = s.split("-").map(Number); return new Date(y, m - 1, d); };
  const todayIso = () => iso(new Date());
  const fmtLong = new Intl.DateTimeFormat(LOC, { weekday: "long", day: "numeric", month: "long" });
  const fmtDay = new Intl.DateTimeFormat(LOC, { day: "numeric", month: "long" });
  const fmtShort = new Intl.DateTimeFormat(LOC, { weekday: "short", day: "2-digit", month: "2-digit" });
  // Tageswert für Grafik und Muster: Abend-Check-out, ohne Check-out der Morgen-Check-in (ab v2 gleiche Skala 1–10)
  function dv(e, k) {
    if (!e) return null;
    if (typeof e[k] === "number") return e[k];
    const a = e.am;
    return a && a.v === 2 && typeof a[k] === "number" ? a[k] : null;
  }
  const blank = () => ({ mood: null, anxiety: null, drive: null, activities: [], meds: null, note: "", intentDone: null });

  let entries = new Map();
  let current = todayIso();
  let form = blank();
  let saving = false;

  // ---------------------------------------------------------------- Einwilligung (neue Fassung)
  let readOnly = false;
  async function afterLogin() {
    if (me && me.consentCurrent === false) { show("consent"); setStatus(""); $("c-consent").checked = false; msg("consent-msg", ""); return; }
    readOnly = false;
    await enterApp();
  }
  $("consent-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!$("c-consent").checked) return msg("consent-msg", $t("Bitte setz das Häkchen, um zuzustimmen."));
    busy($("c-go"), $t("Speichere …"), async () => {
      try { await api("POST", "/api/account/consent", { consent: true }); me.consentCurrent = true; readOnly = false; await enterApp(); }
      catch (e) { msg("consent-msg", e.message); }
    });
  });
  $("c-readonly").addEventListener("click", () => { readOnly = true; enterApp(); });

  let assessments = new Map();
  async function enterApp() {
    show("app"); setStatus($t("Lade Einträge …"));
    try {
      const migrated = readOnly ? 0 : await migrateV1();
      const { total, bad } = await loadAll();
      if (total && bad === total) { await sessionLost($t("Die Einträge ließen sich mit diesem Schlüssel nicht entschlüsseln. Bitte melde dich neu an.")); return; }
      const keys = await api("GET", "/api/account/keys");
      recoveryInfo = keys.recovery; renderRecovery();
      setStatus(readOnly ? $t("Nur ansehen: Ohne Einwilligung werden keine neuen Daten gespeichert. Abmelden und neu anmelden, um zuzustimmen.")
        : bad ? $T`${bad} Datensätze ließen sich nicht entschlüsseln.`
        : migrated ? $T`${migrated} Datensätze auf das neue Format umgestellt. Ende-zu-Ende verschlüsselt.` : $t("Ende-zu-Ende verschlüsselt. Nur du kannst deine Einträge lesen."));
    } catch (e) { if (e.status !== 401) setStatus(e.message); return; }
    current = todayIso(); loadForm(); renderAll(); TESTS.forEach((t) => t.overview()); renderSess();
    loadAdmin(); focusAddonFromUrl();
  }

  // ---------------------------------------------------------------- Bedienelemente
  function buildSeg(id, key) {
    for (let i = 1; i <= 10; i++) {
      const b = document.createElement("button");
      b.type = "button"; b.textContent = i; b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", () => { form[key] = form[key] === i ? null : i; renderForm(); });
      $(id).appendChild(b);
    }
  }
  buildSeg("s-mood", "mood"); buildSeg("s-anx", "anxiety"); buildSeg("s-drive", "drive");
  ACTS.forEach((a) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.textContent = $t(a); b.dataset.act = a;
    b.addEventListener("click", () => {
      const s = new Set(form.activities); s.has(a) ? s.delete(a) : s.add(a);
      form.activities = ACTS.filter((x) => s.has(x)); renderForm();
    });
    $("acts").appendChild(b);
  });
  MEDS.forEach(([v, label]) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "medopt"; b.textContent = label; b.dataset.v = v;
    b.addEventListener("click", () => { form.meds = form.meds === v ? null : v; renderForm(); });
    $("meds").appendChild(b);
  });
  $("note").addEventListener("input", (e) => { form.note = e.target.value; });

  function loadPm() {
    const e = entries.get(current);
    form = e ? { mood: e.mood ?? null, anxiety: e.anxiety ?? null, drive: e.drive ?? null,
      activities: Array.isArray(e.activities) ? e.activities.slice() : [], meds: e.meds ?? null, note: e.note || "", intentDone: e.intentDone ?? null } : blank();
    $("note").value = form.note; msg("saveMsg", ""); $("delConfirm").hidden = true;
  }
  // Ein Tag besteht aus Morgen-Check-in, Gefühlen über den Tag und Abend-Check-out (alles im Tageseintrag bzw. als "feel"-Datensätze)
  function loadForm() {
    loadPm(); loadAm(); amOpen = false; pmOpen = false; closeFeel();
    renderForm();
  }
  function renderForm() {
    const t = todayIso(), d = parse(current);
    $("dayTitle").textContent = current === t ? $t("Heute, ") + fmtDay.format(d) : fmtLong.format(d);
    $("datePick").value = current; $("datePick").max = t;
    $("nextDay").disabled = current >= t;
    [["s-mood", "mood", "v-mood"], ["s-anx", "anxiety", "v-anx"], ["s-drive", "drive", "v-drive"]].forEach(([s, k, v]) => {
      [...$(s).children].forEach((b, i) => b.setAttribute("aria-pressed", String(form[k] === i + 1)));
      $(v).textContent = form[k] ? form[k] + " / 10" : $t("noch nicht gewählt");
    });
    [...$("acts").children].forEach((b) => b.setAttribute("aria-pressed", String(form.activities.includes(b.dataset.act))));
    [...$("meds").children].forEach((b) => b.setAttribute("aria-pressed", String(form.meds === b.dataset.v)));
    $("lowHint").hidden = !(form.mood && form.mood <= 2);
    const cur = entries.get(current);
    $("del").hidden = !hasPm(cur);
    $("save").disabled = saving || readOnly;
    $("save").textContent = hasPm(cur) ? $t("Änderungen speichern") : $t("Check-out speichern");
    const intent = cur && cur.am && cur.am.intent;
    $("intent-field").hidden = !intent; $("intent-text").textContent = intent ? "„" + intent + "“" : "";
    [...$("intent-done").children].forEach((b) => b.setAttribute("aria-pressed", String(form.intentDone === b.dataset.v)));
    if (encKey) { renderMeds(); renderDay(); } // Tabletten-Karte und Tagesansicht folgen dem gewählten Tag
  }
  function shift(days) {
    const d = parse(current); d.setDate(d.getDate() + days);
    const n = iso(d); if (n > todayIso()) return;
    current = n; loadForm();
  }
  $("prevDay").addEventListener("click", () => shift(-1));
  $("nextDay").addEventListener("click", () => shift(1));
  $("datePick").addEventListener("change", (e) => { if (e.target.value && e.target.value <= todayIso()) { current = e.target.value; loadForm(); } });

  $("save").addEventListener("click", async () => {
    if (form.mood == null && form.anxiety == null && form.drive == null && !form.note.trim() && !form.activities.length && !form.meds && !form.intentDone) {
      msg("saveMsg", $t("Wähle mindestens einen Wert oder schreib eine Notiz.")); return;
    }
    const date = current, prev = entries.get(date) || {};
    const data = { ...(prev.am ? { am: prev.am } : {}), mood: form.mood, anxiety: form.anxiety, drive: form.drive, activities: form.activities,
      meds: form.meds, note: form.note.trim(), intentDone: form.intentDone, pmAt: prev.pmAt || nowIfToday(date), updatedAt: new Date().toISOString() };
    saving = true; renderForm();
    try {
      await putRecord("entry", date, data);
      entries.set(date, { ...data, date }); pmOpen = false; renderAll(); msg("pm-done-msg", $t("Gespeichert."));
    } catch (e) { if (e.status !== 401) msg("saveMsg", $t("Speichern hat nicht geklappt: ") + e.message); }
    saving = false; renderForm();
  });
  $("del").addEventListener("click", () => { $("delConfirm").hidden = false; });
  $("delConfirm").addEventListener("click", async () => {
    try {
      const prev = entries.get(current);
      if (prev && prev.am) { const data = { am: prev.am, updatedAt: new Date().toISOString() }; await putRecord("entry", current, data); entries.set(current, { ...data, date: current }); }
      else { await delRecord("entry", current); entries.delete(current); }
      form = blank(); $("note").value = "";
      $("delConfirm").hidden = true; pmOpen = false; renderAll(); msg("pm-later-msg", $t("Gelöscht."));
    } catch (e) { if (e.status !== 401) msg("saveMsg", $t("Löschen hat nicht geklappt: ") + e.message); }
  });

  // ---------------------------------------------------------------- Diagramm
  function renderChart() {
    const box = $("chart"); box.textContent = "";
    const end = parse(todayIso()); const days = [];
    for (let i = 29; i >= 0; i--) { const d = new Date(end); d.setDate(d.getDate() - i); days.push(iso(d)); }
    if (!days.some((d) => entries.has(d))) {
      const p = document.createElement("p"); p.className = "empty";
      p.textContent = $t("Sobald du ein paar Tage eingetragen hast, siehst du hier deinen Verlauf."); box.append(p); return;
    }
    const NS = "http://www.w3.org/2000/svg";
    const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; return e; };
    const W = 640, H = 220, L = 28, R = 10, T = 12, B = 26;
    const x = (i) => L + (i * (W - L - R)) / 29, y = (v) => T + ((10 - v) * (H - T - B)) / 9;
    const svg = el("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": $t("Verlauf von Stimmung, Angst und Antrieb über 30 Tage") });
    [1, 5, 10].forEach((v) => {
      svg.append(el("line", { class: "grid", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
      svg.append(el("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, v));
    });
    [0, 7, 14, 21, 29].forEach((i) => {
      const d = parse(days[i]);
      svg.append(el("text", { x: x(i), y: H - 6, "text-anchor": i === 0 ? "start" : i === 29 ? "end" : "middle" }, `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`));
    });
    [["mood", "s-mood"], ["anxiety", "s-anx"], ["drive", "s-drive"]].forEach(([k, cls]) => {
      let seg = []; const segs = [];
      days.forEach((d, i) => {
        const v = dv(entries.get(d), k);
        if (v == null) { if (seg.length) segs.push(seg); seg = []; } else seg.push([x(i), y(v)]);
      });
      if (seg.length) segs.push(seg);
      segs.forEach((pts) => {
        if (pts.length > 1) svg.append(el("polyline", { class: cls, points: pts.map((p) => p.join(",")).join(" ") }));
        pts.forEach((p) => svg.append(el("circle", { class: cls, cx: p[0], cy: p[1], r: 3 })));
      });
    });
    box.append(svg);
  }

  // ---------------------------------------------------------------- Historie
  function renderHist() {
    const list = $("hist"); list.textContent = "";
    const keys = [...entries.keys()].sort().reverse();
    $("histEmpty").hidden = keys.length > 0;
    keys.slice(0, 60).forEach((k) => {
      const e = entries.get(k);
      const li = document.createElement("li"), b = document.createElement("button");
      b.type = "button";
      const d = document.createElement("span"); d.className = "hd"; d.textContent = fmtShort.format(parse(k));
      const v = document.createElement("span"); v.className = "hv";
      [[$t("Stimmung"), dv(e, "mood"), "k-mood"], [$t("Angst"), dv(e, "anxiety"), "k-anx"], [$t("Antrieb"), dv(e, "drive"), "k-drive"]].forEach(([l, val, cls]) => {
        const sp = document.createElement("span"); sp.className = cls; sp.append(l + " ");
        const bb = document.createElement("b"); bb.textContent = val ?? "–"; sp.append(bb); v.append(sp);
      });
      if (e.meds) { const m = document.createElement("span"); m.textContent = $t("Med.: ") + (MEDLABEL[e.meds] || e.meds); v.append(m); }
      const nf = addonOn("feel") ? feelsOn(k).length : 0; if (nf) { const m = document.createElement("span"); m.textContent = nf === 1 ? $t("1 Gefühl") : $T`${nf} Gefühle`; v.append(m); }
      const n = document.createElement("span"); n.className = "hn";
      n.textContent = [(e.activities || []).map((a) => $t(a)).join(", "), e.note].filter(Boolean).join(" · ") || " ";
      b.append(d, v, n);
      b.addEventListener("click", () => { current = k; setTab("today"); loadForm(); window.scrollTo({ top: 0, behavior: "smooth" }); });
      li.append(b); list.append(li);
    });
  }
  function renderAll() { if (encKey) applyAddons(); renderChart(); renderHist(); renderForm(); if (encKey) { renderPatterns(); renderProg(); renderCrisis(); renderAddons(); } }

  // ---------------------------------------------------------------- Sicherheitskopie
  function csv() {
    const esc = (v) => { const s = v == null ? "" : String(v); return /[";\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const rows = [[$t("Datum"), $t("Stimmung morgens"), $t("Angst morgens"), $t("Antrieb morgens"), $t("Vorhaben"), $t("Vorhaben geschafft"),
      $t("Stimmung"), $t("Angst"), $t("Antrieb"), $t("Aktivitäten"), $t("Medikamente"), $t("Notiz")]];
    [...entries.keys()].sort().forEach((k) => {
      const e = entries.get(k), am = e.am || {};
      rows.push([k, am.v === 2 ? am.mood : "", am.v === 2 ? am.anxiety : "", am.v === 2 ? am.drive : "", am.intent, INTENT_LABEL[e.intentDone] || "", e.mood, e.anxiety, e.drive, (e.activities || []).map((a) => $t(a)).join(", "), MEDLABEL[e.meds] || "", e.note]);
    });
    return "﻿" + rows.map((r) => r.map(esc).join(";")).join("\r\n");
  }
  $("export").addEventListener("click", async () => {
    try { await P.saveFile(new Blob([csv()], { type: "text/csv;charset=utf-8" }), "kopfwetter-" + todayIso() + ".csv"); }
    catch (e) { setStatus($t("Die Datei ließ sich nicht speichern: ") + (e.message || e)); }
  });

  // ---------------------------------------------------------------- Vollständiger Export / Import (JSON, unverschlüsselt)
  // Für den Umzug in ein neues Konto oder auf einen anderen Server. Beim Import wird alles mit dem Schlüssel
  // des angemeldeten Kontos neu verschlüsselt.
  const EXPORT_FORMAT = "kopfwetter-export";
  const ENTRY_DATE = /^\d{4}-\d{2}-\d{2}$/;
  const ASSESS_ID = /^[a-z0-9-]{8,40}$/;
  const ITEM_ID_RE = /^(med-[a-z0-9]{8,16}|(dose|feel|crisis)-\d{4}-\d{2}-\d{2}-[a-z0-9]{8,16}|sess-[a-z0-9]{8,16}|plan-crisis|prefs)$/;
  const strip = (o, k) => { const c = { ...o }; delete c[k]; return c; };
  function fullExport() {
    const by = (a, b) => (a < b ? -1 : 1);
    return {
      format: EXPORT_FORMAT, version: 1, exportedAt: new Date().toISOString(), username: me && me.username,
      entries: [...entries.keys()].sort(by).map((date) => ({ date, data: strip(entries.get(date), "date") })),
      assessments: [...assessments.keys()].sort(by).map((id) => ({ id, data: strip(assessments.get(id), "id") })),
      items: [...items.keys()].sort(by).map((id) => ({ id, data: strip(items.get(id), "id") })),
    };
  }
  $("export-json").addEventListener("click", async () => {
    try {
      const x = fullExport();
      await P.saveFile(new Blob([JSON.stringify(x, null, 2)], { type: "application/json" }), "kopfwetter-export-" + todayIso() + ".json");
      msg("io-msg", $T`Exportiert: ${x.entries.length} Einträge, ${x.assessments.length} Tests, ${x.items.length} weitere Datensätze.`);
    } catch (e) { msg("io-msg", $t("Die Datei ließ sich nicht speichern: ") + (e.message || e)); }
  });
  function parseExport(text) {
    let x; try { x = JSON.parse(text); } catch (e) { throw new Error($t("Die Datei ist kein gültiges JSON.")); }
    if (!x || x.format !== EXPORT_FORMAT || x.version !== 1) throw new Error($t("Das ist keine Kopfwetter-Exportdatei."));
    const ok = (list, test, key) => Array.isArray(list) && list.every((r) => r && test.test(r[key]) && r.data && typeof r.data === "object" && !Array.isArray(r.data));
    if (!ok(x.entries, ENTRY_DATE, "date") || !ok(x.assessments, ASSESS_ID, "id") || !ok(x.items, ITEM_ID_RE, "id"))
      throw new Error($t("Die Exportdatei ist beschädigt oder unvollständig."));
    return x;
  }
  async function importData(x, tick = () => {}) {
    const total = x.entries.length + x.assessments.length + x.items.length; let done = 0;
    for (const r of x.entries) { await putRecord("entry", r.date, r.data); tick(++done, total); }
    for (const r of x.assessments) { await putRecord("assess", r.id, r.data); tick(++done, total); }
    for (const r of x.items) { await putRecord("item", r.id, r.data); tick(++done, total); }
  }
  $("import-file").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0]; ev.target.value = "";
    if (!file) return;
    if (readOnly) { msg("io-msg", $t("Im Modus „Nur ansehen“ ist kein Import möglich.")); return; }
    const label = $("import-label");
    try {
      if (file.size > 50 * 1024 * 1024) throw new Error($t("Die Datei ist zu groß."));
      const x = parseExport(await file.text());
      label.classList.add("disabled");
      await importData(x, (done, total) => msg("io-msg", $T`Importiere … ${done} von ${total}`));
      await enterApp();
      msg("io-msg", $T`Importiert: ${x.entries.length} Einträge, ${x.assessments.length} Tests, ${x.items.length} weitere Datensätze. Lösche die Exportdatei jetzt, sie ist unverschlüsselt.`);
    } catch (e) {
      msg("io-msg", $t("Import abgebrochen: ") + (e.message || e) + $t(" Bereits importierte Datensätze bleiben erhalten; ein erneuter Import überschreibt sie."));
    } finally { label.classList.remove("disabled"); }
  });

  // ---------------------------------------------------------------- Bericht (PDF)
  let repRange = "30";
  const store = { get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* egal */ } } };
  $("rep-name").value = store.get("rep-name") || "";
  if (store.get("rep-notes") === "0") $("rep-notes").checked = false;
  [...$("rep-range").children].forEach((b) => b.addEventListener("click", () => {
    repRange = b.dataset.range;
    [...$("rep-range").children].forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    $("rep-custom").hidden = repRange !== "custom";
    if (repRange === "custom" && !$("rep-from").value) {
      const d = parse(todayIso()); d.setDate(d.getDate() - 29);
      $("rep-from").value = iso(d); $("rep-to").value = todayIso();
    }
  }));
  function reportRange() {
    const t = todayIso();
    if (repRange === "custom") return [$("rep-from").value, $("rep-to").value];
    if (repRange === "all") return [[...entries.keys()].sort()[0] || t, t];
    const d = parse(t); d.setDate(d.getDate() - (Number(repRange) - 1));
    return [iso(d), t];
  }
  const loaded = {};
  function loadScript(src) {
    return loaded[src] || (loaded[src] = new Promise((res, rej) => {
      const s = document.createElement("script"); s.src = src; s.onload = res;
      s.onerror = () => { delete loaded[src]; rej(new Error($t("Das PDF-Modul konnte nicht geladen werden."))); };
      document.head.append(s);
    }));
  }
  $("rep-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const [from, to] = reportRange();
    if (!from || !to || from > to) return msg("rep-msg", $t("Bitte wähle einen gültigen Zeitraum."));
    store.set("rep-name", $("rep-name").value.trim()); store.set("rep-notes", $("rep-notes").checked ? "1" : "0");
    msg("rep-msg", "");
    busy($("rep-go"), $t("Erstelle PDF …"), async () => {
      try {
        await loadScript(withV("/static/vendor/jspdf.umd.min.js"));
        await loadScript(withV("/static/report.js"));
        const { blob, filename } = window.KopfwetterReport.build({ entries, assessments: addonOn("tests") ? [...assessments.values()] : [],
          items: [...items.values()].filter((i) => (i.kind !== "feel" || addonOn("feel")) && ((i.kind !== "dose" && i.kind !== "med") || addonOn("meds"))),
          sessNotes: $("rep-sess").checked ? sessAll().filter((n) => !n.done).sort((a, b) => a.created.localeCompare(b.created)) : [], from, to: to > todayIso() ? todayIso() : to, name: $("rep-name").value.trim(), withNotes: $("rep-notes").checked });
        await P.saveFile(blob, filename);
        msg("rep-msg", "PDF erstellt.");
      } catch (e) { msg("rep-msg", e.message || $t("Das PDF ließ sich nicht erstellen.")); }
    });
  });

  // ---------------------------------------------------------------- Passwort ändern
  $("pw-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const oldPw = $("p-old").value, nw = $("p-new").value, nw2 = $("p-new2").value, code = $("p-code").value.trim();
    if (nw.length < 12) return msg("pw-msg", $t("Das neue Passwort braucht mindestens 12 Zeichen."));
    if (nw !== nw2) return msg("pw-msg", $t("Die neuen Passwörter stimmen nicht überein."));
    msg("pw-msg", "");
    busy($("p-go"), $t("Ändere Passwort …"), async () => {
      try {
        const oldK = await deriveKeys(oldPw, me.salt, me.kdf), newK = await deriveKeys(nw, me.salt, authState.kdf);
        const keys = await api("GET", "/api/account/keys");
        let dek;
        try { dek = await unwrapDek(oldK.kek, keys.wrappedKey); } catch (e) { throw new Error($t("Das aktuelle Passwort stimmt nicht.")); }
        const wrappedKey = await wrapDek(newK.kek, dek); dek.fill(0);
        await api("POST", "/api/auth/change-password", { oldAuthKey: oldK.authKey, newAuthKey: newK.authKey, code, wrappedKey });
        me.kdf = authState.kdf; await persistKeys();
        ["p-old", "p-new", "p-new2", "p-code"].forEach((id) => { $(id).value = ""; });
        msg("pw-msg", $t("Passwort geändert. Deine Einträge bleiben unverändert, ein Wiederherstellungsschlüssel bleibt gültig. Andere Geräte wurden abgemeldet."));
      } catch (e) { msg("pw-msg", e.message || $t("Das hat nicht geklappt.")); }
    });
  });

  // ================================================================ Tabletten: Medikamente und Einnahmen mit Uhrzeit
  // Verschlüsselt wie alles andere; die ID ist als AAD gebunden ("item:<id>").
  let items = new Map();
  const rnd = () => [...crypto.getRandomValues(new Uint8Array(5))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const nowHM = () => { const d = new Date(); return pad(d.getHours()) + ":" + pad(d.getMinutes()); };
  const medsAll = () => [...items.values()].filter((i) => i.kind === "med").sort((a, b) => a.name.localeCompare(b.name, "de"));
  const medsActive = () => medsAll().filter((m) => !m.archived);
  const dosesOn = (day) => [...items.values()].filter((i) => i.kind === "dose" && i.date === day).sort((a, b) => a.time.localeCompare(b.time));
  const medLabel = (m) => m.name + (m.dose ? " " + m.dose : "");
  function parseTimes(str) {
    const out = [];
    for (const t of String(str || "").split(/[,;\s]+/).filter(Boolean)) {
      const m = t.match(/^(\d{1,2})(?:[:.](\d{2}))?$/);
      if (!m || +m[1] > 23 || +(m[2] || 0) > 59) return null;
      out.push(pad(+m[1]) + ":" + (m[2] || "00"));
    }
    return [...new Set(out)].sort();
  }
  async function putItem(obj) {
    const { id, ...data } = obj;
    await putRecord("item", id, data);
    items.set(id, obj);
  }
  async function dropItem(id) { await delRecord("item", id); items.delete(id); }

  // Geplante Zeiten der Reihe nach mit den Einnahmen des Tages abgleichen
  function slotsFor(med, day) {
    const taken = dosesOn(day).filter((d) => d.medId === med.id);
    return (med.times || []).map((t, i) => ({ planned: t, dose: taken[i] || null }));
  }

  function renderMeds() {
    const today = todayIso(), isToday = current === today;
    $("med-day").textContent = isToday ? $t("Heute") : fmtLong.format(parse(current));
    const active = medsActive();
    $("med-empty").hidden = active.length > 0 || readOnly;
    $("med-actions").hidden = readOnly || !active.length;
    $("med-form").hidden = readOnly;
    const plan = $("med-plan"); plan.textContent = "";
    active.forEach((m) => {
      const row = el("div", "medrow");
      const info = el("div", "minfo");
      info.append(el("span", "mname", m.name));
      if (m.dose) info.append(el("span", "mdose", m.dose));
      if (!(m.times && m.times.length)) info.append(el("span", "small", $t("bei Bedarf")));
      row.append(info);
      if (!readOnly) {
        const take = el("button", "btn primary take", isToday ? $t("Jetzt eingenommen") : $t("Einnahme eintragen")); take.type = "button";
        take.addEventListener("click", () => quickTake(m, take));
        row.append(take);
      }
      const slots = slotsFor(m, current);
      if (slots.length) {
        const wrap = el("div", "slots");
        slots.forEach(({ planned, dose }) => {
          let cls = "slot open", text = planned + " · " + (current > today ? "geplant" : "offen");
          if (dose) { cls = "slot done"; text = `${planned} · ✓ ${dose.time}`; }
          else if (isToday && planned < nowHM()) { cls = "slot late"; text = planned + $t(" · noch offen"); }
          else if (current < today) text = planned + $t(" · nicht eingetragen");
          wrap.append(el("span", cls, text));
        });
        row.append(wrap);
      }
      plan.append(row);
    });
    const ul = $("intakes"); ul.textContent = "";
    const list = dosesOn(current);
    $("intakes-empty").hidden = list.length > 0 || !active.length;
    list.forEach((d) => {
      const li = el("li"); const b = el("button"); b.type = "button";
      b.append(el("span", "t", d.time), el("span", "n", d.name + (d.dose ? " · " + d.dose : "")));
      if (d.note) b.append(el("span", "x", d.note));
      b.addEventListener("click", () => { if (!readOnly) openIntakeForm(d); });
      li.append(b); ul.append(li);
    });
    renderMedList();
  }

  async function quickTake(m, btn) {
    if (current !== todayIso()) {                // für vergangene Tage: Uhrzeit nachfragen
      const open = slotsFor(m, current).find((s) => !s.dose);
      return openIntakeForm(null, m, open ? open.planned : "08:00");
    }
    const time = nowHM();
    const d = { kind: "dose", id: `dose-${current}-${rnd()}`, medId: m.id, name: m.name, dose: m.dose || "", date: current, time, note: "", at: new Date().toISOString() };
    btn.disabled = true;
    try { await putItem(d); msg("med-msg", $T`${medLabel(m)} um ${time} Uhr eingetragen. Zum Ändern in der Liste antippen.`); }
    catch (e) { msg("med-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    btn.disabled = false; renderMeds();
  }

  let editingDose = null;
  function fillMedSelect(selectedId) {
    const sel = $("i-med"); sel.textContent = "";
    const list = medsAll().filter((m) => !m.archived || m.id === selectedId);
    list.forEach((m) => { const o = document.createElement("option"); o.value = m.id; o.textContent = medLabel(m) + (m.archived ? " (archiviert)" : ""); sel.append(o); });
    if (selectedId) sel.value = selectedId;
  }
  function openIntakeForm(dose, med, time) {
    editingDose = dose;
    fillMedSelect(dose ? dose.medId : med ? med.id : (medsActive()[0] || {}).id);
    const m = items.get($("i-med").value);
    $("i-time").value = dose ? dose.time : time || nowHM();
    $("i-date").value = dose ? dose.date : current; $("i-date").max = todayIso();
    $("i-dose").value = dose ? dose.dose : (m && m.dose) || "";
    $("i-note").value = dose ? dose.note || "" : "";
    $("intake-title").textContent = dose ? $t("Einnahme bearbeiten") : $t("Einnahme eintragen");
    $("i-delete").hidden = !dose; delete $("i-delete").dataset.armed; $("i-delete").textContent = $t("Löschen");
    msg("intake-msg", ""); $("intake-form").hidden = false; $("med-actions").hidden = true;
    $("intake-form").scrollIntoView({ behavior: "smooth", block: "nearest" }); $("i-time").focus();
  }
  function closeIntakeForm() { editingDose = null; $("intake-form").hidden = true; renderMeds(); }
  $("i-med").addEventListener("change", () => { const m = items.get($("i-med").value); if (m && !editingDose) $("i-dose").value = m.dose || ""; });
  $("intake-other").addEventListener("click", () => openIntakeForm(null, null, nowHM()));
  $("i-cancel").addEventListener("click", closeIntakeForm);
  $("intake-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const m = items.get($("i-med").value), date = $("i-date").value, time = $("i-time").value;
    if (!m) return msg("intake-msg", $t("Lege zuerst unter „Medikamente verwalten“ ein Medikament an."));
    if (!date || date > todayIso()) return msg("intake-msg", $t("Bitte ein Datum bis heute wählen."));
    if (!/^\d{2}:\d{2}$/.test(time)) return msg("intake-msg", $t("Bitte eine Uhrzeit angeben."));
    busy($("i-save"), $t("Speichere …"), async () => {
      try {
        const keepId = editingDose && editingDose.date === date;        // das Datum steckt in der ID
        const d = { kind: "dose", id: keepId ? editingDose.id : `dose-${date}-${rnd()}`, medId: m.id, name: m.name,
          dose: $("i-dose").value.trim(), date, time, note: $("i-note").value.trim(), at: editingDose ? editingDose.at : new Date().toISOString() };
        await putItem(d);
        if (editingDose && !keepId) await dropItem(editingDose.id);
        msg("med-msg", $T`${d.name} am ${deDate(date)} um ${time} Uhr gespeichert.`);
        if (date !== current) { current = date; loadForm(); }
        closeIntakeForm();
      } catch (e) { msg("intake-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });
  $("i-delete").addEventListener("click", async () => {
    const b = $("i-delete");
    if (!b.dataset.armed) { b.dataset.armed = "1"; b.textContent = $t("Wirklich löschen?"); return; }
    try { await dropItem(editingDose.id); msg("med-msg", $t("Einnahme gelöscht.")); closeIntakeForm(); }
    catch (e) { msg("intake-msg", e.message); }
  });

  // ---------------------------------------------------------------- Medikamente verwalten
  let editingMed = null;
  function renderMedList() {
    const ul = $("medlist"); ul.textContent = "";
    medsAll().sort((a, b) => (a.archived - b.archived) || a.name.localeCompare(b.name, "de")).forEach((m) => {
      const li = el("li", m.archived ? "archived" : "");
      li.append(el("span", "mname", medLabel(m)), el("span", "mtimes", m.times && m.times.length ? "geplant " + m.times.join(", ") : $t("bei Bedarf")));
      if (!readOnly) {
        const add = (label, fn, cls) => { const b = el("button", "btn" + (cls ? " " + cls : ""), label); b.type = "button"; b.addEventListener("click", () => fn(b)); li.append(b); };
        if (!m.archived) add($t("Bearbeiten"), () => editMed(m));
        add(m.archived ? $t("Wieder aktivieren") : $t("Archivieren"), async () => {
          try { await putItem({ ...m, archived: !m.archived, archivedAt: m.archived ? null : todayIso() }); renderMeds(); } catch (e) { msg("med-form-msg", e.message); }
        });
        add($t("Löschen"), async (b) => {
          if (!b.dataset.armed) { b.dataset.armed = "1"; b.textContent = $t("Löschen? Einnahmen bleiben erhalten"); return; }
          try { await dropItem(m.id); renderMeds(); msg("med-form-msg", $T`${m.name} gelöscht.`); } catch (e) { msg("med-form-msg", e.message); }
        }, "danger");
      }
      ul.append(li);
    });
  }
  function editMed(m) {
    editingMed = m;
    $("m-name").value = m.name; $("m-dose").value = m.dose || ""; $("m-times").value = (m.times || []).join(", ");
    $("med-form-title").textContent = $t("Medikament bearbeiten"); $("m-save").textContent = $t("Speichern"); $("m-cancel").hidden = false;
    $("m-name").focus();
  }
  function resetMedForm() {
    editingMed = null; $("med-form").reset();
    $("med-form-title").textContent = $t("Medikament hinzufügen"); $("m-save").textContent = $t("Hinzufügen"); $("m-cancel").hidden = true;
  }
  $("m-cancel").addEventListener("click", resetMedForm);
  $("med-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const name = $("m-name").value.trim(), dose = $("m-dose").value.trim(), times = parseTimes($("m-times").value);
    if (!name) return msg("med-form-msg", $t("Bitte einen Namen eingeben."));
    if (times === null) return msg("med-form-msg", $t("Uhrzeiten bitte als HH:MM angeben, z. B. 08:00, 20:00."));
    busy($("m-save"), $t("Speichere …"), async () => {
      try {
        const m = editingMed ? { ...editingMed, name, dose, times } : { kind: "med", id: "med-" + rnd(), name, dose, times, archived: false, created: todayIso() };
        await putItem(m);
        msg("med-form-msg", editingMed ? `${name} gespeichert.` : $T`${name} hinzugefügt.`);
        resetMedForm(); renderMeds();
      } catch (e) { msg("med-form-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });
  // Ohne Medikamente die Verwaltung gleich aufklappen
  $("med-empty").addEventListener("click", () => { $("med-manage").open = true; });

  function medsCsv() {
    const esc = (v) => { const x = v == null ? "" : String(v); return /[";\n\r]/.test(x) ? '"' + x.replace(/"/g, '""') + '"' : x; };
    const rows = [[$t("Datum"), $t("Uhrzeit"), $t("Medikament"), $t("Dosis"), $t("Notiz")]];
    [...items.values()].filter((i) => i.kind === "dose").sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time))
      .forEach((d) => rows.push([d.date, d.time, d.name, d.dose, d.note]));
    return "\ufeff" + rows.map((r) => r.map(esc).join(";")).join("\r\n");
  }
  $("export-meds").addEventListener("click", async () => {
    try { await P.saveFile(new Blob([medsCsv()], { type: "text/csv;charset=utf-8" }), "einnahmen-" + todayIso() + ".csv"); }
    catch (e) { setStatus($t("Die Datei ließ sich nicht speichern: ") + (e.message || e)); }
  });

  // ================================================================ Krisenplan (nach dem Vorbild des Safety Plans von Stanley & Brown)
  const PLAN_ID = "plan-crisis";
  const PLAN_FIXED = [
    { name: $t("Telefonseelsorge"), phone: "0800 111 0 111", note: $t("rund um die Uhr, kostenlos, anonym") },
    { name: $t("Telefonseelsorge"), phone: "0800 111 0 222", note: $t("rund um die Uhr, kostenlos, anonym") },
    { name: $t("Ärztlicher Bereitschaftsdienst"), phone: "116 117", note: "" },
    { name: $t("Notruf"), phone: "112", note: $t("in akuter Gefahr") },
  ];
  const PLAN_SECTIONS = [
    { k: "warn", t: $t("Meine Warnzeichen"), type: "list", h: $t("Gedanken, Gefühle, Situationen oder Verhaltensweisen, an denen ich merke, dass eine Krise beginnt.") },
    { k: "self", t: $t("Was ich selbst tun kann"), type: "list", h: $t("Dinge, die mich beruhigen oder ablenken, ganz ohne andere Menschen. Zum Beispiel Musik, kalt duschen, rausgehen, eine Atemübung.") },
    { k: "places", t: $t("Menschen und Orte, die mich ablenken"), type: "list", h: $t("Wo oder mit wem ich auf andere Gedanken komme, auch ohne über die Krise zu sprechen.") },
    { k: "people", t: $t("Menschen, die ich um Hilfe bitten kann"), type: "contacts", h: $t("Freundinnen, Freunde, Familie, mit Telefonnummer.") },
    { k: "pros", t: $t("Fachliche Hilfe"), type: "contacts", fixed: true, h: $t("Meine Therapeutin oder mein Therapeut, die Hausarztpraxis, die nächste psychiatrische Klinik oder Notaufnahme.") },
    { k: "safe", t: $t("Meine Umgebung sicherer machen"), type: "list", h: $t("Was ich tun kann, damit Dinge, mit denen ich mir schaden könnte, nicht griffbereit sind, zum Beispiel jemandem geben oder wegschließen.") },
    { k: "reasons", t: $t("Was mir wichtig ist"), type: "list", h: $t("Menschen, Tiere, Pläne und Dinge, die mich halten.") },
  ];
  const telHref = (p) => "tel:" + String(p).replace(/[^\d+]/g, "");
  const getPlan = () => items.get(PLAN_ID) || null;

  function contactLi(c) {
    const li = el("li"); li.append(el("span", "cn", c.name || $t("Kontakt")));
    if (c.phone) { const a = el("a", "tel", c.phone); a.href = telHref(c.phone); li.append(a); }
    if (c.note) li.append(el("span", "cnote", c.note));
    return li;
  }
  function renderPlan() {
    const plan = getPlan();
    $("plan-empty").hidden = !!plan || readOnly;
    $("plan-view").hidden = !plan; $("plan-form").hidden = true;
    $("plan-actions").hidden = !plan; $("plan-edit").hidden = readOnly;
    const v = $("plan-view"); v.textContent = "";
    if (!plan) {
      if (readOnly) { v.hidden = false; v.append(el("p", "small", $t("Noch kein Krisenplan angelegt."))); }
      return;
    }
    PLAN_SECTIONS.forEach((sec, i) => {
      const box = el("section", "plan-sec"); const h = el("h3"); h.append(el("span", "n", String(i + 1)), sec.t); box.append(h);
      if (sec.type === "list") {
        const list = (plan[sec.k] || []).filter(Boolean);
        if (list.length) { const ul = el("ul"); list.forEach((x) => ul.append(el("li", null, x))); box.append(ul); }
        else box.append(el("p", "none", $t("noch leer")));
      } else {
        const ul = el("ul", "contacts");
        (plan[sec.k] || []).filter((c) => c.name || c.phone).forEach((c) => ul.append(contactLi(c)));
        if (sec.fixed) PLAN_FIXED.forEach((c) => ul.append(contactLi(c)));
        if (!ul.children.length) box.append(el("p", "none", $t("noch leer"))); else box.append(ul);
      }
      v.append(box);
    });
    v.append(el("p", "small", $t("Zuletzt geändert am ") + new Date(plan.updated).toLocaleDateString(LOC) + "."));
  }
  function contactRow(c, container) {
    const row = el("div", "crow");
    const n = document.createElement("input"); n.type = "text"; n.placeholder = $t("Name"); n.maxLength = 60; n.value = c.name || ""; n.setAttribute("aria-label", $t("Name"));
    const t = document.createElement("input"); t.type = "tel"; t.placeholder = $t("Telefon"); t.maxLength = 30; t.value = c.phone || ""; t.setAttribute("aria-label", $t("Telefonnummer"));
    const x = el("button", "btn", $t("Entfernen")); x.type = "button"; x.addEventListener("click", () => row.remove());
    row.dataset.note = c.note || "";
    row.append(n, t, x); container.append(row);
  }
  function openPlanForm() {
    const plan = getPlan() || {};
    const f = $("plan-form"); f.textContent = "";
    PLAN_SECTIONS.forEach((sec, i) => {
      const fs = el("fieldset", "plan-form-sec"); fs.dataset.k = sec.k; fs.dataset.type = sec.type;
      fs.append(el("legend", null, `${i + 1}. ${sec.t}`), el("p", "small hint", sec.h));
      if (sec.type === "list") {
        const ta = document.createElement("textarea"); ta.maxLength = 2000; ta.placeholder = $t("Ein Punkt pro Zeile");
        ta.setAttribute("aria-label", sec.t); ta.value = (plan[sec.k] || []).join("\n"); fs.append(ta);
      } else {
        const rows = el("div", "stack"); rows.style.gap = "6px";
        const list = plan[sec.k] && plan[sec.k].length ? plan[sec.k] : [{}];
        list.forEach((c) => contactRow(c, rows)); fs.append(rows);
        const add = el("button", "btn", $t("Kontakt hinzufügen")); add.type = "button";
        add.addEventListener("click", () => { if (rows.children.length < 10) contactRow({}, rows); rows.lastChild.querySelector("input").focus(); });
        fs.append(add);
        if (sec.fixed) fs.append(el("p", "small", $t("Telefonseelsorge, 116 117 und 112 stehen immer automatisch im Plan.")));
      }
      f.append(fs);
    });
    const act = el("div", "actions");
    const save = el("button", "btn primary", $t("Speichern")); save.type = "submit"; save.id = "plan-save";
    const cancel = el("button", "btn", $t("Abbrechen")); cancel.type = "button"; cancel.addEventListener("click", renderPlan);
    const m = el("span", "msg"); m.id = "plan-form-msg"; m.setAttribute("role", "status");
    act.append(save, cancel, m); f.append(act);
    $("plan-empty").hidden = true; $("plan-view").hidden = true; $("plan-actions").hidden = true; f.hidden = false;
    f.querySelector("textarea").focus();
  }
  $("plan-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const plan = { kind: "plan", v: 1, updated: new Date().toISOString() };
    $("plan-form").querySelectorAll("fieldset").forEach((fs) => {
      if (fs.dataset.type === "list") plan[fs.dataset.k] = fs.querySelector("textarea").value.split("\n").map((x) => x.trim()).filter(Boolean).slice(0, 30);
      else plan[fs.dataset.k] = [...fs.querySelectorAll(".crow")].map((r) => {
        const [n, t] = r.querySelectorAll("input"); return { name: n.value.trim(), phone: t.value.trim(), note: r.dataset.note || "" };
      }).filter((c) => c.name || c.phone);
    });
    busy($("plan-save"), $t("Speichere …"), async () => {
      try { await putItem({ ...plan, id: PLAN_ID }); renderPlan(); msg("plan-msg", $t("Krisenplan gespeichert.")); }
      catch (e) { msg("plan-form-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });
  function showPlan() {
    $("plan-card").hidden = false; renderPlan(); msg("plan-msg", "");
    $("plan-card").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  $("open-plan").addEventListener("click", showPlan);
  $("plan-close").addEventListener("click", () => { $("plan-card").hidden = true; });
  $("plan-start").addEventListener("click", openPlanForm);
  $("plan-edit").addEventListener("click", openPlanForm);
  $("plan-pdf").addEventListener("click", () => busy($("plan-pdf"), $t("Erstelle PDF …"), async () => {
    try {
      await loadScript(withV("/static/vendor/jspdf.umd.min.js")); await loadScript(withV("/static/report.js"));
      const { blob, filename } = window.KopfwetterReport.crisisPlan({ plan: getPlan(), sections: PLAN_SECTIONS, fixed: PLAN_FIXED, name: $("rep-name").value.trim() });
      await P.saveFile(blob, filename); msg("plan-msg", $t("PDF erstellt. Ausgedruckt hilft der Plan auch, wenn das Handy aus ist."));
    } catch (e) { msg("plan-msg", e.message || $t("Das PDF ließ sich nicht erstellen.")); }
  }));

  // ================================================================ Depressions-Selbsttest (PHQ-9)
  // Fragebögen im Wortlaut der deutschen Fassungen. PHQ-9: PHQ-D (Löwe et al.), Auswertung nach Kroenke et al. (2001).
  // GAD-7: deutsche Fassung von Löwe et al. (2008), Auswertung nach Spitzer et al. (2006).
  const FREQ_OPTS = [$t("Überhaupt nicht"), $t("An einzelnen Tagen"), $t("An mehr als der Hälfte der Tage"), $t("Beinahe jeden Tag")];
  const DIFF_OPTS = [$t("Überhaupt nicht erschwert"), $t("Etwas erschwert"), $t("Relativ stark erschwert"), $t("Sehr stark erschwert")];
  const TEST_DEFS = {
    phq: {
      type: "phq9", aad: "phq9", idPrefix: "", name: "PHQ-9", max: 27, bands: [4, 9, 14, 19], safetyItem: 8,
      items: [
        $t("Wenig Interesse oder Freude an Ihren Tätigkeiten"),
        $t("Niedergeschlagenheit, Schwermut oder Hoffnungslosigkeit"),
        $t("Schwierigkeiten, ein- oder durchzuschlafen, oder vermehrter Schlaf"),
        $t("Müdigkeit oder Gefühl, keine Energie zu haben"),
        $t("Verminderter Appetit oder übermäßiges Bedürfnis zu essen"),
        $t("Schlechte Meinung von sich selbst; Gefühl, ein Versager zu sein oder die Familie enttäuscht zu haben"),
        $t("Schwierigkeiten, sich auf etwas zu konzentrieren, z. B. beim Zeitunglesen oder Fernsehen"),
        $t("Waren Ihre Bewegungen oder Ihre Sprache so verlangsamt, dass es auch anderen auffallen würde? Oder waren Sie im Gegenteil „zappelig“ oder ruhelos und hatten dadurch einen stärkeren Bewegungsdrang als sonst?"),
        $t("Gedanken, dass Sie lieber tot wären oder sich Leid zufügen möchten"),
      ],
      sev: [$t("minimal"), $t("mild"), $t("mittelgradig"), $t("ausgeprägt"), $t("schwer")],
      sevText: [
        $t("Deine Antworten sprechen für keine oder nur minimale depressive Beschwerden in den letzten zwei Wochen."),
        $t("Deine Antworten sprechen für leichte depressive Beschwerden. Beobachte den Verlauf weiter und sprich das Ergebnis beim nächsten Termin an."),
        $t("Deine Antworten sprechen für mittelgradige depressive Beschwerden. Ab einem Wert von 10 empfehlen Fachleute, das Ergebnis ärztlich oder psychotherapeutisch zu besprechen."),
        $t("Deine Antworten sprechen für ausgeprägte depressive Beschwerden. Bitte sprich zeitnah mit deiner Ärztin, deinem Arzt oder in der Therapie darüber."),
        $t("Deine Antworten sprechen für schwere depressive Beschwerden. Bitte nimm möglichst bald Kontakt zu deiner Ärztin, deinem Arzt oder deiner Therapeutin bzw. deinem Therapeuten auf."),
      ],
      sevCls: [0, 1, 2, 3, 4],
    },
    gad: {
      type: "gad7", aad: "gad7", idPrefix: "gad7-", name: "GAD-7", max: 21, bands: [4, 9, 14], safetyItem: null,
      items: [
        $t("Nervosität, Ängstlichkeit oder Anspannung"),
        $t("Nicht in der Lage sein, Sorgen zu stoppen oder zu kontrollieren"),
        $t("Übermäßige Sorgen bezüglich verschiedener Angelegenheiten"),
        $t("Schwierigkeiten zu entspannen"),
        $t("Rastlosigkeit, so dass Stillsitzen schwer fällt"),
        $t("Schnelle Verärgerung oder Gereiztheit"),
        $t("Gefühl der Angst, so als würde etwas Schlimmes passieren"),
      ],
      sev: [$t("minimal"), $t("leicht"), $t("mäßig"), $t("schwer")],
      sevText: [
        $t("Deine Antworten sprechen für keine oder nur minimale Ängste in den letzten zwei Wochen."),
        $t("Deine Antworten sprechen für leichte Ängste. Beobachte den Verlauf weiter und sprich das Ergebnis beim nächsten Termin an."),
        $t("Deine Antworten sprechen für mäßige Ängste. Ab einem Wert von 10 empfehlen Fachleute, das Ergebnis ärztlich oder psychotherapeutisch zu besprechen."),
        $t("Deine Antworten sprechen für schwere Ängste. Bitte sprich zeitnah mit deiner Ärztin, deinem Arzt oder in der Therapie darüber."),
      ],
      sevCls: [0, 1, 2, 4],
    },
  };
  const deDate = (s) => { const d = parse(s); return LOC === "de-DE" ? `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()}` : `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`; };
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  function buildOpts(container, name, labels) {
    labels.forEach((label, v) => {
      const l = el("label"); const i = document.createElement("input");
      i.type = "radio"; i.name = name; i.value = String(v);
      l.append(i, document.createTextNode(label)); container.append(l);
    });
  }

  function safetyBox() {
    const box = el("div", "safety"); box.setAttribute("role", "alert");
    box.append(el("h3", null, $t("Du musst damit nicht allein bleiben")));
    box.append(el("p", null, $t("Du hast angegeben, dass du Gedanken hattest, lieber tot zu sein oder dir etwas anzutun. Das ist wichtig. Bitte sprich zeitnah mit deiner Therapeutin, deinem Therapeuten oder deiner Ärztin, deinem Arzt darüber.")));
    const p = el("p"); p.append($t("Telefonseelsorge, rund um die Uhr, kostenlos und anonym: "));
    const a1 = el("a", null, "0800 111 0 111"); a1.href = "tel:08001110111";
    const a2 = el("a", null, "0800 111 0 222"); a2.href = "tel:08001110222";
    p.append(a1, $t(" oder "), a2, $t(". Chat und Mail unter online.telefonseelsorge.de."));
    box.append(p);
    const p2 = el("p"); p2.append($t("Ärztlicher Bereitschaftsdienst: "));
    const a3 = el("a", null, "116 117"); a3.href = "tel:116117"; p2.append(a3, $t(". In akuter Gefahr: "));
    const a4 = el("a", null, "112"); a4.href = "tel:112"; p2.append(a4, $t(" oder die nächste psychiatrische Notaufnahme."));
    box.append(p2);
    const pb = el("button", "btn", getPlan() ? $t("Meinen Krisenplan öffnen") : $t("Krisenplan erstellen")); pb.type = "button";
    pb.addEventListener("click", () => { showPlan(); if (!getPlan()) openPlanForm(); });
    box.append(pb);
    return box;
  }

  function makeTest(key) {
    const D = TEST_DEFS[key], $$ = (id) => $(key + "-" + id);
    const sevOf = (score) => { const i = D.bands.findIndex((b) => score <= b); return i < 0 ? D.bands.length : i; };
    const sorted = () => [...assessments.values()].filter((a) => a.type === D.type).sort((a, b) => (a.at || a.date).localeCompare(b.at || b.date));
    D.items.forEach((q, i) => {
      const li = el("li", "phq-q"); li.dataset.q = i; li.setAttribute("role", "radiogroup");
      const t = el("div", "qtext", q); t.id = `${key}-q${i}`; li.setAttribute("aria-labelledby", t.id);
      const opts = el("div", "phq-opts"); buildOpts(opts, "q" + i, FREQ_OPTS);
      li.append(t, opts); $$("items").append(li);
    });
    buildOpts($$("diff"), "diff", DIFF_OPTS);
    $$("items").addEventListener("change", (e) => { const li = e.target.closest(".phq-q"); if (li) li.classList.remove("missing"); });

    function overview() {
      $$("overview").hidden = false; $$("form").hidden = true; $$("result").hidden = true;
      $$("start").disabled = readOnly;
      msg(key + "-msg", readOnly ? $t("Im Modus „Nur ansehen“ gesperrt. Melde dich neu an und stimm der Einwilligung zu.") : "");
      const list = sorted(), last = list[list.length - 1];
      if (last) {
        const next = parse(last.date); next.setDate(next.getDate() + 14);
        $$("due").textContent = iso(next) <= todayIso() ? $t("Wieder fällig") : $t("Nächster Test ab ") + deDate(iso(next));
      } else $$("due").textContent = "";
      chart(list); renderProg();
      const ul = $$("list"); ul.textContent = "";
      [...list].reverse().slice(0, 12).forEach((a) => {
        const li = el("li"), sv = sevOf(a.score);
        li.append(el("span", "d", deDate(a.date)), el("span", "s", `${a.score} / ${D.max}`), el("span", "sev sev-" + D.sevCls[sv], D.sev[sv]));
        if (D.safetyItem != null && a.answers && a.answers[D.safetyItem] > 0) li.append(el("span", "flag", $T`Frage ${D.safetyItem + 1}: ${a.answers[D.safetyItem]}`));
        const del = el("button", "btn", $t("Löschen")); del.type = "button";
        del.addEventListener("click", async () => {
          if (!del.dataset.armed) { del.dataset.armed = "1"; del.textContent = $t("Wirklich löschen?"); return; }
          try { await delRecord("assess", a.id); assessments.delete(a.id); overview(); msg(key + "-msg", $t("Test gelöscht.")); }
          catch (e) { msg(key + "-msg", e.message); }
        });
        if (!readOnly) li.append(del);
        ul.append(li);
      });
    }
    function chart(list) {
      const box = $$("chart"); box.textContent = "";
      if (list.length < 2) return;
      const NS = "http://www.w3.org/2000/svg";
      const mk = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; return e; };
      const W = 640, H = 170, L = 30, R = 10, T = 10, B = 24, n = list.length, M = D.max;
      const x = (i) => L + (i * (W - L - R)) / (n - 1), y = (v) => T + ((M - v) * (H - T - B)) / M;
      const svg = mk("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": $T`Verlauf der ${D.name}-Werte` });
      svg.append(mk("rect", { class: "band", x: L, width: W - L - R, y: y(M), height: y(10) - y(M) }));
      svg.append(mk("text", { class: "band-label", x: W - R - 6, y: y(M) + 14, "text-anchor": "end" }, $t("ab 10 Punkten: ärztlich oder therapeutisch besprechen")));
      [...new Set([0, 5, 10, 15, 20, M])].filter((v) => v <= M).forEach((v) => {
        svg.append(mk("line", { class: "grid", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
        svg.append(mk("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, v));
      });
      const ticks = Math.min(n, 6);
      for (let k = 0; k < ticks; k++) {
        const i = ticks === 1 ? 0 : Math.round((k * (n - 1)) / (ticks - 1)); const d = parse(list[i].date);
        svg.append(mk("text", { x: x(i), y: H - 6, "text-anchor": k === 0 ? "start" : k === ticks - 1 ? "end" : "middle" }, `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.`));
      }
      svg.append(mk("polyline", { class: "s-phq", points: list.map((a, i) => `${x(i)},${y(a.score)}`).join(" ") }));
      list.forEach((a, i) => svg.append(mk("circle", { class: "s-phq", cx: x(i), cy: y(a.score), r: 3.5 })));
      box.append(svg);
    }
    function start() {
      $$("card").hidden = false;
      $$("form").reset(); [...$$("items").children].forEach((li) => li.classList.remove("missing")); msg(key + "-form-msg", "");
      $$("overview").hidden = true; $$("result").hidden = true; $$("form").hidden = false;
      $$("card").scrollIntoView({ behavior: "smooth", block: "start" });
    }
    function open() { overview(); $$("card").hidden = false; $$("card").scrollIntoView({ behavior: "smooth", block: "start" }); }
    function close() { overview(); $$("card").hidden = true; $("prog-card").scrollIntoView({ behavior: "smooth", block: "nearest" }); }
    $$("start").addEventListener("click", start);
    $$("cancel").addEventListener("click", close);
    $$("close").addEventListener("click", close);
    $$("form").addEventListener("submit", (ev) => {
      ev.preventDefault();
      const fd = new FormData($$("form"));
      const answers = D.items.map((_, i) => (fd.get("q" + i) == null ? null : Number(fd.get("q" + i))));
      const missing = answers.map((v, i) => (v == null ? i : -1)).filter((i) => i >= 0);
      [...$$("items").children].forEach((li, i) => li.classList.toggle("missing", missing.includes(i)));
      if (missing.length) {
        msg(key + "-form-msg", missing.length === 1 ? $T`Frage ${missing[0] + 1} ist noch offen.` : $T`Noch ${missing.length} Fragen offen (markiert).`);
        $$("items").children[missing[0]].scrollIntoView({ behavior: "smooth", block: "center" }); return;
      }
      const diff = fd.get("diff") == null ? null : Number(fd.get("diff"));
      const score = answers.reduce((a, b) => a + b, 0);
      const prev = sorted().pop();
      const rec = { v: 1, type: D.type, date: todayIso(), at: new Date().toISOString(), answers, difficulty: diff, score };
      const r4 = [...crypto.getRandomValues(new Uint8Array(4))].map((b) => b.toString(16).padStart(2, "0")).join("");
      const id = D.idPrefix + todayIso() + "-" + r4;
      busy($$("submit"), $t("Speichere …"), async () => {
        try {
          await putRecord("assess", id, rec);
          assessments.set(id, { ...rec, id });
          result(rec, prev);
        } catch (e) { msg(key + "-form-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
      });
    });
    function result(rec, prev) {
      const box = $$("result"); box.textContent = "";
      const sv = sevOf(rec.score);
      if (D.safetyItem != null && rec.answers[D.safetyItem] > 0) box.append(safetyBox());
      const sc = el("div", "phq-score");
      sc.append(el("b", null, String(rec.score)), el("span", "small", $T`von ${D.max} Punkten`), el("span", "sev sev-" + D.sevCls[sv], D.sev[sv]));
      box.append(sc, el("p", null, D.sevText[sv]));
      if (prev) {
        const d = rec.score - prev.score;
        box.append(el("p", "small", $T`Letzter Test am ${deDate(prev.date)}: ${prev.score} Punkte (${d === 0 ? $t("unverändert") : d > 0 ? "+" + d : d}).`));
      }
      if (rec.difficulty != null) box.append(el("p", "small", $t("Beeinträchtigung im Alltag: ") + DIFF_OPTS[rec.difficulty] + "."));
      box.append(el("p", "small", $T`Der ${D.name} ist ein Screening, keine Diagnose. Das Ergebnis erscheint auch im PDF-Bericht für die Therapie.`));
      const act = el("div", "actions"); const done = el("button", "btn primary", $t("Fertig")); done.type = "button";
      done.addEventListener("click", close); act.append(done); box.append(act);
      $$("form").hidden = true; $$("overview").hidden = true; box.hidden = false;
      $$("card").scrollIntoView({ behavior: "smooth", block: "start" });
    }
    return { key, D, overview, start, open, sorted };
  }
  const TESTS = [makeTest("phq"), makeTest("gad")];

  // ================================================================ Muster (nur beschreibend, auf dem Gerät berechnet)
  let patDays = 90;
  const WD_SHORT = ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"].map((d) => $t(d));
  const MONTHS = [$t("Jan"), $t("Feb"), $t("Mär"), $t("Apr"), $t("Mai"), $t("Jun"), $t("Jul"), $t("Aug"), $t("Sep"), $t("Okt"), $t("Nov"), $t("Dez")];
  const moodCls = (m) => (typeof m !== "number" ? "h0" : "h" + Math.min(5, Math.ceil(m / 2)));
  const avgOf = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : null);
  const f1 = (v) => (v == null ? "–" : LOC === "de-DE" ? v.toFixed(1).replace(".", ",") : v.toFixed(1));
  const svgEl = (tag, attrs, text) => { const e = document.createElementNS("http://www.w3.org/2000/svg", tag); for (const k in attrs) e.setAttribute(k, attrs[k]); if (text != null) e.textContent = text; return e; };
  [...$("pat-range").children].forEach((b) => b.addEventListener("click", () => {
    patDays = Number(b.dataset.days);
    [...$("pat-range").children].forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    renderPatterns();
  }));
  function inRange(days) {
    const from = parse(todayIso()); from.setDate(from.getDate() - (days - 1));
    const f = iso(from);
    return [...entries.values()].filter((e) => e.date >= f && e.date <= todayIso());
  }
  function renderPatterns() {
    const withMood = [...entries.values()].filter((e) => dv(e, "mood") != null);
    const enough = withMood.length >= 3;
    $("pat-empty").hidden = enough;
    document.querySelectorAll("#patterns-card .pat-block").forEach((b) => { b.hidden = !enough; });
    if (!enough) return;
    renderHeat(); renderWeek(); renderActs();
  }
  function renderHeat() {
    const box = $("pat-heat"); box.textContent = "";
    const today = parse(todayIso());
    const start = new Date(today); start.setDate(start.getDate() - 364);
    start.setDate(start.getDate() - ((start.getDay() + 6) % 7));              // auf Montag zurück
    const C = 11, G = 2, L = 22, T = 16;
    const weeks = Math.ceil(((today - start) / 864e5 + 1) / 7);
    const svg = svgEl("svg", { class: "heat", viewBox: `0 0 ${L + weeks * (C + G)} ${T + 7 * (C + G)}`, role: "img", "aria-label": $t("Stimmung pro Tag im letzten Jahr") });
    [0, 2, 4].forEach((r) => svg.append(svgEl("text", { x: 0, y: T + r * (C + G) + 9 }, WD_SHORT[r])));
    let lastMonth = -1;
    for (let w = 0; w < weeks; w++) {
      for (let r = 0; r < 7; r++) {
        const d = new Date(start); d.setDate(start.getDate() + w * 7 + r);
        if (d > today) continue;
        if (r === 0 && d.getMonth() !== lastMonth) {
          if (w > 0 || d.getDate() <= 7) svg.append(svgEl("text", { x: L + w * (C + G), y: 10 }, MONTHS[d.getMonth()]));
          lastMonth = d.getMonth();
        }
        const e = entries.get(iso(d));
        const rect = svgEl("rect", { class: moodCls(dv(e, "mood")), x: L + w * (C + G), y: T + r * (C + G), width: C, height: C });
        rect.append(svgEl("title", {}, `${deDate(iso(d))}: ${dv(e, "mood") != null ? $t("Stimmung ") + dv(e, "mood") : $t("kein Eintrag")}`));
        svg.append(rect);
      }
    }
    box.append(svg);
    requestAnimationFrame(() => { box.scrollLeft = box.scrollWidth; });   // neueste Wochen zuerst sichtbar
  }
  if (window.ResizeObserver) new ResizeObserver(() => { const hb = $("pat-heat"); hb.scrollLeft = hb.scrollWidth; }).observe($("pat-heat"));
  function renderWeek() {
    const box = $("pat-week"); box.textContent = "";
    const buckets = WD_SHORT.map(() => []);
    inRange(patDays).forEach((e) => { const m = dv(e, "mood"); if (m != null) buckets[(parse(e.date).getDay() + 6) % 7].push(m); });
    const W = 420, H = 190, L = 24, B = 34, T = 18, bw = (W - L) / 7;
    const y = (v) => T + ((10 - v) * (H - T - B)) / 10;
    const svg = svgEl("svg", { class: "chart week", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": $T`Durchschnittliche Stimmung nach Wochentag, letzte ${patDays} Tage` });
    [0, 5, 10].forEach((v) => { svg.append(svgEl("line", { class: "grid", x1: L, x2: W, y1: y(v), y2: y(v) })); svg.append(svgEl("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, v)); });
    buckets.forEach((b, i) => {
      const a = avgOf(b), x = L + i * bw + bw * 0.18, w = bw * 0.64, cx = L + i * bw + bw / 2;
      if (a != null && b.length >= 2) {
        svg.append(svgEl("rect", { class: "bar", x, y: y(a), width: w, height: y(0) - y(a), rx: 4 }));
        svg.append(svgEl("text", { class: "v", x: cx, y: y(a) - 5, "text-anchor": "middle" }, f1(a)));
      } else svg.append(svgEl("text", { x: cx, y: y(0) - 6, "text-anchor": "middle" }, "–"));
      svg.append(svgEl("text", { x: cx, y: H - 18, "text-anchor": "middle" }, WD_SHORT[i]));
      svg.append(svgEl("text", { class: "n", x: cx, y: H - 4, "text-anchor": "middle" }, `${b.length}×`));
    });
    box.append(svg);
  }
  function renderActs() {
    const ul = $("pat-acts"); ul.textContent = "";
    const list = inRange(patDays).filter((e) => dv(e, "mood") != null);
    const rows = ACTS.map((a) => {
      const yes = list.filter((e) => (e.activities || []).includes(a)).map((e) => dv(e, "mood"));
      const no = list.filter((e) => !(e.activities || []).includes(a)).map((e) => dv(e, "mood"));
      return { a, yes, no, ay: avgOf(yes), an: avgOf(no) };
    }).filter((r) => r.yes.length >= 3 && r.no.length >= 3).sort((p, q) => (q.ay - q.an) - (p.ay - p.an));
    if (!rows.length) { ul.append(el("li", "small", $t("Noch zu wenige Tage, um Aktivitäten zu vergleichen. Dafür braucht es je Aktivität mindestens drei Tage mit und drei ohne."))); return; }
    rows.forEach((r) => {
      const li = el("li"); li.append(el("span", "an", $t(r.a)));
      const bars = el("div", "bars");
      [[$t("mit"), r.ay, r.yes.length, ""], [$t("ohne"), r.an, r.no.length, " wo"]].forEach(([lab, v, n, cls]) => {
        const row = el("div", "row" + cls);
        const track = el("span", "track"); const b = el("b"); b.style.width = (v * 10) + "%"; track.append(b);
        row.append(el("span", "lab", lab), track, el("span", "val", $T`${f1(v)} · ${n} Tage`)); bars.append(row);
      });
      li.append(bars);
      const d = r.ay - r.an;
      li.append(el("span", "diff " + (d >= 0.5 ? "up" : d <= -0.5 ? "down" : ""), Math.abs(d) < 0.5 ? $t("kaum Unterschied") : $T`${d > 0 ? "+" : "–"}${f1(Math.abs(d))} an Tagen mit ${$t(r.a)}`));
      ul.append(li);
    });
  }

  // ================================================================ Für die nächste Sitzung
  const sessAll = () => [...items.values()].filter((i) => i.kind === "sess");
  function renderSess() {
    const open = sessAll().filter((n) => !n.done).sort((a, b) => a.created.localeCompare(b.created));
    const done = sessAll().filter((n) => n.done).sort((a, b) => (b.doneAt || "").localeCompare(a.doneAt || ""));
    $("sess-count").textContent = open.length ? `${open.length} offen` : "";
    $("sess-empty").hidden = open.length > 0;
    $("sess-form").hidden = readOnly;
    const draw = (ul, list) => {
      ul.textContent = "";
      list.forEach((n) => {
        const li = el("li"); const cb = document.createElement("input"); cb.type = "checkbox"; cb.checked = !!n.done; cb.disabled = readOnly;
        cb.setAttribute("aria-label", n.done ? $t("Wieder als offen markieren") : $t("Als besprochen markieren"));
        cb.addEventListener("change", async () => {
          try { await putItem({ ...n, done: cb.checked, doneAt: cb.checked ? new Date().toISOString() : null }); renderSess(); }
          catch (e) { cb.checked = !cb.checked; msg("sess-msg", e.message); }
        });
        const t = el("span", "st", n.text);
        t.append(el("span", "sd", (n.done && n.doneAt ? $T`besprochen am ${new Date(n.doneAt).toLocaleDateString(LOC)}` : $T`notiert am ${new Date(n.created).toLocaleDateString(LOC)}`)));
        li.append(cb, t);
        if (!readOnly) {
          const del = el("button", "btn", $t("Löschen")); del.type = "button";
          del.addEventListener("click", async () => {
            if (!del.dataset.armed) { del.dataset.armed = "1"; del.textContent = $t("Wirklich?"); return; }
            try { await dropItem(n.id); renderSess(); } catch (e) { msg("sess-msg", e.message); }
          });
          li.append(del);
        }
        ul.append(li);
      });
    };
    draw($("sess-open"), open); draw($("sess-done"), done.slice(0, 30));
    $("sess-done-wrap").hidden = !done.length; $("sess-done-sum").textContent = $T`Besprochen (${done.length})`;
  }
  $("sess-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = $("sess-text").value.trim();
    if (!text) return;
    busy($("sess-add"), "…", async () => {
      try { await putItem({ kind: "sess", id: "sess-" + rnd(), text, created: new Date().toISOString(), done: false, doneAt: null }); $("sess-text").value = ""; renderSess(); msg("sess-msg", ""); }
      catch (e) { msg("sess-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });

  // ================================================================ Tag: Morgen-Check-in, Gefühle, Abend-Check-out, Tagesübersicht
  // Einfacher Ablauf: morgens kurz einchecken, tagsüber Gefühle antippen, abends auschecken. Check-in und Check-out stehen
  // im Tageseintrag ("entry", Felder am / pmAt / intentDone), jedes Gefühl ist ein eigener Datensatz ("item", kind "feel").
  const FEEL_HARD = ["Traurig", "Leer", "Hoffnungslos", "Erschöpft", "Antriebslos", "Wertlos", "Schuldig", "Beschämt", "Einsam",
    "Gereizt", "Frustriert", "Überfordert", "Überreizt", "Ängstlich", "Unruhig", "Gefühllos"];
  const FEEL_GOOD = ["Ruhig", "Erleichtert", "Zufrieden", "Froh", "Dankbar", "Verbunden", "Motiviert", "Konzentriert"];
  const FEEL_ALERT = ["Hoffnungslos", "Wertlos", "Leer"];          // bei „stark“ Hinweis auf Hilfe zeigen
  const FEEL_LVL = [[1, $t("leicht")], [2, $t("mittel")], [3, $t("stark")]];
  const INTENT_OPTS = [["ja", $t("Geschafft")], ["teilweise", $t("Teilweise")], ["nein", $t("Nicht geschafft")]];
  const INTENT_LABEL = Object.fromEntries(INTENT_OPTS);
  const feelLabel = (n) => (FEEL_HARD.includes(n) || FEEL_GOOD.includes(n) ? $t(n) : n);
  const lvlLabel = (v) => (FEEL_LVL[v - 1] || [0, ""])[1];
  const feelsOn = (day) => [...items.values()].filter((i) => i.kind === "feel" && i.date === day).sort((a, b) => a.time.localeCompare(b.time));
  const hmOf = (s) => { if (!s) return ""; const d = new Date(s); return isNaN(d) ? "" : pad(d.getHours()) + ":" + pad(d.getMinutes()); };
  const num5 = (v) => typeof v === "number";
  const hasPm = (e) => !!e && (num5(e.mood) || num5(e.anxiety) || num5(e.drive) || !!e.note || (e.activities || []).length > 0 || !!e.meds || !!e.intentDone);
  const nowIfToday = (date) => (date === todayIso() ? new Date().toISOString() : null);
  let amOpen = false, pmOpen = false, amForm = { mood: null, energy: null, intent: "" };

  // ---------------------------------------------------------------- Bereiche (Heute / Verlauf & mehr)
  function setTab(name) {
    if (document.body.classList.contains("crisis")) return;   // im Krisenmodus gibt es nur die Krisen-Ansicht
    const today = name !== "more";
    $("tab-today").setAttribute("aria-selected", String(today)); $("tab-more").setAttribute("aria-selected", String(!today));
    $("tab-today").tabIndex = today ? 0 : -1; $("tab-more").tabIndex = today ? -1 : 0;
    $("pane-today").hidden = !today; $("pane-more").hidden = today;
  }
  $("tab-today").addEventListener("click", () => setTab("today"));
  $("tab-more").addEventListener("click", () => setTab("more"));
  [$("tab-today"), $("tab-more")].forEach((b) => b.addEventListener("keydown", (ev) => {
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    const next = b.id === "tab-today" ? "more" : "today"; setTab(next); $("tab-" + next).focus(); ev.preventDefault();
  }));
  setTab("today");

  // ---------------------------------------------------------------- Morgen-Check-in
  const AM_SEGS = [["s-am-mood", "mood", "v-am-mood"], ["s-am-anx", "anxiety", "v-am-anx"], ["s-am-drive", "drive", "v-am-drive"]];
  AM_SEGS.forEach(([id, k]) => {
    for (let i = 1; i <= 10; i++) {
      const b = el("button", null, String(i)); b.type = "button"; b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", () => { amForm[k] = amForm[k] === i ? null : i; renderAmForm(); });
      $(id).append(b);
    }
  });
  $("am-intent").addEventListener("input", (e) => { amForm.intent = e.target.value; });
  function loadAm() {
    const am = (entries.get(current) || {}).am || {};
    // Ältere Check-ins (Stimmung und Energie 1–5) werden nicht umgerechnet, nur das Vorhaben wird übernommen
    const v2 = am.v === 2;
    amForm = { mood: v2 ? am.mood ?? null : null, anxiety: v2 ? am.anxiety ?? null : null, drive: v2 ? am.drive ?? null : null, intent: am.intent || "" };
    $("am-intent").value = amForm.intent; msg("am-msg", ""); msg("am-done-msg", ""); msg("am-later-msg", "");
    const d = $("am-del"); delete d.dataset.armed; d.textContent = $t("Löschen");
  }
  function renderAmForm() {
    AM_SEGS.forEach(([s, k, v]) => {
      [...$(s).children].forEach((b, i) => b.setAttribute("aria-pressed", String(amForm[k] === i + 1)));
      $(v).textContent = amForm[k] ? amForm[k] + " / 10" : $t("noch nicht gewählt");
    });
    $("amLowHint").hidden = !(amForm.mood && amForm.mood <= 2);
  }
  function amSummary(am) {
    const parts = [];
    if (am.v === 2) {
      if (num5(am.mood)) parts.push($T`Stimmung ${am.mood}/10`);
      if (num5(am.anxiety)) parts.push($T`Angst ${am.anxiety}/10`);
      if (num5(am.drive)) parts.push($T`Antrieb ${am.drive}/10`);
    } else {
      if (num5(am.mood)) parts.push($T`Stimmung ${am.mood}/5`);
      if (num5(am.energy)) parts.push($T`Energie ${am.energy}/5`);
    }
    if (am.intent) parts.push($t("Vorhaben: ") + "„" + am.intent + "“");
    return parts.join(" · ") || "–";
  }
  function renderAm() {
    const e = entries.get(current), am = e && e.am, isToday = current === todayIso();
    const mode = amOpen ? "form" : am ? "done" : isToday ? "form" : "later";
    $("am-form").hidden = mode !== "form"; $("am-done").hidden = mode !== "done"; $("am-later").hidden = mode !== "later";
    $("am-time").textContent = am && am.at ? $T`um ${hmOf(am.at)} Uhr` : "";
    if (mode === "done") $("am-sum").textContent = amSummary(am);
    $("am-cancel").hidden = !amOpen; $("am-del").hidden = !am;
    $("am-save").textContent = am ? $t("Änderungen speichern") : $t("Check-in speichern");
    [$("am-save"), $("am-edit"), $("am-open"), $("am-del")].forEach((b) => { b.disabled = readOnly; });
    renderAmForm();
  }
  const openAm = () => { amOpen = true; loadAm(); renderAm(); $("s-am-mood").children[0].focus({ preventScroll: true }); };
  $("am-edit").addEventListener("click", openAm);
  $("am-open").addEventListener("click", openAm);
  $("am-cancel").addEventListener("click", () => { amOpen = false; loadAm(); renderAm(); });
  $("am-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (readOnly) return;
    const intent = amForm.intent.trim();
    if (amForm.mood == null && amForm.anxiety == null && amForm.drive == null && !intent) return msg("am-msg", $t("Wähle mindestens einen Wert oder schreib dein Vorhaben auf."));
    const date = current, prev = entries.get(date) || {};
    const { date: _d, ...rest } = prev;
    const data = { ...rest, am: { v: 2, mood: amForm.mood, anxiety: amForm.anxiety, drive: amForm.drive, intent, at: (prev.am && prev.am.at) || nowIfToday(date) }, updatedAt: new Date().toISOString() };
    busy($("am-save"), $t("Speichere …"), async () => {
      try { await putRecord("entry", date, data); entries.set(date, { ...data, date }); amOpen = false; renderAll(); msg("am-done-msg", $t("Gespeichert.")); }
      catch (e) { if (e.status !== 401) msg("am-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });
  $("am-del").addEventListener("click", async () => {
    const b = $("am-del");
    if (!b.dataset.armed) { b.dataset.armed = "1"; b.textContent = $t("Wirklich löschen?"); return; }
    const date = current, prev = entries.get(date);
    try {
      if (hasPm(prev)) {
        const { date: _d, am: _a, intentDone: _i, ...rest } = prev; const data = { ...rest, updatedAt: new Date().toISOString() };
        await putRecord("entry", date, data); entries.set(date, { ...data, date });
      } else { await delRecord("entry", date); entries.delete(date); }
      amOpen = false; loadAm(); loadPm(); renderAll(); msg(date === todayIso() ? "am-msg" : "am-later-msg", $t("Gelöscht."));
    } catch (e) { if (e.status !== 401) msg("am-msg", $t("Löschen hat nicht geklappt: ") + e.message); }
  });

  // ---------------------------------------------------------------- Abend-Check-out (Felder des bisherigen Tageseintrags)
  INTENT_OPTS.forEach(([v, label]) => {
    const b = el("button", "chip", label); b.type = "button"; b.dataset.v = v; b.setAttribute("aria-pressed", "false");
    b.addEventListener("click", () => { form.intentDone = form.intentDone === v ? null : v; renderForm(); });
    $("intent-done").append(b);
  });
  function pmSummary(e) {
    const parts = [];
    if (num5(e.mood)) parts.push($T`Stimmung ${e.mood}/10`);
    if (num5(e.anxiety)) parts.push($T`Angst ${e.anxiety}/10`);
    if (num5(e.drive)) parts.push($T`Antrieb ${e.drive}/10`);
    if (e.intentDone) parts.push($t("Vorhaben: ") + INTENT_LABEL[e.intentDone]);
    if ((e.activities || []).length) parts.push(e.activities.map((a) => $t(a)).join(", "));
    return parts.join(" · ") || e.note || "–";
  }
  function renderPm() {
    const e = entries.get(current), done = hasPm(e), isToday = current === todayIso();
    const mode = pmOpen ? "form" : done ? "done" : isToday && new Date().getHours() >= 17 ? "form" : "later";
    $("pm-form").hidden = mode !== "form"; $("pm-done").hidden = mode !== "done"; $("pm-later").hidden = mode !== "later";
    $("pm-time").textContent = e && e.pmAt ? $T`um ${hmOf(e.pmAt)} Uhr` : "";
    if (mode === "done") $("pm-sum").textContent = pmSummary(e);
    $("pm-later-text").textContent = isToday ? $t("Am Abend schaust du kurz auf den Tag zurück. Ab 17 Uhr ist der Check-out hier schon geöffnet.")
      : $t("An diesem Tag gab es keinen Check-out.");
    $("pm-open").textContent = isToday ? $t("Jetzt ausfüllen") : $t("Nachtragen");
    $("pm-cancel").hidden = !pmOpen;
    [$("pm-edit"), $("pm-open")].forEach((b) => { b.disabled = readOnly; });
  }
  const openPm = () => { pmOpen = true; loadPm(); renderForm(); $("s-mood").children[0].focus({ preventScroll: true }); };
  $("pm-edit").addEventListener("click", openPm);
  $("pm-open").addEventListener("click", openPm);
  $("pm-cancel").addEventListener("click", () => { pmOpen = false; loadPm(); renderForm(); });

  // ---------------------------------------------------------------- Gefühle: antippen, Stärke, Auslöser
  let feelEdit = null, feelLvl = null;
  const feelChip = (name, box, good) => {
    const b = el("button", "chip feel" + (good ? " good" : ""), feelLabel(name)); b.type = "button";
    b.addEventListener("click", () => openFeel({ name })); box.append(b);
  };
  FEEL_HARD.forEach((n) => feelChip(n, $("feel-hard")));
  FEEL_GOOD.forEach((n) => feelChip(n, $("feel-good"), true));
  { const b = el("button", "chip feel other", $t("Anderes …")); b.type = "button"; b.addEventListener("click", () => openFeel({ name: "", custom: true })); $("feel-good").append(b); }
  FEEL_LVL.forEach(([v, label]) => {
    const b = el("button", "chip lvl lvl-" + v, label); b.type = "button"; b.dataset.v = String(v); b.setAttribute("aria-pressed", "false");
    b.addEventListener("click", () => { feelLvl = v; renderFeelForm(); }); $("feel-lvl").append(b);
  });
  function openFeel(f) {
    if (readOnly) { msg("feel-msg", $t("Im Modus „Nur ansehen“ gesperrt. Melde dich neu an und stimm der Einwilligung zu.")); return; }
    const custom = !!f.custom || (!!f.name && !FEEL_HARD.includes(f.name) && !FEEL_GOOD.includes(f.name));
    feelEdit = { ...f, custom }; feelLvl = f.level || null;
    $("feel-form-title").textContent = f.id ? $T`${feelLabel(f.name)} bearbeiten` : custom ? $t("Anderes Gefühl") : feelLabel(f.name);
    $("feel-other-wrap").hidden = !custom; $("feel-other").value = custom ? f.name || "" : "";
    $("feel-trig").value = f.trigger || "";
    $("feel-time").value = f.time || (current === todayIso() ? nowHM() : "12:00");
    const d = $("feel-del"); d.hidden = !f.id; delete d.dataset.armed; d.textContent = $t("Löschen");
    msg("feel-form-msg", ""); msg("feel-msg", "");
    $("feel-form").hidden = false; renderFeelForm();
    $("feel-form").scrollIntoView({ behavior: "smooth", block: "nearest" });
    (custom ? $("feel-other") : $("feel-lvl").children[0]).focus({ preventScroll: true });
  }
  function closeFeel(all) { feelEdit = null; feelLvl = null; $("feel-form").hidden = true; if (all !== false) $("feelHint").hidden = true; }
  function renderFeelForm() {
    [...$("feel-lvl").children].forEach((b) => b.setAttribute("aria-pressed", String(feelLvl === Number(b.dataset.v))));
    $("feelHint").hidden = !(feelEdit && !feelEdit.custom && feelLvl === 3 && FEEL_ALERT.includes(feelEdit.name));
  }
  $("feel-cancel").addEventListener("click", () => closeFeel());
  $("feel-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (!feelEdit || readOnly) return;
    const name = feelEdit.custom ? $("feel-other").value.trim() : feelEdit.name, level = feelLvl, time = $("feel-time").value;
    if (!name) return msg("feel-form-msg", $t("Wie heißt das Gefühl?"));
    if (!level) return msg("feel-form-msg", $t("Wähle, wie stark das Gefühl ist."));
    if (!/^\d{2}:\d{2}$/.test(time)) return msg("feel-form-msg", $t("Bitte gib eine Uhrzeit an."));
    const date = feelEdit.date || current;
    const obj = { kind: "feel", id: feelEdit.id || `feel-${date}-${rnd()}`, date, time, name, level, trigger: $("feel-trig").value.trim(), at: feelEdit.at || new Date().toISOString() };
    busy($("feel-save"), $t("Speichere …"), async () => {
      try {
        await putItem(obj); closeFeel(false); renderDay(); renderHist();
        msg("feel-msg", $T`Gespeichert: ${feelLabel(name)} (${lvlLabel(level)}) um ${time} Uhr.`);
      } catch (e) { if (e.status !== 401) msg("feel-form-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    });
  });
  $("feel-del").addEventListener("click", async () => {
    const b = $("feel-del");
    if (!feelEdit || !feelEdit.id) return;
    if (!b.dataset.armed) { b.dataset.armed = "1"; b.textContent = $t("Wirklich löschen?"); return; }
    try { await dropItem(feelEdit.id); closeFeel(); renderDay(); renderHist(); msg("feel-msg", $t("Gelöscht.")); }
    catch (e) { if (e.status !== 401) msg("feel-form-msg", $t("Löschen hat nicht geklappt: ") + e.message); }
  });
  function feelCsv() {
    const esc = (v) => { const s = v == null ? "" : String(v); return /[";\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const rows = [[$t("Datum"), $t("Uhrzeit"), $t("Gefühl"), $t("Stärke"), $t("Auslöser")]];
    [...items.values()].filter((i) => i.kind === "feel").sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time))
      .forEach((f) => rows.push([f.date, f.time, feelLabel(f.name), lvlLabel(f.level), f.trigger]));
    return "﻿" + rows.map((r) => r.map(esc).join(";")).join("\r\n");
  }
  $("export-feel").addEventListener("click", async () => {
    try { await P.saveFile(new Blob([feelCsv()], { type: "text/csv;charset=utf-8" }), $t("gefuehle-") + todayIso() + ".csv"); }
    catch (e) { setStatus($t("Die Datei ließ sich nicht speichern: ") + (e.message || e)); }
  });

  // ---------------------------------------------------------------- Tagesübersicht
  function renderDay() { renderAm(); renderPm(); renderTimeline(); }
  function renderTimeline() {
    const e = entries.get(current), fs = feelsOn(current), ul = $("timeline"), rows = [];
    ul.textContent = "";
    if (e && e.am) rows.push({ t: hmOf(e.am.at), k: hmOf(e.am.at) || "00:00", cls: "tl-am", title: $t("Morgen-Check-in"), text: amSummary(e.am) });
    if (addonOn("feel")) fs.forEach((f) => rows.push({ t: f.time, k: f.time, cls: "tl-feel lvl-" + f.level + (FEEL_GOOD.includes(f.name) ? " good" : ""),
      title: feelLabel(f.name) + " · " + lvlLabel(f.level), text: f.trigger, feel: f }));
    if (addonOn("meds")) dosesOn(current).forEach((d) => rows.push({ t: d.time, k: d.time, cls: "tl-dose", title: $t("Tablette: ") + medLabel(d), text: d.note }));
    if (hasPm(e)) rows.push({ t: hmOf(e.pmAt), k: hmOf(e.pmAt) || "99:99", cls: "tl-pm", title: $t("Abend-Check-out"), text: pmSummary(e) + (e.note && pmSummary(e) !== e.note ? " · " + e.note : "") });
    rows.sort((a, b) => a.k.localeCompare(b.k));
    rows.forEach((r) => {
      const li = el("li", "tl " + r.cls), time = el("span", "tl-t", r.t || "–"), body = el("div", "tl-b");
      body.append(el("b", null, r.title)); if (r.text) body.append(el("span", "tl-x", r.text));
      if (r.feel && !readOnly) {
        const b = el("button", "tl-btn"); b.type = "button"; b.append(time, body);
        b.title = $t("Bearbeiten"); b.addEventListener("click", () => openFeel(r.feel)); li.append(b);
      } else li.append(time, body);
      ul.append(li);
    });
    $("sum-empty").hidden = rows.length > 0;
    let stat = "";
    if (fs.length && addonOn("feel")) {
      const c = new Map(); fs.forEach((f) => c.set(f.name, (c.get(f.name) || 0) + 1));
      const top = [...c.entries()].sort((a, b) => b[1] - a[1])[0];
      stat = fs.length === 1 ? $t("1 Gefühl") : $T`${fs.length} Gefühle`;
      if (top[1] > 1) stat += " · " + $T`am häufigsten: ${feelLabel(top[0])}`;
    }
    $("sum-stat").textContent = stat;
    $("feel-count").textContent = fs.length ? $T`${fs.length} an diesem Tag` : "";
  }

  // ---------------------------------------------------------------- Fragebögen als Monatsbalken
  let progKey = "phq";
  [...$("prog-pick").children].forEach((b) => b.addEventListener("click", () => { progKey = b.dataset.test; renderProg(); }));
  const sevIdx = (D, s) => { const i = D.bands.findIndex((b) => s <= b); return i < 0 ? D.bands.length : i; };
  const nextDue = (list) => { const last = list[list.length - 1]; if (!last) return null; const d = parse(last.date); d.setDate(d.getDate() + 14); return iso(d); };
  function renderProg() {
    const T = TESTS.find((x) => x.key === progKey), D = T.D, list = T.sorted();
    [...$("prog-pick").children].forEach((b) => {
      const other = TESTS.find((x) => x.key === b.dataset.test), n = nextDue(other.sorted());
      b.setAttribute("aria-pressed", String(b.dataset.test === progKey));
      b.classList.toggle("due", !n || n <= todayIso());
    });
    const box = $("prog-bars"); box.textContent = "";
    const now = new Date(), fmtM = new Intl.DateTimeFormat(LOC, { month: "short" }), fmtML = new Intl.DateTimeFormat(LOC, { month: "long", year: "numeric" });
    const grid = el("div", "bars-grid");
    for (let i = 6; i >= 0; i--) {
      const m = new Date(now.getFullYear(), now.getMonth() - i, 1), key = m.getFullYear() + "-" + pad(m.getMonth() + 1);
      const inM = list.filter((a) => a.date.startsWith(key)), last = inM[inM.length - 1];
      const col = el("div", "bar-col" + (i === 0 ? " now" : "")), track = el("div", "bar-track");
      track.setAttribute("role", "img");
      if (last) {
        const sv = sevIdx(D, last.score), fill = el("div", "bar-fill");
        fill.style.height = Math.max(10, (last.score / D.max) * 100) + "%";
        track.append(fill);
        track.setAttribute("aria-label", $T`${fmtML.format(m)}: ${last.score} von ${D.max} Punkten, ${D.sev[sv]}`); track.title = track.getAttribute("aria-label");
      } else track.setAttribute("aria-label", $T`${fmtML.format(m)}: kein Fragebogen`);
      col.append(track, el("span", "bar-m", fmtM.format(m).replace(".", "")));
      grid.append(col);
    }
    const axis = el("div", "bars-axis"); axis.setAttribute("aria-hidden", "true");
    [$t("hoch"), $t("mittel"), $t("niedrig")].forEach((l) => axis.append(el("span", null, l)));
    box.append(grid, axis);
    const next = nextDue(list), due = !next || next <= todayIso(), btn = $("prog-go");
    btn.className = "btn wide" + (due ? " primary" : " quiet");
    btn.textContent = due ? (list.length ? $T`${D.name} ist wieder fällig – jetzt ausfüllen` : $T`Ersten ${D.name}-Fragebogen ausfüllen`)
      : $T`Kein Fragebogen fällig · nächster ab ${deDate(next)}`;
    btn.disabled = readOnly || !due;
    $("prog-all").hidden = !list.length;
  }
  $("prog-go").addEventListener("click", () => TESTS.find((x) => x.key === progKey).start());
  $("prog-all").addEventListener("click", () => TESTS.find((x) => x.key === progKey).open());

  // ================================================================ Krisenmodus
  // Für schwere Phasen: nur noch Hilfe, eine Frage zum Befinden und kleine Schritte. Ein- und Ausschalten wird als
  // verschlüsselter Datensatz gespeichert (item, kind "crisis", start/end), damit es auf allen Geräten gilt.
  const CM_MOOD = [[1, $t("sehr schlecht")], [3, $t("schlecht")], [5, $t("geht so")], [7, $t("okay")], [9, $t("gut")]];
  const STEPS = [["drink", $t("Etwas getrunken")], ["eat", $t("Etwas gegessen")], ["meds", $t("Tabletten genommen")],
    ["light", $t("Kurz Tageslicht")], ["wash", $t("Zähne geputzt oder geduscht")], ["contact", $t("Jemandem geschrieben")]];
  const crisisActive = () => [...items.values()].filter((i) => i.kind === "crisis" && !i.end).sort((a, b) => b.start.localeCompare(a.start))[0] || null;

  function renderCrisis() {
    const on = !!crisisActive();
    document.body.classList.toggle("crisis", on);
    $("pane-crisis").hidden = !on;
    document.querySelector(".tabs").hidden = on;
    $("crisis-switch").hidden = on || readOnly;
    if (on) {
      $("pane-today").hidden = true; $("pane-more").hidden = true;
      $("crisis-off").disabled = readOnly;
      renderHelp(); renderCmMood(); renderSteps();
    } else if ($("pane-today").hidden && $("pane-more").hidden) setTab("today");
  }

  $("crisis-on").addEventListener("click", () => {
    if (readOnly) return;
    busy($("crisis-on"), $t("Einen Moment …"), async () => {
      try {
        await putItem({ kind: "crisis", id: `crisis-${todayIso()}-${rnd()}`, start: new Date().toISOString(), end: null });
        renderCrisis(); msg("cm-msg", ""); window.scrollTo({ top: 0 });
      } catch (e) { if (e.status !== 401) setStatus($t("Das hat nicht geklappt: ") + e.message); }
    });
  });
  $("crisis-off").addEventListener("click", () => {
    const c = crisisActive(); if (!c || readOnly) return;
    busy($("crisis-off"), $t("Einen Moment …"), async () => {
      try { await putItem({ ...c, end: new Date().toISOString() }); renderAll(); setStatus($t("Krisenmodus beendet.")); window.scrollTo({ top: 0 }); }
      catch (e) { if (e.status !== 401) msg("cm-msg", $t("Das hat nicht geklappt: ") + e.message); }
    });
  });

  // ---------------------------------------------------------------- Hilfe: Kontakte und Hilfen aus dem Krisenplan, feste Nummern
  function callItem(c) {
    const li = el("li", "help-item"), t = el("div", "help-who");
    t.append(el("b", null, c.name || c.phone));
    if (c.note) t.append(el("span", "small", c.note));
    li.append(t);
    if (c.phone) { const a = el("a", "btn call", $t("Anrufen")); a.href = telHref(c.phone); a.setAttribute("aria-label", $T`${c.name || c.phone} anrufen`); li.append(a); }
    return li;
  }
  function textList(title, list) {
    const items_ = (list || []).filter((x) => typeof x === "string" && x.trim());
    if (!items_.length) return null;
    const wrap = el("div", "help-block"); wrap.append(el("h3", "sub3", title));
    const ul = el("ul", "help-text"); items_.forEach((x) => ul.append(el("li", null, x))); wrap.append(ul);
    return wrap;
  }
  function renderHelp() {
    const box = $("help-body"), plan = getPlan(); box.textContent = "";
    const people = plan ? [...(plan.people || []), ...(plan.pros || [])].filter((c) => c && (c.name || c.phone)) : [];
    if (people.length) {
      const wrap = el("div", "help-block"); wrap.append(el("h3", "sub3", $t("Menschen, die du anrufen kannst")));
      const ul = el("ul", "help-list"); people.forEach((c) => ul.append(callItem(c))); wrap.append(ul); box.append(wrap);
    }
    [textList($t("Was dir hilft"), plan && plan.self), textList($t("Was dir wichtig ist"), plan && plan.reasons)].forEach((b) => b && box.append(b));
    const fixed = el("div", "help-block"); fixed.append(el("h3", "sub3", $t("Rund um die Uhr erreichbar")));
    const ul = el("ul", "help-list"); PLAN_FIXED.forEach((c) => ul.append(callItem(c)));
    if (window.KW_I18N.lang === "en") {
      const li = el("li", "help-item"), a = el("a", null, "findahelpline.com"); a.href = "https://findahelpline.com"; a.rel = "noopener noreferrer"; a.target = "_blank";
      const t = el("div", "help-who"); t.append(el("b", null, $t("Hilfe in anderen Ländern")), a); li.append(t); ul.append(li);
    }
    fixed.append(ul); box.append(fixed);
    if (!plan) {
      const p = el("p", "small", $t("Du hast noch keinen Krisenplan. Lege ihn am besten in einer ruhigeren Zeit an, gern zusammen mit deiner Therapeutin oder deinem Therapeuten."));
      const b = el("button", "btn", $t("Krisenplan ansehen")); b.type = "button"; b.addEventListener("click", showPlan);
      box.append(p, b);
    }
  }

  // ---------------------------------------------------------------- Wie geht's gerade? (eine Frage, gespeichert auf der Skala 1–10)
  CM_MOOD.forEach(([v, label]) => {
    const b = el("button", "cm-opt"); b.type = "button"; b.dataset.v = String(v); b.setAttribute("aria-pressed", "false");
    b.append(el("span", "cm-dot"), el("span", null, label));
    b.addEventListener("click", () => saveCm({ mood: v }));
    $("cm-mood").append(b);
  });
  [["s-cm-anx", "anxiety"], ["s-cm-drive", "drive"]].forEach(([id, k]) => {
    for (let i = 1; i <= 10; i++) {
      const b = el("button", null, String(i)); b.type = "button"; b.setAttribute("aria-pressed", "false");
      b.addEventListener("click", () => saveCm({ [k]: i })); $(id).append(b);
    }
  });
  // Ziel: ohne Morgen-Check-in (oder mit einem aus dem Krisenmodus, solange es keinen Check-out gibt) der Morgen, sonst der Abend
  const cmToAm = (e) => !e || !e.am || (e.am.crisis && !hasPm(e));
  function cmValues() {
    const e = entries.get(todayIso());
    const src = cmToAm(e) ? (e && e.am) || {} : e;
    return { mood: src.mood ?? null, anxiety: src.anxiety ?? null, drive: src.drive ?? null };
  }
  function renderCmMood() {
    const v = cmValues();
    const near = v.mood == null ? -1 : CM_MOOD.reduce((best, [x], i) => (Math.abs(x - v.mood) < Math.abs(CM_MOOD[best][0] - v.mood) ? i : best), 0);
    [...$("cm-mood").children].forEach((b, i) => b.setAttribute("aria-pressed", String(i === near)));
    [["s-cm-anx", "anxiety", "v-cm-anx"], ["s-cm-drive", "drive", "v-cm-drive"]].forEach(([s, k, id]) => {
      [...$(s).children].forEach((b, i) => { b.setAttribute("aria-pressed", String(v[k] === i + 1)); b.disabled = readOnly; });
      $(id).textContent = v[k] ? v[k] + " / 10" : $t("noch nicht gewählt");
    });
    [...$("cm-mood").children].forEach((b) => { b.disabled = readOnly; });
    $("cmLowHint").hidden = !(v.mood != null && v.mood <= 2);
  }
  async function saveCm(patch) {
    if (readOnly) return;
    const date = todayIso(), prev = entries.get(date) || {}, now = new Date().toISOString();
    const { date: _d, ...rest } = prev;
    const data = cmToAm(prev)
      ? { ...rest, am: { ...(prev.am || {}), v: 2, ...patch, crisis: true, at: (prev.am && prev.am.at) || now }, updatedAt: now }
      : { ...rest, ...patch, pmAt: prev.pmAt || now, updatedAt: now };
    try { await putRecord("entry", date, data); entries.set(date, { ...data, date }); renderAll(); msg("cm-mood-msg", $t("Gespeichert.")); }
    catch (e) { if (e.status !== 401) msg("cm-mood-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
  }

  // ---------------------------------------------------------------- Kleine Schritte (im Tageseintrag, Feld steps)
  STEPS.forEach(([k, label]) => {
    const b = el("button", "cm-step"); b.type = "button"; b.dataset.k = k; b.setAttribute("aria-pressed", "false");
    b.append(el("span", "cm-check"), el("span", null, label));
    b.addEventListener("click", () => toggleStep(k));
    $("cm-steps").append(b);
  });
  function renderSteps() {
    const done = (entries.get(todayIso()) || {}).steps || [];
    [...$("cm-steps").children].forEach((b) => { b.setAttribute("aria-pressed", String(done.includes(b.dataset.k))); b.disabled = readOnly; });
    $("steps-count").textContent = done.length ? (done.length === 1 ? $t("1 Schritt heute") : $T`${done.length} Schritte heute`) : "";
  }
  async function toggleStep(k) {
    if (readOnly) return;
    const date = todayIso(), prev = entries.get(date) || {}, { date: _d, ...rest } = prev;
    const s = new Set(prev.steps || []); s.has(k) ? s.delete(k) : s.add(k);
    const data = { ...rest, steps: STEPS.map(([x]) => x).filter((x) => s.has(x)), updatedAt: new Date().toISOString() };
    try { await putRecord("entry", date, data); entries.set(date, { ...data, date }); renderSteps(); msg("steps-msg", ""); }
    catch (e) { if (e.status !== 401) msg("steps-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
  }

  // ---------------------------------------------------------------- „Ich bin in Gefahr“: sofort Nummern, nichts wird gespeichert
  let dangerReturn = null;
  function openDanger() {
    const box = $("danger-actions"); box.textContent = "";
    const call = (label, phone, main) => { const a = el("a", "btn " + (main ? "primary big-call" : "big-call"), label); a.href = telHref(phone); box.append(a); };
    call($t("Notruf 112 anrufen"), "112", true);
    call($t("Telefonseelsorge anrufen (0800 111 0 111)"), "08001110111");
    const plan = getPlan();
    [...((plan && plan.people) || []), ...((plan && plan.pros) || [])].filter((c) => c && c.phone).slice(0, 4)
      .forEach((c) => call($T`${c.name || c.phone} anrufen`, c.phone));
    if (window.KW_I18N.lang === "en") { const a = el("a", "btn big-call", $t("Hilfe in anderen Ländern")); a.href = "https://findahelpline.com"; a.rel = "noopener noreferrer"; a.target = "_blank"; box.append(a); }
    dangerReturn = document.activeElement;
    $("danger").hidden = false; document.body.classList.add("danger-open");
    box.querySelector("a").focus();
  }
  function closeDanger() {
    $("danger").hidden = true; document.body.classList.remove("danger-open");
    if (dangerReturn && dangerReturn.focus) dangerReturn.focus();
  }
  $("danger-open").addEventListener("click", openDanger);
  $("danger-close").addEventListener("click", closeDanger);
  $("danger").addEventListener("keydown", (ev) => { if (ev.key === "Escape") closeDanger(); });
  $("danger").addEventListener("click", (ev) => { if (ev.target === $("danger")) closeDanger(); });

  // ================================================================ Add-ons
  // Der Kern bleibt schlicht; Gefühle, Fragebögen, Tabletten, Muster und Therapie sind einschaltbar. Welche an sind,
  // steht verschlüsselt im Datensatz "prefs" und gilt damit auf allen Geräten (App und Browser). Neue Konten: alle aus.
  // Ausblenden per CSS: Elemente mit data-addon="<k>" sind nur sichtbar, wenn body die Klasse addon-<k> trägt.
  const ADDONS = [
    { k: "feel", slug: "gefuehle", name: $t("Gefühle"), text: $t("Gefühle über den Tag antippen, mit Stärke, Auslöser und Uhrzeit.") },
    { k: "tests", slug: "fragebogen", name: $t("Fragebögen"), text: $t("PHQ-9 und GAD-7 alle zwei Wochen, als Verlauf über die Monate.") },
    { k: "meds", slug: "tabletten", name: $t("Tabletten"), text: $t("Medikamente mit Dosis und Zeiten, jede Einnahme mit einem Tipp.") },
    { k: "patterns", slug: "muster", name: $t("Muster"), text: $t("Jahresübersicht, Wochentage und Aktivitäten im Zusammenhang mit deiner Stimmung.") },
    { k: "therapy", slug: "therapie", name: $t("Therapie"), text: $t("Notizen für die nächste Sitzung und ein PDF-Bericht für die Therapie.") },
  ];
  const PREFS_ID = "prefs";
  let addonBase = "";   // Domain der Infoseiten (ADDON_DOMAIN), z. B. kopfwetter.app -> https://gefuehle.kopfwetter.app
  let siteBase = "";
  // Ohne gespeicherte Einstellung (Konten von vor den Add-ons): an, was schon Daten hat
  function addonDefaults() {
    const all = [...items.values()];
    return { feel: all.some((i) => i.kind === "feel"), tests: assessments.size > 0, meds: all.some((i) => i.kind === "med" || i.kind === "dose"),
      patterns: false, therapy: all.some((i) => i.kind === "sess") };
  }
  function addonState() { const p = items.get(PREFS_ID); return p && p.addons ? p.addons : addonDefaults(); }
  function addonOn(k) { return !!addonState()[k]; }
  function applyAddons() {
    const st = addonState();
    ADDONS.forEach((a) => document.body.classList.toggle("addon-" + a.k, !!st[a.k]));
  }
  function addonInfoUrl(a) {
    if (addonBase) return `https://${a.slug}.${addonBase}/`;
    return (siteBase || P.apiBase || "") + "/addon/" + a.slug;
  }
  function renderAddons() {
    const ul = $("addons"), st = addonState(); ul.textContent = "";
    ADDONS.forEach((a) => {
      const li = el("li", "addon"); li.id = "addon-" + a.slug;
      const t = el("div", "addon-text");
      t.append(el("b", null, a.name), el("span", "small", a.text));
      const more = el("a", "addon-more", $t("Mehr erfahren")); more.href = addonInfoUrl(a);
      if (/^https?:/.test(more.href) && (addonBase || P.native)) { more.target = "_blank"; more.rel = "noopener noreferrer"; }
      t.append(more);
      const sw = el("button", "switch"); sw.type = "button"; sw.setAttribute("role", "switch");
      sw.setAttribute("aria-checked", String(!!st[a.k])); sw.setAttribute("aria-label", a.name); sw.disabled = readOnly;
      sw.append(el("span", "knob"));
      sw.addEventListener("click", () => toggleAddon(a, sw));
      li.append(t, sw); ul.append(li);
    });
  }
  async function toggleAddon(a, sw) {
    if (readOnly) return;
    const next = { ...addonState(), [a.k]: !addonOn(a.k) };
    sw.disabled = true;
    try {
      await putItem({ kind: "prefs", id: PREFS_ID, addons: next });
      renderAll(); if (a.k === "tests") TESTS.forEach((t) => t.overview()); if (a.k === "therapy") renderSess();
      msg("addons-msg", next[a.k] ? $T`${a.name} ist eingeschaltet.` : $T`${a.name} ist ausgeschaltet. Die Einträge bleiben erhalten.`);
    } catch (e) { if (e.status !== 401) msg("addons-msg", $t("Speichern hat nicht geklappt: ") + e.message); }
    sw.disabled = readOnly;
  }
  // Link von einer Infoseite: …?addon=gefuehle öffnet die Add-on-Einstellungen und hebt das Add-on hervor
  function focusAddonFromUrl() {
    const slug = new URLSearchParams(location.search).get("addon");
    const a = ADDONS.find((x) => x.slug === slug);
    if (!a || document.body.classList.contains("crisis")) return;
    setTab("more");
    const li = $("addon-" + a.slug); if (!li) return;
    li.classList.add("highlight"); li.scrollIntoView({ block: "center" });
    try { const u = new URL(location.href); u.searchParams.delete("addon"); history.replaceState(null, "", u.toString()); } catch (e) { /* egal */ }
  }

  boot();
})();
