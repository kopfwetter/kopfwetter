// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
// Brücke zwischen Weboberfläche und iOS/Android (Capacitor).
// Wird von scripts/build-www.mjs gebündelt und vor app.js geladen.
import { Capacitor } from "@capacitor/core";
import { App } from "@capacitor/app";
import { Directory, Filesystem } from "@capacitor/filesystem";
import { Share } from "@capacitor/share";
import { StatusBar, Style } from "@capacitor/status-bar";
import { SecureStorage } from "@aparajita/capacitor-secure-storage";
import { installIfMissing } from "./subtle-polyfill.js";

// Sprache: gespeicherte Wahl, sonst Gerätesprache (Deutsch für de-*, sonst Englisch); passende Seite laden
(() => {
  let want = null;
  try { want = localStorage.getItem("kw-lang"); } catch (e) { /* egal */ }
  if (want !== "de" && want !== "en") want = /^de\b/i.test(navigator.language || "") ? "de" : "en";
  const isEn = /\/en\.html$/.test(location.pathname);
  if (want === "en" && !isEn) location.replace("en.html");
  else if (want === "de" && isEn) location.replace("index.html");
})();

// Falls das WebView kein WebCrypto anbietet: kompatiblen Ersatz einsetzen (vor app.js)
const usingPolyfill = installIfMissing();

const TOKEN_KEY = "session-token";
const native = Capacitor.isNativePlatform();

function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1]);
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
}

window.KopfwetterPlatform = {
  native,
  usingPolyfill,
  apiBase: __API_BASE__,
  // Token im Keychain (iOS) bzw. Android Keystore, nicht im WebView-Speicher
  async getToken() { return native ? await SecureStorage.getItem(TOKEN_KEY) : null; },
  async setToken(t) { if (native) await SecureStorage.setItem(TOKEN_KEY, t); },
  async clearToken() { if (native) await SecureStorage.removeItem(TOKEN_KEY); },
  // PDF/CSV: in den App-Cache schreiben und das Teilen-Menü öffnen (Dateien, Mail, Drucken …)
  async saveFile(blob, filename) {
    const data = await blobToBase64(blob);
    const res = await Filesystem.writeFile({ path: filename, data, directory: Directory.Cache });
    try {
      await Share.share({ title: filename, url: res.uri, dialogTitle: "Speichern oder teilen" });
    } finally {
      // Kopie im Cache nach kurzer Zeit wieder löschen (enthält Gesundheitsdaten im Klartext)
      setTimeout(() => Filesystem.deleteFile({ path: filename, directory: Directory.Cache }).catch(() => {}), 120000);
    }
  },
};

if (native) {
  const setBar = () => StatusBar.setStyle({ style: matchMedia("(prefers-color-scheme: dark)").matches ? Style.Dark : Style.Light }).catch(() => {});
  setBar();
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", setBar);
  // Android-Zurücktaste: offene Formulare schließen statt die App zu beenden
  App.addListener("backButton", ({ canGoBack }) => {
    const cancel = document.querySelector("#phq-form:not([hidden]) #phq-cancel");
    if (cancel) return cancel.click();
    if (canGoBack) history.back(); else App.minimizeApp();
  });
}
