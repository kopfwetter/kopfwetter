// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
// Baut den Web-Teil der App: kopiert ../static nach www/ und bündelt src/native.js.
// Server-Adresse: app.config.json ("server") oder Umgebungsvariable KOPFWETTER_SERVER.
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cfg = JSON.parse(readFileSync(join(root, "app.config.json"), "utf8"));
const server = (process.env.KOPFWETTER_SERVER || cfg.server || "").replace(/\/+$/, "");
if (!/^https:\/\/[^/]+$/.test(server) && !process.env.ALLOW_HTTP_SERVER) {
  console.error(`Ungültige Server-Adresse „${server}“. Erwartet z. B. https://kopfwetter.app (ohne Pfad).`);
  process.exit(1);
}
if (server.includes("example.")) console.warn("Hinweis: Trage in mobile/app.config.json die Adresse deines Servers ein.");

const www = join(root, "www");
rmSync(www, { recursive: true, force: true });
mkdirSync(www, { recursive: true });
cpSync(join(root, "..", "static"), join(www, "static"), { recursive: true });

await build({
  entryPoints: [join(root, "src", "native.js")],
  bundle: true, minify: true, format: "iife", target: ["es2020"],
  define: { __API_BASE__: JSON.stringify(server) },
  outfile: join(www, "static", "native.js"),
  logLevel: "warning",
});

// index.html: native.js vor app.js laden und eine Content-Security-Policy setzen (im Web kommt sie als Header vom Server)
let html = readFileSync(join(root, "..", "static", "index.html"), "utf8");
const csp = `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self' ${server}; object-src 'none'; base-uri 'none'; form-action 'self'`;
html = html.replace('<meta name="referrer" content="no-referrer">',
  `<meta name="referrer" content="no-referrer">\n<meta http-equiv="Content-Security-Policy" content="${csp}">`);
html = html.replace('<script src="/static/app.js" defer></script>', '<script src="/static/native.js" defer></script>\n<script src="/static/app.js" defer></script>');
html = html.replace('<link rel="manifest" href="/manifest.webmanifest">\n', "");
if (!html.includes("/static/native.js")) { console.error("index.html: app.js-Einbindung nicht gefunden."); process.exit(1); }
writeFileSync(join(www, "index.html"), html);

// en.html: gleiche Übersetzungslogik wie i18n_html.py auf dem Server
const table = JSON.parse(readFileSync(join(root, "..", "i18n", "en-html.json"), "utf8"));
const ATTRS = /\b(placeholder|aria-label|title|alt|content)="([^"]*)"/g;
let skip = 0; const missing = [];
const en = html.split(/(<[^>]+>)/).map((part) => {
  if (part.startsWith("<")) {
    const low = part.toLowerCase();
    if (/^<(script|style)\b/.test(low)) skip++; else if (/^<\/(script|style)\b/.test(low)) skip--;
    part = part.replace(ATTRS, (m, a, v) => (Object.hasOwn(table, v) ? `${a}="${table[v]}"` : m));
    if (low.startsWith("<html")) part = part.replace(/lang="[^"]*"/, 'lang="en"');
    return part;
  }
  const key = part.split(/\s+/).filter(Boolean).join(" ");
  if (skip || !key) return part;
  if (Object.hasOwn(table, key)) return part.match(/^\s*/)[0] + table[key] + part.match(/\s*$/)[0];
  if (/[a-zäöüß]{3,}/.test(key)) missing.push(key);
  return part;
}).join("").replace('<script src="/static/i18n.js" defer></script>', '<script src="/static/i18n/en.js" defer></script>\n<script src="/static/i18n.js" defer></script>');
writeFileSync(join(www, "en.html"), en);
if (missing.length) console.warn("en.html: ohne Übersetzung: " + missing.slice(0, 10).join("; "));
console.log(`www/ gebaut. Server: ${server}`);
