// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
// Prüft die Testvektoren (vectors.json, erzeugt mit Python: argon2-cffi und cryptography) gegen
//   1. WebCrypto (crypto.subtle, wie im Browser) und
//   2. den noble-Ersatz aus mobile/src/subtle-polyfill.js (für WebViews ohne WebCrypto).
// Argon2id kommt in beiden Fällen aus hash-wasm (static/vendor/argon2.umd.min.js), wie in der App.
// Die Abläufe entsprechen deriveKeys / wrapDek / importDek / rid / putRecord / deriveRecovery in static/app.js.
// Aufruf: (cd mobile && npm ci) && node tests/vectors/check.mjs
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
import { subtle as nobleSubtle } from "../../mobile/src/subtle-polyfill.js";

const require = createRequire(import.meta.url);
const hashwasm = require("../../static/vendor/argon2.umd.min.js");
const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (u) => Buffer.from(u).toString("base64"), unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const hex = (u) => Buffer.from(u).toString("hex"), unhex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const RK = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const hkdfInfo = (s) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(s) });

function parseRecoveryKey(str) {
  const c = String(str).toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/I/g, "1");
  let bits = ""; for (const ch of c) bits += RK.indexOf(ch).toString(2).padStart(5, "0");
  return Uint8Array.from(bits.match(/.{8}/g), (x) => parseInt(x, 2));
}

async function run(name, subtle) {
  const fails = [];
  const eq = (label, got, want) => { if (got !== want) fails.push(`${label}: ${got} != ${want}`); };
  const bits = async (key, info) => new Uint8Array(await subtle.deriveBits(hkdfInfo(info), key, 256));
  const aes = (raw, usages) => subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, usages);
  const k = V.kdf, pw = k.password.normalize("NFKC");

  // Passwort -> Argon2id -> master -> authKey / KEK
  const master = await hashwasm.argon2id({ password: pw, salt: unb64(k.salt), parallelism: k.p, iterations: k.t, memorySize: k.m, hashLength: 32, outputType: "binary" });
  eq("argon2id master", hex(master), k.master_hex);
  const hk = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits", "deriveKey"]);
  eq("authKey", b64(await bits(hk, "kopfwetter-app/auth/v1")), k.authKey);
  const kekRaw = await bits(hk, "kopfwetter-app/kek/v1");
  eq("kek", hex(kekRaw), k.kek_hex);

  // v1-Ableitung (PBKDF2), nur noch für die Anmeldung vor der Umstellung
  const base = await subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const m1 = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", salt: unb64(k.salt), iterations: V.kdf_v1.i, hash: "SHA-256" }, base, 256));
  eq("pbkdf2 master (v1)", hex(m1), V.kdf_v1.master_hex);
  eq("authKey (v1)", b64(await bits(await subtle.importKey("raw", m1, "HKDF", false, ["deriveBits"]), "kopfwetter-app/auth/v1")), V.kdf_v1.authKey);

  // DEK einpacken (AES-GCM, AAD kopfwetter-app/dek/v1) und wieder auspacken
  const kek = await aes(kekRaw, ["encrypt", "decrypt"]), aad = te.encode(V.dek.aad), w = V.dek.wrappedKey;
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: unb64(w.iv), additionalData: aad }, kek, unhex(V.dek.dek_hex)));
  eq("wrappedKey.ct", b64(ct), w.ct);
  const dek = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(w.iv), additionalData: aad }, kek, unb64(w.ct)));
  eq("unwrap", hex(dek), V.dek.dek_hex);

  // Wiederherstellungsschlüssel
  const r = V.recovery, raw = parseRecoveryKey(r.key);
  eq("recovery.raw", hex(raw), r.raw_hex);
  const rhk = await subtle.importKey("raw", raw, "HKDF", false, ["deriveBits", "deriveKey"]);
  eq("recovery.authKey", b64(await bits(rhk, "kopfwetter-app/recovery-auth/v1")), r.authKey);
  const rkekRaw = await bits(rhk, "kopfwetter-app/recovery-kek/v1");
  eq("recovery.kek", hex(rkekRaw), r.kek_hex);
  const rdek = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(r.recoveryWrapped.iv), additionalData: aad }, await aes(rkekRaw, ["decrypt"]), unb64(r.recoveryWrapped.ct)));
  eq("recovery.unwrap", hex(rdek), V.dek.dek_hex);

  // Datensatz: Kennung per HMAC, Inhalt aufgefüllt, AAD mit Kennung
  const R = V.record;
  const dhk = await subtle.importKey("raw", dek, "HKDF", false, ["deriveBits", "deriveKey"]);
  eq("record.idKey", hex(await bits(dhk, "kopfwetter-app/record-id/v1")), R.idKey_hex);
  const idKey = await subtle.deriveKey(hkdfInfo("kopfwetter-app/record-id/v1"), dhk, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
  const id = hex(new Uint8Array(await subtle.sign("HMAC", idKey, te.encode(R.kind + ":" + R.key))).slice(0, 16));
  eq("record.id", id, R.id);
  const dk = await aes(dek, ["encrypt", "decrypt"]);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(R.sealed.iv), additionalData: te.encode(R.aad) }, dk, unb64(R.sealed.ct)));
  eq("record.length", pt.length, R.plaintext_len);
  const o = JSON.parse(td.decode(pt));
  eq("record.body", JSON.stringify(o), R.body);
  let moved = false;
  try { await subtle.decrypt({ name: "AES-GCM", iv: unb64(R.sealed.iv), additionalData: te.encode("kopfwetter-app/record/v1:" + "0".repeat(32)) }, dk, unb64(R.sealed.ct)); moved = true; } catch {}
  if (moved) fails.push("record: Entschlüsselung unter fremder Kennung hätte scheitern müssen");

  console.log(fails.length ? `✗ ${name}\n  ${fails.join("\n  ")}` : `✓ ${name}`);
  return fails.length;
}

// Die App muss genau diese Kennungen verwenden (schützt vor unbemerkten Abweichungen zwischen Test und App)
const appJs = readFileSync(new URL("../../static/app.js", import.meta.url), "utf8");
const labels = ["kopfwetter-app/auth/v1", "kopfwetter-app/kek/v1", V.dek.aad, "kopfwetter-app/recovery-auth/v1",
  "kopfwetter-app/recovery-kek/v1", "kopfwetter-app/record-id/v1", "kopfwetter-app/record/v1:"];
const missing = labels.filter((l) => !appJs.includes(`"${l}"`));
if (missing.length) console.log("✗ static/app.js verwendet andere Kennungen, fehlt: " + missing.join(", "));
else console.log("✓ Kennungen in static/app.js");

const n = missing.length + (await run("WebCrypto", webcrypto.subtle)) + (await run("noble-Ersatz", nobleSubtle));
process.exit(n ? 1 : 0);
