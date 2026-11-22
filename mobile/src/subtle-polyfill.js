// SPDX-FileCopyrightText: 2026 Torsten Albrecht
// SPDX-License-Identifier: AGPL-3.0-or-later
// Ersatz für die Teile von WebCrypto (crypto.subtle), die die App nutzt – nur falls das WebView sie nicht anbietet
// (z. B. ältere iOS-Versionen unter capacitor://localhost). Gleiche Verfahren und Formate wie WebCrypto:
// PBKDF2-SHA256, HKDF-SHA256, HMAC-SHA256, AES-256-GCM (Tag angehängt). Grundlage: @noble/hashes und @noble/ciphers (auditiert).
import { pbkdf2Async } from "@noble/hashes/pbkdf2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { gcm } from "@noble/ciphers/aes.js";
import { hmac } from "@noble/hashes/hmac.js";

const u8 = (x) => (x instanceof Uint8Array ? x : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength) : new Uint8Array(x ?? []));
const ab = (u) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength);
const algName = (a) => (typeof a === "string" ? a : a.name).toUpperCase();
const makeKey = (raw, algorithm, extractable, usages) =>
  ({ type: "secret", algorithm: typeof algorithm === "string" ? { name: algorithm } : { ...algorithm }, extractable, usages, __raw: u8(raw).slice() });
const opError = (msg) => { const e = new Error(msg); e.name = "OperationError"; return e; };

export const subtle = {
  async importKey(format, keyData, algorithm, extractable, usages) {
    if (format !== "raw") throw opError("Nur das Format raw wird unterstützt.");
    return makeKey(keyData, algorithm, extractable, usages);
  },
  async deriveBits(alg, baseKey, length) {
    const name = algName(alg), dkLen = length / 8;
    if (algName(alg.hash) !== "SHA-256") throw opError("Nur SHA-256 wird unterstützt.");
    if (name === "PBKDF2") return ab(await pbkdf2Async(sha256, baseKey.__raw, u8(alg.salt), { c: alg.iterations, dkLen, asyncTick: 25 }));
    if (name === "HKDF") return ab(hkdf(sha256, baseKey.__raw, u8(alg.salt), u8(alg.info), dkLen));
    throw opError("Nicht unterstützt: " + name);
  },
  async deriveKey(alg, baseKey, derivedAlg, extractable, usages) {
    return makeKey(await this.deriveBits(alg, baseKey, derivedAlg.length), derivedAlg, extractable, usages);
  },
  async sign(alg, key, data) {
    if (algName(alg) !== "HMAC" || algName(key.algorithm) !== "HMAC") throw opError("Nur HMAC wird unterstützt.");
    if (algName(key.algorithm.hash) !== "SHA-256") throw opError("Nur SHA-256 wird unterstützt.");
    return ab(hmac(sha256, key.__raw, u8(data)));
  },
  async encrypt(alg, key, data) {
    if (algName(alg) !== "AES-GCM") throw opError("Nur AES-GCM wird unterstützt.");
    return ab(gcm(key.__raw, u8(alg.iv), alg.additionalData ? u8(alg.additionalData) : undefined).encrypt(u8(data)));
  },
  async decrypt(alg, key, data) {
    if (algName(alg) !== "AES-GCM") throw opError("Nur AES-GCM wird unterstützt.");
    try { return ab(gcm(key.__raw, u8(alg.iv), alg.additionalData ? u8(alg.additionalData) : undefined).decrypt(u8(data))); }
    catch (e) { throw opError("Entschlüsselung fehlgeschlagen."); }
  },
};

export function installIfMissing() {
  const c = globalThis.crypto;
  if (c && typeof c.getRandomValues === "function" && !c.subtle) {
    Object.defineProperty(c, "subtle", { value: subtle, configurable: true });
    return true;
  }
  return false;
}
