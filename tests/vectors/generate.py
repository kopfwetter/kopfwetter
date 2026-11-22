# SPDX-FileCopyrightText: 2026 Torsten Albrecht
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Erzeugt Testvektoren für die Schlüsselhierarchie (docs/CRYPTO.md) unabhängig vom JavaScript-Code.

Aufruf:  python3 tests/vectors/generate.py > tests/vectors/vectors.json
Prüfen:  node tests/vectors/check.mjs   (WebCrypto und noble-Ersatz müssen dieselben Werte liefern)
"""
import base64, json, unicodedata
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac as chmac
from argon2.low_level import Type, hash_secret_raw

RK_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
b64 = lambda b: base64.b64encode(b).decode()
seq = lambda start, n: bytes((start + i) % 256 for i in range(n))


def hkdf(ikm: bytes, info: str) -> bytes:
    # WebCrypto-HKDF mit leerem Salt = RFC 5869 mit Salt aus 32 Nullbytes
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=info.encode()).derive(ikm)


def recovery_string(raw: bytes) -> str:
    bits = "".join(f"{x:08b}" for x in raw)
    s = "".join(RK_ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, 160, 5))
    return "-".join(s[i:i + 4] for i in range(0, 32, 4))


def main():
    password, salt = "Kopfwetter: heiter bis wolkig – Ä", seq(0, 16)
    pw = unicodedata.normalize("NFKC", password).encode()
    m, t, p = 65536, 3, 1
    master = hash_secret_raw(pw, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32, type=Type.ID)
    auth, kek = (hkdf(master, i) for i in ("kopfwetter-app/auth/v1", "kopfwetter-app/kek/v1"))
    iterations = 600_000   # v1-Konten, nur noch für die Anmeldung vor der Umstellung
    master_v1 = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(pw)

    dek, dek_iv = seq(0x20, 32), seq(0xA0, 12)
    wrapped = AESGCM(kek).encrypt(dek_iv, dek, b"kopfwetter-app/dek/v1")

    rk_raw = seq(0x50, 20)
    rk_auth, rk_kek = hkdf(rk_raw, "kopfwetter-app/recovery-auth/v1"), hkdf(rk_raw, "kopfwetter-app/recovery-kek/v1")
    rk_iv = seq(0xB0, 12)
    rk_wrapped = AESGCM(rk_kek).encrypt(rk_iv, dek, b"kopfwetter-app/dek/v1")

    # Datensatz: Kennung = HMAC(idKey, Art:Schlüssel)[:16], Klartext mit Leerzeichen auf 256 Byte aufgefüllt
    id_key = hkdf(dek, "kopfwetter-app/record-id/v1")
    h = chmac.HMAC(id_key, hashes.SHA256()); h.update(b"entry:2026-11-04"); rid = h.finalize()[:16].hex()
    body = json.dumps({"k": "entry", "key": "2026-11-04", "d": {"mood": 3, "note": "Spaziergang"}}, separators=(",", ":"), ensure_ascii=False).encode()
    plain = body + b" " * (256 - len(body))
    rec_iv = seq(0xC0, 12)
    rec_ct = AESGCM(dek).encrypt(rec_iv, plain, ("kopfwetter-app/record/v1:" + rid).encode())

    print(json.dumps({
        "version": 2,
        "kdf": {"password": password, "salt": b64(salt), "alg": "argon2id", "m": m, "t": t, "p": p,
                "master_hex": master.hex(), "authKey": b64(auth), "kek_hex": kek.hex()},
        "kdf_v1": {"alg": "pbkdf2-sha256", "i": iterations, "master_hex": master_v1.hex(),
                   "authKey": b64(hkdf(master_v1, "kopfwetter-app/auth/v1"))},
        "dek": {"dek_hex": dek.hex(), "aad": "kopfwetter-app/dek/v1", "wrappedKey": {"iv": b64(dek_iv), "ct": b64(wrapped)}},
        "recovery": {"raw_hex": rk_raw.hex(), "key": recovery_string(rk_raw), "authKey": b64(rk_auth), "kek_hex": rk_kek.hex(),
                     "recoveryWrapped": {"iv": b64(rk_iv), "ct": b64(rk_wrapped)}},
        "record": {"kind": "entry", "key": "2026-11-04", "idKey_hex": id_key.hex(), "id": rid, "plaintext_len": len(plain),
                   "body": body.decode(), "aad": "kopfwetter-app/record/v1:" + rid, "sealed": {"iv": b64(rec_iv), "ct": b64(rec_ct)}},
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
