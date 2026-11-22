# Verwendete Software Dritter

Kopfwetter selbst steht unter der [AGPL-3.0-or-later](LICENSE).

## Im Repository enthalten

| Komponente | Version | Lizenz | Ort |
| --- | --- | --- | --- |
| [jsPDF](https://github.com/parallax/jsPDF) | 2.5.2 | MIT | `static/vendor/jspdf.umd.min.js`, Lizenztext in `static/vendor/jspdf.LICENSE` |
| [hash-wasm](https://github.com/Daninet/hash-wasm) (Argon2id) | 4.12.0 | MIT | `static/vendor/argon2.umd.min.js`, Lizenztext in `static/vendor/hash-wasm.LICENSE` |

## Server (Python, über `requirements.txt`)

| Paket | Lizenz |
| --- | --- |
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| PyOTP | MIT |
| argon2-cffi | MIT |
| cryptography | Apache-2.0 oder BSD-3-Clause |
| qrcode | BSD-3-Clause |

## Apps (npm, über `mobile/package.json`, im App-Paket gebündelt)

| Paket | Lizenz |
| --- | --- |
| @capacitor/core, android, ios, app, filesystem, share, splash-screen, status-bar, cli, assets | MIT |
| @aparajita/capacitor-secure-storage | MIT |
| @noble/hashes, @noble/ciphers | MIT |
| esbuild (nur zum Bauen) | MIT |
