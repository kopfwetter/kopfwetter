# Checkliste vor der Veröffentlichung

## Einmalig: Repository öffentlich machen

- [ ] Alte verschachtelte Kopie `stimmung-app/` im GitLab-Repo löschen (`git rm -r stimmung-app && git commit`)
- [ ] Prüfen, dass `.env`, `data/` und `*.db` nie committet wurden:
      `git log --all --full-history --oneline -- .env data '*.db'` (muss leer sein)
- [ ] Die gesamte Historie auf Geheimnisse scannen:
      `docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect --source /repo --config /repo/.gitleaks.toml -v`
- [ ] Bei einem Fund: Geheimnis **erneuern** (bei `APP_SECRET` siehe unten) und die Historie mit `git filter-repo` bereinigen. Nur löschen reicht nicht.
- [ ] Ein geleaktes `APP_SECRET` über `APP_SECRET_PREVIOUS` wechseln (README, „APP_SECRET erneuern“). Die 2FA bleibt dabei für alle Konten gültig.
- [ ] Impressumsdaten nur in `.env` auf dem Server, nicht im Code
- [ ] Projekt in GitLab auf **Public** stellen, Beschreibung und Topics setzen (`e2ee`, `mental-health`, `fastapi`, `capacitor`)
- [ ] Optional: Spiegel auf Codeberg oder GitHub für mehr Sichtbarkeit

## Bei jedem Release

- [ ] `pytest -q` und `node tests/vectors/check.mjs` grün (CI)
- [ ] `PRIVACY_VERSION` in `legal.py` erhöhen, wenn sich die Datenschutzerklärung inhaltlich ändert
- [ ] Versionsnummer in `mobile/package.json`, `versionCode`/`versionName` (Android) und Build/Version (Xcode) erhöhen
- [ ] Tag setzen: `git tag -a v1.x.y -m "…" && git push --tags`
- [ ] Release-Notes mit Hinweis auf Migrationen und Sicherheitsfixes
