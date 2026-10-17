# Website-Dateien für die statische Website (separates Repo, Plesk Git Autodeploy)

Die Website ist eine statische Seite auf Plesk (`httpdocs`). Dieses Verzeichnis enthält nur die Teile für
AI Hosting; die bestehende Produktseite `/ki-hosting/` liegt bereits auf der Website und wird nicht ersetzt.

| Datei | Zweck |
|---|---|
| `build/pages.py` | erzeugt `ki-hosting/bestellen/index.html`, `ki-hosting/danke/index.html` und `domains/index.html` im Design der Website (Kopf, Fuss und Meta aus `snippets/_*.html`) und kopiert `assets/signup.js`, `assets/domains.js`, `assets/domains.json`. Aufruf: `SIGNUP_BASE=https://<mcp-host>/plesk python3 build/pages.py <website-checkout>` |
| `assets/signup.js` | Formularlogik: Preisliste, Länder und Formular-Token vom Dienst holen, Live-Verfügbarkeit, Preissumme, JSON-POST an `/signup`; `SIGNUP_BASE` wird beim Build gesetzt |
| `assets/domains.js` | rendert die Domaintabelle aus `assets/domains.json` (statische Tabelle bleibt als Fallback) |
| `assets/domains.json` | Kopie von `pleskmcp/signup/data/domains.json`; beide gleich halten |
| `snippets/navigation.html`, `startseite.html`, `faq.html`, `sitemap.xml` | Einträge für Navigation (alle Seiten), Startseite, FAQ und Sitemap |

Die Website-Origin (`https://tabside.ch`) muss in `SIGNUP_ALLOWED_ORIGINS` des Dienstes stehen, `SIGNUP_SUCCESS_URL`
zeigt auf `/ki-hosting/danke/`.
