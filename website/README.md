# Website-Dateien für die statische Website (separates Repo)

Diese Dateien gehören in das Repo der statischen Website und sind hier nur abgelegt, weil das Website-Repo
in dieser Umgebung nicht erreichbar war. Sie enthalten keine echten Hostnamen; vor dem Einbau die Platzhalter
ersetzen (siehe unten).

| Datei | Ziel auf der Website | Zweck |
|---|---|---|
| `ki-hosting/index.html` | `/ki-hosting/` | Produktseite AI Hosting (Leistungen, Preis, FAQ, Link zur Bestellung) |
| `ki-hosting/bestellen/index.html` | `/ki-hosting/bestellen/` | Bestellformular; sendet per JavaScript an den Signup-Endpunkt des PleskMCP-Dienstes |
| `ki-hosting/danke/index.html` | `/ki-hosting/danke/` | Bestätigungsseite (Ziel von `SIGNUP_SUCCESS_URL`) |
| `domains/index.html` + `assets/domains.js` | `/domains/` | Domainpreise aus der gemeinsamen Preisliste (`assets/domains.json`) |
| `assets/signup.js`, `assets/signup.css` | `/assets/` | Formularlogik (Token, Live-Verfügbarkeit, Fehlermeldungen) und Stil |
| `assets/domains.json` | `/assets/domains.json` | Kopie von `pleskmcp/signup/data/domains.json`; beide Dateien gleich halten (oder im Build kopieren) |
| `snippets/navigation.html`, `snippets/startseite.html`, `snippets/faq.html`, `snippets/sitemap.xml` | in die bestehenden Seiten einfügen | Navigationseintrag "AI Hosting", Hinweis auf der Startseite, FAQ-Einträge, Sitemap-Einträge |

Platzhalter: `https://mcp.example.com/plesk` ist die `PUBLIC_BASE_URL` des Dienstes (in `assets/signup.js`
als `SIGNUP_BASE` und in `assets/domains.js`), `https://www.example.com` die Website-Adresse (Sitemap,
Canonical-Links), `/agb/` die AGB-Seite. Die Website-Origin muss in `SIGNUP_ALLOWED_ORIGINS` des Dienstes stehen.

Die Preise auf `/domains/` und im Formular kommen zur Laufzeit aus `assets/domains.json`; das Formular lädt
zusätzlich `GET <SIGNUP_BASE>/signup/config` (Preisliste, Länder, AGB-Version des Dienstes), damit beide Seiten
dieselbe Liste zeigen.
