# PleskMCP

Ein eigenständiger Remote-MCP-Server, mit dem Hosting-Kunden ihre AI-Tools (Claude, ChatGPT, Claude Code und andere MCP-Clients) per Connector mit den Webdateien ihrer eigenen Plesk-Abonnements verbinden. Anmeldung mit den Plesk-Zugangsdaten des Kunden, Autorisierung nach der MCP-Spezifikation (OAuth 2.1).

Dieses Repo ist öffentlich. Code, README, Tests und Beispiele enthalten keine echten Hostnamen, IPs, Domains, Tokens oder Kundennamen, nur Platzhalter wie `plesk.example.com`. Echte Werte gehören ausschliesslich in Umgebungsvariablen (z.B. in Portainer).

## Sicherheitsmodell in Kürze

- **Kein Root.** Der Dienst hat weder Root-SSH noch das Root-Passwort noch den Plesk-DB-Admin-Zugang. Auf dem Plesk-Server gibt es einen eigenen, unprivilegierten SSH-Benutzer `pleskmcp` mit Key, dessen Key per `authorized_keys` auf ein Forced Command festgenagelt ist und der per sudoers genau einen Befehl ausführen darf: das Hilfsskript, und zwar nur als Mitglied der Plesk-Gruppe `psacln` (die Systembenutzer der Abonnements). root ist nicht in dieser Gruppe.
- **Dateioperationen laufen unter dem Systembenutzer des Kunden.** Die Trennung zwischen Kunden übernimmt das Betriebssystem, neue Dateien gehören automatisch dem Kunden.
- **Zuordnung serverseitig.** Login → Abonnements → Domains → Systembenutzer → Document Root wird read-only aus der Plesk XML API ermittelt (im Kontext des Kunden selbst). Der Client übergibt nur Domainname und relativen Pfad. Die Domain wird gegen die Liste des angemeldeten Kunden geprüft, bevor irgendetwas ausgeführt wird.
- **Pfade werden im Hilfsskript abgesichert:** normalisiert, auf den Document Root begrenzt, jede Komponente per `lstat` geprüft, Symlinks werden abgelehnt, Ziel ausserhalb wird abgelehnt. Keine Shell-Strings, alle Parameter gehen als JSON über stdin.
- **Nur Kunden-Hauptlogins.** Admin, Reseller und Zusatzbenutzer werden abgewiesen (die XML API zeigt ihnen keinen Kunden mit ihrem Login bzw. antwortet mit `1006 Permission denied`).
- **Passwörter werden nie gespeichert und nie geloggt.** Access- und Refresh-Tokens liegen nur als SHA-256-Hash in SQLite. Access-Tokens sind kurzlebig (Standard 30 Minuten), Refresh-Tokens rotieren, die Wiederverwendung eines alten Refresh-Tokens widerruft die ganze Token-Familie.
- **Statusprüfung pro Tool-Aufruf** (kurz gecacht): gelöschte oder gesperrte Plesk-Konten fallen durch, gesperrte Abonnements verschwinden aus der Domainliste.
- **Sicherungen und Papierkorb** liegen im Abonnement des Kunden unter `/var/www/vhosts/<abo>/.pleskmcp/` (Modus 0700), also ausserhalb jedes Document Root und nicht per Browser erreichbar. `delete_file` löscht nie endgültig.
- **Audit-Log** (JSON Lines) für jede Anmeldung und jeden schreibenden Aufruf: Zeit, Plesk-Login, Domain, Pfad, Tool, Client. Keine Dateiinhalte, keine Secrets.
- **Rate-Limits** für Anmeldeversuche pro IP und pro Login plus ein globales Budget fehlgeschlagener Plesk-Logins, damit Plesks Fail2ban die IP des Dienstes nicht sperrt (siehe unten).

## Verifizierte Plesk-Fakten (Plesk Obsidian 18.0.80, CloudLinux 8)

| Frage | Ergebnis |
|---|---|
| Kundenlogin an der XML API (`agent.php`, Header `HTTP_AUTH_LOGIN`/`HTTP_AUTH_PASSWD`) | Funktioniert. `webspace get` liefert `name`, `ftp_login` (Systembenutzer) und `www_root`. `customer get` zeigt dem Kunden nur sich selbst. |
| Zusatzbenutzer | Passwort wird geprüft (falsch: 1001), aber jede Abfrage liefert `1006 Permission denied`. Keine Zuordnung zu Abos möglich, daher nicht unterstützt. |
| Gesperrter Kunde | Systemfehler `1011 Zugriff verweigert. Ihr Konto wurde gesperrt.` ohne Fail2ban-Eintrag. |
| Gesperrtes Abonnement | `webspace get` liefert für dieses Abo `1006`, der Kunde selbst bleibt aktiv. |
| MFA | Die XML API prüft keinen zweiten Faktor (Plesk-Support: die Mobile-App nutzt die XML API und unterstützt MFA nicht). MFA in Plesk schützt den MCP-Login also nicht. |
| Fail2ban | Ein API-Fehlversuch landet als `Failed login attempt with login '<login>' from IP <ip>` in `/var/log/plesk/panel.log` und zählt für die Jail `plesk-panel` (Standard 5 Versuche in 10 Minuten, Sperre 10 Minuten auf 443/8880/8443). **Die IP des MCP-Hosts muss in Plesks Trusted-Liste.** |
| CageFS | `sudo -u <user>` tritt nicht in CageFS ein (CloudLinux rät von `pam_lve` in `/etc/pam.d/sudo` ab, dort steht nur `pam_sulve`). Das Hilfsskript läuft als Systembenutzer ausserhalb des Käfigs und ohne LVE-Limit. Die Trennung kommt aus den Dateirechten plus den Pfadprüfungen. |

## Einrichtung auf dem Plesk-Server

Voraussetzung: Linux-Plesk, Python 3.6 oder neuer (`/usr/libexec/platform-python` auf CloudLinux/RHEL 8 reicht).

1. Auf dem Docker-Host ein Schlüsselpaar erzeugen (ohne Passphrase):
   ```
   ssh-keygen -t ed25519 -N "" -f pleskmcp_ssh_key -C pleskmcp
   ```
2. `server-setup/` und `helper/pleskmcp_helper.py` auf den Plesk-Server kopieren und als root installieren:
   ```
   ./server-setup/install.sh "$(cat pleskmcp_ssh_key.pub)"
   ```
   Das Skript installiert
   - `/usr/local/bin/pleskmcp-helper` (root-eigen, 0755, wird per sudo als Systembenutzer ausgeführt),
   - `/usr/local/bin/pleskmcp-sshwrap` (Forced Command, lässt exakt `sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper` zu),
   - `/etc/sudoers.d/pleskmcp`:
     ```
     Defaults:pleskmcp !requiretty
     Defaults:pleskmcp env_reset
     pleskmcp ALL=(%psacln) NOPASSWD: /usr/local/bin/pleskmcp-helper ""
     ```
   - den Benutzer `pleskmcp` (Home `/var/lib/pleskmcp`) mit `restrict,command="/usr/local/bin/pleskmcp-sshwrap" <key>` in `authorized_keys`.
3. Die IP des Docker-Hosts bei Fail2ban als vertrauenswürdig eintragen:
   ```
   plesk bin ip_ban --add-trusted "<ip des docker-hosts>" -description "PleskMCP"
   ```
4. Host-Key des Servers für `PLESK_SSH_HOST_KEY` auslesen (nur Typ und Base64):
   ```
   ssh-keyscan -t ed25519 plesk.example.com 2>/dev/null | awk '{print $2, $3}'
   ```
5. Vom Docker-Host testen (Systembenutzer und Document Root eines beliebigen Abos einsetzen):
   ```
   echo '{"op":"ping","domain":"example.com","docroot":"/var/www/vhosts/example.com/httpdocs"}' \
     | ssh -i pleskmcp_ssh_key pleskmcp@plesk.example.com 'sudo -n -u example_sysuser /usr/local/bin/pleskmcp-helper'
   ```
   Erwartet: `{"ok": true, "result": {"uid": ..., "home": "/var/www/vhosts/example.com", ...}}`.

Hinweise:
- Das Hilfsskript prüft bei jedem Aufruf, dass der übergebene Document Root im Home des Systembenutzers (`/var/www/vhosts/<abo>`) liegt und ihm gehört. Ein fremder Docroot wird abgelehnt, selbst wenn der Dienst ihn übergeben würde.
- Logs der Domain (`search_log`) werden aus `/var/www/vhosts/<abo>/logs/` bzw. für Addon-Domains aus `/var/www/vhosts/system/<domain>/logs/` gelesen, sofern der Systembenutzer sie lesen darf.
- Updates des Hilfsskripts: `install.sh` erneut ausführen.

## Deployment (Docker, Portainer)

Das Image wird bei jedem Push auf `main` von GitHub Actions gebaut und nach `ghcr.io/tabside/pleskmcp:latest` veröffentlicht (`.github/workflows/docker-publish.yml`, Tests laufen vorher). Ist das GHCR-Package privat, braucht Portainer unter Registries einen `ghcr.io`-Eintrag mit einem GitHub-Token (Scope `read:packages`).

1. In Portainer einen Stack aus `docker-compose.yml` anlegen, Umgebungsvariablen aus `.env.example` setzen. Pflicht: `PUBLIC_BASE_URL`, `PLESK_URL`, `PLESK_SSH_HOST`, `PLESK_SSH_USER`, `PLESK_SSH_KEY_PATH` (Secret), `PLESK_SSH_HOST_KEY` oder `PLESK_SSH_KNOWN_HOSTS`, bei `ACCOUNT_CHECK_MODE=customer_key` zusätzlich `DATA_ENCRYPTION_KEY`. Fehlt eine Pflichtvariable, startet der Container nicht und nennt sie im Log.
2. `DATA_ENCRYPTION_KEY` erzeugen: `docker run --rm ghcr.io/tabside/pleskmcp pleskmcp generate-key`.
3. Den privaten SSH-Key als Docker-Secret bereitstellen (Compose: `secrets.pleskmcp_ssh_key.file`).
4. Der Container bindet standardmässig nur auf `127.0.0.1:8426`. Davor gehört ein Reverse-Proxy mit TLS.

### Reverse-Proxy (nginx, z.B. als zusätzliche nginx-Direktiven einer Plesk-Domain)

Bei `PUBLIC_BASE_URL=https://mcp.example.com/plesk` müssen der Pfad `/plesk/` **und** die drei Well-known-Pfade mit dem Suffix `/plesk` an den Container gehen:

```nginx
location ^~ /plesk/ { proxy_pass http://127.0.0.1:8426; include /etc/nginx/pleskmcp-proxy.inc; }
location = /plesk   { proxy_pass http://127.0.0.1:8426; include /etc/nginx/pleskmcp-proxy.inc; }
location ^~ /.well-known/oauth-authorization-server/plesk { proxy_pass http://127.0.0.1:8426; include /etc/nginx/pleskmcp-proxy.inc; }
location ^~ /.well-known/openid-configuration/plesk       { proxy_pass http://127.0.0.1:8426; include /etc/nginx/pleskmcp-proxy.inc; }
location ^~ /.well-known/oauth-protected-resource/plesk   { proxy_pass http://127.0.0.1:8426; include /etc/nginx/pleskmcp-proxy.inc; }
```

Inhalt von `pleskmcp-proxy.inc` (oder die Zeilen in jede location kopieren):

```nginx
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 300s;
proxy_buffering off;
client_max_body_size 16m;
```

`TRUSTED_PROXIES` muss die IP enthalten, von der der Proxy den Container anspricht (Standard `127.0.0.1`), sonst sieht der Dienst für Rate-Limits und Audit-Log die Proxy-IP statt der Client-IP.

Prüfung nach dem Deploy:

```
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/plesk/mcp
curl -s https://mcp.example.com/.well-known/oauth-authorization-server/plesk
curl -si https://mcp.example.com/plesk/mcp      # 401 mit WWW-Authenticate: Bearer resource_metadata=...
```

### Statusprüfung: die drei Modi

| `ACCOUNT_CHECK_MODE` | Funktionsweise | Benötigt |
|---|---|---|
| `customer_key` (Standard) | Beim Login legt der Dienst mit den Kundendaten einen Plesk-Secret-Key für diesen Kunden an und speichert ihn verschlüsselt (Fernet). Statusprüfung und Domainliste laufen damit im Kontext des Kunden. Kein Admin-Zugang im Dienst. | `DATA_ENCRYPTION_KEY`; Kunden müssen `secret_key create` aufrufen dürfen (im Log erscheint sonst ein klarer Hinweis, der Login schlägt mit 503 fehl). |
| `admin_key` | Ein Admin-Secret-Key (XML API, `plesk bin secret_key -c -ip-address <docker-host-ip>`) liest Kundenstatus und Webspaces. Der Code nutzt ihn ausschliesslich lesend. | `PLESK_ADMIN_API_KEY` |
| `login_only` | Keine Prüfung nach dem Login. Die Domainliste vom Login bleibt bis zum nächsten Login, Tokens laufen normal ab. | nichts |

Unabhängig vom Modus wird das Passwort immer nur gegen die XML API geprüft und nie gespeichert.

## Betrieb

CLI im Container (`docker exec pleskmcp pleskmcp <befehl>`):

| Befehl | Zweck |
|---|---|
| `revoke --login <plesk-login>` | Alle Tokens eines Logins widerrufen, gespeicherten Secret-Key löschen (auch in Plesk). **Nach einer Passwortänderung in Plesk nötig**, bestehende Tokens werden sonst nicht ungültig. |
| `revoke --all` | Alle Tokens widerrufen. |
| `accounts` / `clients` / `tokens` | Bekannte Konten, registrierte OAuth-Clients, aktive Tokens. |
| `prune` | Abgelaufene Einträge löschen. |
| `generate-key` | Neuen `DATA_ENCRYPTION_KEY` erzeugen. |
| `check [--sysuser X --domain Y --docroot Z]` | Erreichbarkeit der XML API und (optional) des SSH-Hilfsskripts prüfen. |

Daten: SQLite und Audit-Log liegen im Volume `/data` (`pleskmcp.sqlite3`, `audit.log`). Das Audit-Log geht zusätzlich auf stdout.

Sicherungen: `write_file`, `replace_in_file` und `move_file` mit `overwrite` kopieren die bisherige Datei nach `/var/www/vhosts/<abo>/.pleskmcp/backups/<domain>/<pfad>.<zeitstempel>` (die letzten 20 pro Datei). Papierkorb: `/var/www/vhosts/<abo>/.pleskmcp/trash/<id>/`. Beides gehört dem Kunden und zählt zu seinem Speicherplatz.

## Tools

| Tool | Beschreibung |
|---|---|
| `list_domains` | Domains des Kontos (Abonnements, Addon-Domains, Subdomains) mit Document Root |
| `list_dir` | Verzeichnis unterhalb des Document Root auflisten |
| `read_file` | Datei lesen (Text UTF-8 oder Base64), mit `offset` und Grössenlimit |
| `write_file` | Datei anlegen oder überschreiben, mit Sicherung; Base64 für Binärdateien |
| `replace_in_file` | Textstelle exakt ersetzen (mehrfache Treffer nur mit `replace_all`), mit Sicherung |
| `move_file` | Verschieben oder umbenennen innerhalb des Document Root |
| `delete_file` | In den Papierkorb verschieben (Ordner nur mit `recursive`) |
| `restore_file` | Papierkorb auflisten oder einen Eintrag wiederherstellen |
| `search_log` | access_log/error_log der Domain nach einem regulären Ausdruck durchsuchen (read-only) |

Scopes: `files:read` (Lesen) und `files:write` (Schreiben). Kein Tool für freie Shell-Befehle.

**Nicht umgesetzt: Datenbankabfragen.** Plesk legt DB-Benutzer pro Datenbank an, es gibt keinen kundenweiten Nur-Lese-Benutzer, und Datenbanknamen tragen kein Kundenpräfix für Wildcard-Grants. Eine saubere Lösung bräuchte pro Kunde einen vom Administrator gepflegten MySQL-Benutzer mit ausschliesslich SELECT auf die Datenbanken dieses Kunden plus Fernzugriff vom Docker-Host. Eine Lösung über den Plesk-DB-Admin mit SQL-Filter im Code wurde bewusst nicht gebaut.

## Anleitung für Kunden

Du brauchst nur deinen Plesk-Benutzernamen und dein Plesk-Passwort. Es werden ausschliesslich die Dateien deiner eigenen Abonnements freigegeben.

**Claude (claude.ai, Desktop, Mobile):** Einstellungen → Connectors → Eigenen Connector hinzufügen. Als URL `https://mcp.example.com/plesk/mcp` eintragen, speichern und auf Verbinden klicken. Es öffnet sich die Anmeldeseite des Dienstes: Plesk-Benutzername und Passwort eingeben, "Verbinden" bestätigen. Danach steht der Connector in Chats zur Verfügung.

**ChatGPT:** Einstellungen → Connectors → Connector erstellen (Entwicklermodus). Name vergeben, als MCP-Server-URL `https://mcp.example.com/plesk/mcp` eintragen, Authentifizierung OAuth, erstellen. Beim ersten Verbinden erscheint dieselbe Anmeldeseite.

**Claude Code:**
```
claude mcp add --transport http plesk https://mcp.example.com/plesk/mcp
```
Beim ersten Aufruf startet die Anmeldung im Browser.

**Verbindung trennen:** Den Connector in der jeweiligen App entfernen. Zusätzlich kann der Hoster alle Tokens eines Logins jederzeit widerrufen. Nach einer Passwortänderung in Plesk bitte beim Hoster melden oder den Connector neu verbinden; alte Tokens laufen spätestens nach 30 Tagen aus.

## Entwicklung

```
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Die Tests dürfen nicht als root laufen (das Hilfsskript verweigert das). Sie decken ab: Path-Traversal, Symlink-Ausbruch, Zugriff auf fremde Domain, abgelaufenes und widerrufenes Token, Refresh-Token-Rotation mit Reuse-Erkennung, abgelehnte Admin-, Reseller- und Zusatzbenutzer-Logins, gesperrte Konten, Rate-Limits, Client-ID-Metadata-Documents, Dynamic Client Registration, Scope-Prüfung und das Audit-Log ohne Secrets. Das Hilfsskript muss Python-3.6-kompatibel bleiben (CI prüft die Syntax).

Verwendete Bausteine des offiziellen MCP Python SDK (`mcp` 2.x): `OAuthAuthorizationServerProvider`, Authorization-, Token-, Registration- und Revocation-Handler, Protected Resource Metadata, Bearer-Middleware mit Audience-Prüfung (RFC 8707), PKCE S256. Client-ID-Metadata-Documents werden in `pleskmcp/auth/cimd.py` ergänzt, weil das SDK sie serverseitig noch nicht abholt.
