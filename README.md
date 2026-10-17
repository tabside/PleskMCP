# PleskMCP

Ein eigenständiger Remote-MCP-Server, mit dem Hosting-Kunden ihre AI-Tools (Claude, ChatGPT, Claude Code und andere MCP-Clients) per Connector mit den Webdateien, DNS-Zonen und (je nach Abo) Datenbanken ihrer eigenen Plesk-Abonnements verbinden. Anmeldung mit den Plesk-Zugangsdaten des Kunden, Autorisierung nach der MCP-Spezifikation (OAuth 2.1).

Zwei Kundengruppen werden bedient: ein günstiges Abo auf einem eigenen Serviceplan (im Beispiel "AI Hosting": Dateien und DNS lesen) und Bestandskunden, die über ein Plesk-Add-on (im Beispiel "KI-Zugang") zusätzlich Datenbankzugriff bekommen. Welche Abos dürfen und was, steht in `ACCESS_PROFILES` (Abschnitt "Freischaltung").

Dieses Repo ist öffentlich. Code, README, Tests und Beispiele enthalten keine echten Hostnamen, IPs, Domains, Tokens, Plan- oder Kundennamen, nur Platzhalter wie `plesk.example.com`, "AI Hosting" und "KI-Zugang". Echte Werte gehören ausschliesslich in Umgebungsvariablen (z.B. in Portainer).

## Sicherheitsmodell in Kürze

- **Kein Root.** Der Dienst hat weder Root-SSH noch das Root-Passwort noch den Plesk-DB-Admin-Zugang. Auf dem Plesk-Server gibt es einen eigenen, unprivilegierten SSH-Benutzer `pleskmcp` mit Key, dessen Key per `authorized_keys` auf ein Forced Command festgenagelt ist und der per sudoers genau einen Befehl ausführen darf: das Hilfsskript, und zwar nur als Mitglied der Plesk-Gruppe `psacln` (die Systembenutzer der Abonnements). root ist nicht in dieser Gruppe.
- **Datei- und Datenbankoperationen laufen unter dem Systembenutzer des Kunden.** Die Trennung zwischen Kunden übernimmt das Betriebssystem, neue Dateien gehören automatisch dem Kunden. Datenbankabfragen laufen lokal auf dem Plesk-Server mit dem Datenbankbenutzer des Kunden, nie mit Admin-Rechten.
- **Kein Plesk-Admin-Schreibzugriff.** Die XML API wird im Kontext des Kunden benutzt (eigener Secret-Key pro Kunde). Ein optionaler Admin-Key dient ausschliesslich lesend (Kontostatus im Modus `admin_key`, Auflösung von Plan-Namen).
- **Zuordnung serverseitig.** Login → Abonnements → Domains → Systembenutzer → Document Root wird read-only aus der Plesk XML API ermittelt. Der Client übergibt nur Domainname und relativen Pfad. Die Domain wird gegen die Liste des angemeldeten Kunden und gegen das Profil des Abos geprüft, bevor irgendetwas ausgeführt wird.
- **Pfade werden im Hilfsskript abgesichert:** normalisiert, auf den Document Root begrenzt, jede Komponente per `lstat` geprüft, Symlinks werden abgelehnt, Ziel ausserhalb wird abgelehnt. Keine Shell-Strings, alle Parameter gehen als JSON über stdin.
- **Zugangsdaten gehen nie an die KI.** Geschützte Dateien (`wp-config.php`, `.env`, ...) werden mit geschwärzten Werten geliefert, Schlüsseldateien gar nicht; geschwärzte Werte können nicht zurückgeschrieben werden. Datenbank-Zugangsdaten werden auf dem Server aus der Konfiguration gelesen oder liegen verschlüsselt (Fernet) in Postgres und werden nur dem Auftrag auf dem Server übergeben. Sensible Spalten in Abfrageergebnissen werden geschwärzt.
- **Nur Kunden-Hauptlogins.** Admin, Reseller und Zusatzbenutzer werden abgewiesen.
- **Passwörter werden nie gespeichert und nie geloggt.** Tokens liegen nur als SHA-256-Hash in Postgres. Access-Tokens sind kurzlebig (Standard 30 Minuten), Refresh-Tokens rotieren, die Wiederverwendung eines alten Refresh-Tokens widerruft die ganze Token-Familie.
- **Statusprüfung pro Tool-Aufruf** (kurz gecacht): gelöschte oder gesperrte Plesk-Konten fallen durch, gesperrte Abonnements verschwinden aus der Domainliste, Abos ohne gebuchtes Profil werden abgelehnt.
- **Jede Änderung ist rückgängig zu machen.** Sicherungen (Dateiversionen, DNS-Exporte, Datenbank-Dumps) und Papierkorb liegen im Abonnement unter `/var/www/vhosts/<abo>/.pleskmcp/` (0700), ausserhalb jedes Document Root. Aufbewahrung und Grössenbudget werden automatisch eingehalten, das Disk-Kontingent des Abos wird vom Dienst selbst durchgesetzt.
- **Audit-Log** (JSON Lines) für jede Anmeldung und jeden schreibenden Aufruf: Zeit, Plesk-Login, Domain, Pfad bzw. Tabelle, Tool, Client, Request-ID. Keine Dateiinhalte, keine SQL-Werte, keine Secrets.
- **Rate-Limits** pro Login (Aufrufe, Schreibzugriffe, geschriebene Bytes) und pro Login/IP für Anmeldeversuche, alle in Redis und damit über alle api-Replikas gültig.

## Architektur

```
Client (Claude, ChatGPT, ...)  --HTTPS-->  Reverse-Proxy  -->  api (MCP, OAuth, /account)
                                                                 |  Jobs (Redis-Queue)
                                                                 v
                                            worker ... worker  --SSH (pleskmcp, forced command)-->  Plesk-Server
                                                 ^                 sudo -u <sysuser> pleskmcp-helper
                                            scheduler (Leader-Lock)
                                        redis (Queue, Limits, Caches)   postgres (Clients, Tokens, Konten, DB-Zugangsdaten)
```

Ein Image, mehrere Startbefehle (`pleskmcp api|worker|scheduler|migrate`):

| Dienst | Aufgabe | Skalierung |
|---|---|---|
| `api` | MCP-Endpunkt (Streamable HTTP, zustandslos), OAuth-Endpunkte, Login-Seite, `/account`, `/healthz`, `/readyz`, `/metrics`. Führt keine SSH-Aufrufe aus, sondern stellt pro Tool-Aufruf einen Job in die Queue und wartet bis `TOOL_SYNC_WAIT` (25 s) auf das Ergebnis. Dauert es länger, liefert das Tool eine `job_id`; `job_status(job_id)` holt Status und Ergebnis (nur für den eigenen Login, Ergebnisse verfallen nach `JOB_RESULT_TTL`). | `API_WORKERS` Prozesse pro Container; mehrere Container hinter einem Load-Balancer (Port-Mapping dann entfernen). |
| `worker` | Nimmt Jobs aus der Queue, führt das Hilfsskript per SSH aus (eine Verbindung, mehrere Kanäle parallel, Reconnect, Kanal-Timeout). `SSH_MAX_CONCURRENCY` (8) parallele Helper-Läufe pro Worker. Heartbeat in Redis und als Datei für den Healthcheck. | `WORKER_REPLICAS` |
| `scheduler` | Periodische Aufgaben: hängende Jobs zurückstellen (jede Minute), abgelaufene Datenbankzeilen löschen (stündlich), Kontingent- und Plan-Cache auffrischen (`QUOTA_CACHE_TTL`), Aufbewahrungsjob pro Abo mit niedriger Priorität (`RETENTION_INTERVAL_HOURS`, 6 h), bei `SIGNUP_ENABLED` Zahlungsprüfung offener Bestellungen (5 min) und Lebenszyklus aktiver Abos (stündlich). Genau eine aktive Instanz über einen Leader-Lock in Redis; weitere Instanzen stehen bereit. | 1 (weitere als Standby) |
| `migrate` | Einmaliger Container pro Deploy: `pleskmcp migrate` (Alembic). api und worker starten erst danach. | |
| `redis` | Queue, Rate-Limits, Concurrency-Zähler, Caches, Sessions der Kontoseite. AOF-Persistenz, `maxmemory` mit `noeviction`, Passwort, kein veröffentlichter Port. | |
| `postgres` | Clients, Tokens, Auth-Codes, Konten, Login-Versuche, verschlüsselte Datenbank-Zugangsdaten. Passwort, kein veröffentlichter Port. | |

**Queue und Fairness.** Jeder Tool-Aufruf ist ein Job (Login, Domain, Operation, Request-ID). Die Queue besteht aus Teil-Queues pro Login (hohe und niedrige Priorität), aus denen ein Lua-Skript im Round-Robin zieht; pro Login laufen höchstens `LOGIN_MAX_CONCURRENCY` (2) Jobs gleichzeitig. Ein Kunde unter Dauerlast kann andere damit nicht ausbremsen (Test `tests/test_queue.py`, Lasttest `tests/load/run_load.py`). Die Queue ist eine eigene, schlanke Umsetzung auf Redis statt arq: arq kennt keine Teil-Queues pro Login mit Round-Robin, und genau das ist hier die Anforderung. Nach einem Worker-Absturz stellt der Scheduler laufende Jobs zurück; schreibende Jobs tragen eine Request-ID, das Hilfsskript erkennt eine Wiederholung an einem Marker (`.pleskmcp/idem/`) und liefert das gespeicherte Ergebnis statt die Operation erneut auszuführen. Zeitlimits: `signal.alarm` im Hilfsskript (`HELPER_TIME_LIMIT` 30 s, für Hintergrundjobs wie Log-Suche, Aufräumen oder Datenbank-Restore `JOB_TIME_LIMIT` 300 s), zusätzlich schliesst der Worker den SSH-Kanal bei Überschreitung.

**Betrieb.** JSON-Logs auf stdout (`LOG_FORMAT=text` zum Lesen in der Konsole), `/healthz` (Prozess lebt), `/readyz` (Postgres, Redis, Anzahl lebender Worker), optional `/metrics` im Prometheus-Format (Jobs pro Operation und Status, Queue-Länge, laufende Jobs, lebende Worker; keine Logins, Domains oder Pfade als Labels). SIGTERM beendet api, worker und scheduler sauber (laufende Jobs werden fertig).

## Freischaltung und Rechte pro Plan bzw. Add-on

Zugang gibt es nur für Abonnements, deren Serviceplan oder eines ihrer Add-on-Pläne in `ACCESS_PROFILES` steht. Alle anderen Abos erscheinen nicht in `list_domains`; Aufrufe darauf werden mit "KI-Zugang für dieses Abo nicht gebucht" abgelehnt. Die Prüfung läuft pro Domain bei jedem Aufruf (Plan-Zuordnung gecacht, `PLAN_CACHE_TTL` 10 min).

`ACCESS_PROFILES` ist JSON (Umgebungsvariable oder Datei in `ACCESS_PROFILES_FILE`), pro Plan-/Add-on-Name oder -GUID:

```json
{
  "AI Hosting": {"scopes": ["files:read", "files:write", "dns:read"],
                 "store_max_percent": 10, "store_max_bytes": 268435456,
                 "backup_retention_days": 14, "trash_retention_days": 14,
                 "tool_calls_per_minute": 60, "tool_writes_per_minute": 30, "write_bytes_per_hour": 104857600},
  "KI-Zugang": {"scopes": ["files:read", "files:write", "dns:read", "db:read", "db:admin"],
                "max_databases_created": 3}
}
```

Felder: `scopes` (`files:read`, `files:write`, `dns:read`, `dns:write`, `db:read`, `db:write`, `db:admin`), `store_max_percent`, `store_max_bytes`, `backup_retention_days`, `trash_retention_days`, `tool_calls_per_minute`, `tool_writes_per_minute`, `write_bytes_per_hour`, `max_databases_created`. Fehlende Felder nehmen die Defaults aus der Umgebung. Passen mehrere Profile auf ein Abo (Plan plus Add-on), gilt pro Wert das grosszügigere (Scopes vereinigt).

Der Token behält die beim Login erteilten Scopes; die effektiven Rechte sind die Schnittmenge aus Token-Scopes und Profil des Abos. Eine Verbindung mit `db:read` im Token darf auf einem "AI Hosting"-Abo trotzdem keine Datenbank lesen.

**Plan-Namen oder GUIDs.** Die XML API zeigt einem Kunden für sein Abo nur die GUIDs von Plan und Add-ons (`webspace get`, Dataset `subscriptions`); `service-plan get` und `service-plan-addon get` liefern Kunden `1006`. Namen kann der Dienst nur mit `PLESK_ADMIN_API_KEY` auflösen (lesend, gecacht). Ohne Admin-Key müssen die Schlüssel in `ACCESS_PROFILES` die GUIDs sein (`plesk bin service_plan --list` bzw. `service_plan_addon --list` zeigen sie). Beides darf gemischt werden.

## Was Kunden selbst rückgängig machen

| Was | Wie |
|---|---|
| Dateiänderung | Jede schreibende Operation legt vorher eine Version an (`.pleskmcp/versions/<id>/` mit `meta.json`: Domain, Docroot, Pfad, Grösse, Zeitpunkt, Tool, Request-ID). `list_versions(domain, path)` zeigt sie, `restore_version` spielt eine zurück und sichert den aktuellen Stand. Auch gelöschte Dateien, solange eine Version existiert. Dateien über `BACKUP_MAX_FILE_BYTES` (20 MB) werden nicht gesichert (`backup: null, backup_skipped: "too_large"`). |
| Gelöschte Datei oder Ordner | `delete_file` verschiebt in den Papierkorb (`.pleskmcp/trash/<id>/`), `restore_file` stellt wieder her. |
| DNS-Änderung | Vor jeder Änderung ein Export der ganzen Zone (`.pleskmcp/dns/<domain>/<id>.json`); `dns_restore_zone` listet Exporte, zeigt die Unterschiede und setzt die Zone zurück (SOA/NS bleiben gesperrt). |
| Datenbankänderung | `db_execute` sichert die betroffenen Tabellen, `db_apply_schema` und `db_drop` die ganze Datenbank (`.pleskmcp/db/<database>/<id>.sql.gz`); `db_restore` spielt einen Dump zurück und sichert vorher den aktuellen Stand. Eine gelöschte Datenbank: `db_create` mit demselben Suffix, dann `db_restore` mit dem Voll-Dump. |
| "Mach die letzten Änderungen rückgängig" | `list_changes(domain, since, limit)` listet alle schreibenden Änderungen (Dateien, Papierkorb, DNS, Datenbank), neueste zuerst, mit den IDs für die Restore-Tools. |

Alte Sicherungen aus Version 0.1 (`.pleskmcp/backups/<domain>/<pfad mit __>.<zeitstempel>`) werden beim ersten Zugriff auf `list_versions`/`list_changes` in die neue Ablage migriert (Pfad aus dem Dateinamen rekonstruiert, als `migrated: true` markiert).

## Speicherkontingent

Sicherungen und Papierkorb zählen zum Speicherplatz des Kunden. Damit sie das Kontingent nie sprengen:

- Aufbewahrung läuft im Hilfsskript nach jeder schreibenden Operation und als Scheduler-Job (alle `RETENTION_INTERVAL_HOURS`). Werte aus dem Profil des Abos, sonst Defaults: Papierkorb älter als `trash_retention_days` (30) endgültig löschen; Sicherungen älter als `backup_retention_days` (30) löschen, die neueste Sicherung pro Datei/Tabelle aber mindestens `BACKUP_MIN_KEEP_DAYS` (7) behalten; Gesamtgrösse von `.pleskmcp` auf `store_max_percent` (10 %) des Disk-Kontingents begrenzen, bei unbegrenztem Kontingent `store_max_bytes` (1 GB). Älteste Einträge zuerst, die neueste Sicherung pro Datei zuletzt.
- Kontingent und Belegung liest der Scheduler über die XML API (`webspace get`, `limits/disk_space` und `gen_info/real_size`), legt sie in Redis ab (`QUOTA_CACHE_TTL`) und die api gibt sie dem Job als Limits mit.
- **Der Dienst setzt das Kontingent selbst durch**, weil der Plesk-Plan Überbeanspruchung erlaubt (Abo wird nicht gesperrt, nur benachrichtigt): eine Schreiboperation, die die Belegung über das Kontingent heben würde, räumt den Store bis aufs Minimum auf, prüft genau einmal neu und wird sonst mit `quota_exceeded` (Belegung und Limit) abgelehnt. `EDQUOT`/`ENOSPC` vom Dateisystem werden gleich behandelt.
- `storage_status(domain)` zeigt Belegung Webspace, Belegung `.pleskmcp` nach Kategorie, Kontingent, verbleibenden Platz, Profil und Rate-Limit-Stand. `purge_store(domain, what, older_than_days, confirm)` räumt gezielt auf (ohne `confirm=true` nur Vorschau).

## Schutz von Zugangsdaten und Bestandsseiten

- **Geschützte Dateien** (`PROTECTED_FILES`, Glob-Muster relativ zum Docroot; Standard `wp-config.php`, `.env`, `.env.*`, `config/database.php`, `configuration.php`, `app/etc/env.php`, `*.pem`, `*.key`, `.htpasswd`, `.git/config`): `read_file` liefert sie mit geschwärzten Werten (`define('DB_PASSWORD', '***')`, `APP_KEY=***`, Passwörter in URLs), `*.pem`/`*.key` gar nicht. Schreiben und Ersetzen sind erlaubt, aber ein `***` an einer Secret-Stelle bricht mit klarer Meldung ab; der Rest der Datei bleibt bearbeitbar. `list_dir` markiert geschützte Dateien. `search_log` schwärzt Zeilen mit `password=`, `token=`, `Authorization:` und ähnlichen Mustern.
- **Fremde Datei-Besitzer** (z.B. von früheren Migrationen): schlägt ein Schreiben an Rechten fehl, kommt `not_owner` mit Pfad und Besitzer statt `io_error`; `list_dir` zeigt `owner_ok: false`. Der Hoster prüft mit `pleskmcp report-ownership --domain X` oder `--all` (read-only Helper-Befehl als Systembenutzer, meldet nicht lesbare Ordner separat, ändert nichts).

## Datenbanken

Nur für Profile mit db-Scopes. Abfragen laufen über das `mysql`-CLI auf dem Plesk-Server (MariaDB), als Systembenutzer des Abos, mit `--defaults-extra-file` (temporäre Datei 0600 im Store, sofort gelöscht), Host nur `localhost`, Zeitlimit (`max_statement_time` bzw. `MAX_EXECUTION_TIME`, `DB_QUERY_TIME_LIMIT`) und Zeilenlimit (`DB_MAX_ROWS`). Nutzbar sind nur Datenbanken, die die XML API dem Kunden als eigene zeigt (`database get-db`) oder deren Zugangsdaten auf dem Server in der Konfiguration der Seite stehen.

**Zugangsdaten**, in dieser Reihenfolge: (1) vom Dienst angelegte Datenbanken (`db_create`), (2) aus der Konfiguration der Seite, vom Hilfsskript direkt auf dem Server gelesen (`wp-config.php`, `.env` mit `DB_*`, `configuration.php`, `app/etc/env.php`, `config/database.php`; `DB_CONFIG_SOURCES`), (3) vom Kunden auf der `/account`-Seite pro Datenbank hinterlegt (verschlüsselt in Postgres, nur an den Job übergeben, nie angezeigt). Job-Anfragen in Redis tragen diese Werte nur bis zum Abschluss des Jobs; mit dem Ergebnis wird die Anfrage gelöscht.

| Tool | Scope | Verhalten |
|---|---|---|
| `db_list(domain)` | `db:read` | Datenbanken des Abos mit Grösse und Herkunft der Zugangsdaten (`service`, `config`, `stored`, `missing`). |
| `db_schema(domain, database, table=None)` | `db:read` | Tabellen bzw. Spalten. |
| `db_query(domain, database, sql)` | `db:read` | Ein Statement, nur `SELECT`/`SHOW`/`DESCRIBE`/`EXPLAIN`. Serverseitig `START TRANSACTION READ ONLY` ... `ROLLBACK`. Blockiert: `INTO OUTFILE/DUMPFILE`, `LOAD_FILE`, `SLEEP`, `BENCHMARK`, Variablen-Zuweisungen, Mehrfach-Statements, ausführbare Kommentare (`/*! */`), Sperr-Lesen. Spalten aus `DB_REDACT_COLUMNS` werden geschwärzt. |
| `db_execute(domain, database, sql, confirm)` | `db:write` | Ein `INSERT`/`UPDATE`/`DELETE` auf bestehende Tabellen, kein DDL. Ohne `confirm`: Vorschau mit `ROLLBACK` und betroffener Zeilenzahl. Mit `confirm`: `mysqldump` der betroffenen Tabellen, dann ausführen. Abbruch über `DB_MAX_AFFECTED_ROWS`. Audit ohne SQL-Werte. |
| `db_apply_schema(domain, database, sql, confirm)` | `db:admin` (ohne `db:admin` nur für vom Dienst angelegte Datenbanken) | `CREATE TABLE`, `ALTER TABLE`, `CREATE INDEX`, `DROP INDEX`, `RENAME TABLE`. Kein `DROP TABLE`/`DATABASE`, keine Benutzer- oder Rechteverwaltung. Vorher kompletter Dump, Vorschau ohne `confirm`. |
| `db_restore(domain, database, dump_id, confirm)` | `db:write`, Voll-Dumps `db:admin` | Dumps auflisten, Vorschau, zurückspielen (vorher aktuellen Stand dumpen). |
| `db_create(domain, name_suffix, confirm, write_config_path)` | `db:admin` | Neue Datenbank mit eigenem Benutzer über die XML API im Kundenkontext. Name = erstes Label des Abos + bereinigter Suffix (a-z, 0-9, _). Passwort zufällig (40 Zeichen). Zugangsdaten verschlüsselt in Postgres und als Datei `/var/www/vhosts/<abo>/private/pleskmcp-db/<name>.env` (0600, Ordner 0700, Systembenutzer), optional zusätzlich als `DB_*`-Werte in eine Datei im Docroot (`write_config_path`, danach geschützt). Werte nie im Ergebnis, nie im Audit-Log. Limit `max_databases_created` aus dem Profil, Plesk prüft `max_db`. Nur mit `DB_MANAGEMENT_ENABLED=true`. |
| `db_drop(domain, database, confirm)` | `db:admin` | Nur vom Dienst angelegte Datenbanken (sonst Ablehnung mit Hinweis auf Plesk). Voll-Dump in den Store, dann Datenbank und Benutzer über die XML API löschen, gespeicherte Zugangsdaten und die Datei entfernen. |

## Self-Signup "AI Hosting"

Mit `SIGNUP_ENABLED=true` nimmt die api Bestellungen für den Plan "AI Hosting" von der Website an, stellt die Rechnung über reBill/bexio, schaltet nach Zahlungseingang automatisch frei und kümmert sich um Sperrung, Löschung und Domain-Verlängerung. Alles läuft im bestehenden Stack: die api liefert die Endpunkte, der Scheduler die periodischen Prüfungen, Postgres hält die Bestellungen (`signup_orders`, `signup_events`), Redis Sperren, Formular-Nonces und Limits. Standardmässig ist das Feature aus.

### Ablauf

```
Website /ki-hosting/bestellen/  --POST /signup-->  api: Prüfungen, Bestellung (awaiting_payment)
                                                    |-- bexio: Kontakt per E-Mail suchen oder anlegen
                                                    |-- reBill: Abo (jährlich, lead_months 1, run_now) -> erste Rechnung sofort
                                                    `-- Zammad: Ticket in "Web TAB", Kunde = Besteller, nur interne Notizen
scheduler alle 5 min:  offene Bestellungen -> neueste Rechnung des Abos (reBill) -> Status in bexio (9 = bezahlt)
   bezahlt -> Freischaltung (Lock pro Bestellung, jeder Schritt nur einmal):
     1. neue Domain: Owner-Kontakt aus den Formulardaten bei Netim anlegen, Domain 1 Jahr registrieren, Auto-Renew aus
     2. Plesk: Kunde (Login aus dem Namen, kollisionsfrei) und Abonnement mit Plan "AI Hosting" (Zufallspasswort, nirgends gespeichert)
     3./4. Willkommensmail: Einmal-Login-Link statt Passwort, Panel-URL, DNS-Angaben, KI-Anleitung, Kontoseite
     5. Status active, interne Zammad-Notiz "aktiviert" mit Abonnement-ID
scheduler stündlich:  aktive und gesperrte Bestellungen (Rechnungen, Kündigung, Löschfrist, Domain-Ablauf)
```

Zustände einer Bestellung:

```
awaiting_payment --bezahlt--> activating --ok--> active --Rechnung 10 Tage überfällig--> suspended --bezahlt--> active
                                  |                 |--Abo in reBill deaktiviert, Laufzeit abgelaufen--> suspended
                                  |                                                                        |--60 Tage--> pending_deletion --Backup bestätigt--> deleted
                                  |                                                                                        (SIGNUP_DELETE_BACKUP_MODE=none: direkt deleted)
                                  `--Fehler--> awaiting_payment (nächster Versuch)  --SIGNUP_MAX_ATTEMPTS erreicht oder nicht wiederholbar--> needs_attention --Admin "Erneut versuchen"--> vorheriger Status
```

`needs_attention` bekommt immer eine interne Zammad-Notiz. Jeder Zustandswechsel steht als Ereignis in `signup_events` und im Audit-Log (nur Bestell-ID, Codes und externe IDs, keine Personendaten).

### Endpunkte

| Pfad | Zweck |
|---|---|
| `GET /signup/config` | Preisliste, Länder, AGB-Version (CORS für `SIGNUP_ALLOWED_ORIGINS`) |
| `GET /signup/token` | Formular-Token: HMAC über Zeitstempel und Nonce, zustandslos; gilt frühestens nach `SIGNUP_MIN_FILL_SECONDS`, höchstens `SIGNUP_TOKEN_MAX_AGE`, einmalig (Nonce in Redis) |
| `GET /signup/check-domain?domain=` | Live-Verfügbarkeit bei Netim (nur bestellbare Endungen, 60 s Cache, Limit pro IP) |
| `POST /signup` | Bestellung (JSON oder Formular-POST). Schutz: nur HTTPS, Origin-Prüfung, Honeypot-Feld `website` (Antwort sieht wie Erfolg aus, nichts wird angelegt), Token, Limits pro IP (`SIGNUP_RATE_LIMIT_IP`/h) und pro E-Mail (`SIGNUP_RATE_LIMIT_EMAIL`/Tag), Validierung aller Felder serverseitig. Antworten verraten nie, ob eine E-Mail-Adresse schon Kunde ist. |
| `GET /signup/thanks/{id}` | eingebaute Bestätigungsseite (wenn `SIGNUP_SUCCESS_URL` leer ist) |
| `GET /signup/welcome/{token}` | Einmal-Link aus der Willkommensmail: erzeugt per XML API `server create_session` einen Session-Token für den Kunden und leitet auf `rsession_init.php` um; danach ist der Link verbraucht. Abgelaufen oder verbraucht: Hinweis auf "Passwort vergessen" (`get_password.php`). `PLESK_LOGIN_LINK_MODE=reset_page` verlinkt stattdessen direkt die Passwort-vergessen-Seite. |
| `GET /signup/admin` | Übersicht aller Bestellungen (HTTP Basic, `SIGNUP_ADMIN_USER`/`SIGNUP_ADMIN_PASSWORD`): Status, Rechnung, Plesk, Netim, Verlauf; Aktionen "Erneut versuchen", "Jetzt prüfen", "Backup erledigt, löschen" |

CLI: `pleskmcp signup-orders [--status S]` listet Bestellungen als JSON-Zeilen (ohne Tokens).

### Domains

Eigene Domain: Format geprüft, dann `webspace get`, `site get` und `site-alias get` per Name im Admin-Kontext; existiert die Domain irgendwo in Plesk, wird die Bestellung abgelehnt. Offene Bestellungen anderer Kunden für dieselbe Domain werden ebenfalls abgelehnt; dieselbe E-Mail mit derselben Domain liefert die bestehende Bestellung zurück (keine zweite Rechnung).

Neue Domain: nur Endungen mit `orderable: true` in der Preisliste (`pleskmcp/signup/data/domains.json`, überschreibbar mit `SIGNUP_PRICE_LIST_FILE`; dieselbe Datei rendert `/domains/` auf der Website). `.swiss` steht mit `orderable: false` drin und erscheint als "auf Anfrage". Pro Endung listet `owner_fields`, welche Formularfelder für den Netim-Owner-Kontakt zusätzlich Pflicht sind (bei allen bestellbaren Endungen `phone`, weil Netims `StructContact` die Telefonnummer international verlangt; Netim liefert keine API für diese Regeln, die Liste wird von Hand gepflegt). Netim-Aufrufe (REST 1.0): `POST /session/`, `GET /domain/{d}/check/`, `POST /contact/` (`isOwner: 1`, `bodyForm` IND oder ORG), `POST /domain/{d}/` (idOwner/idAdmin/idTech/idBilling, duration 1, ns1..ns5), `PATCH /domain/{d}/preference/` (`auto_renew` = 0), `GET /operation/{id}`, `GET /domain/{d}/info/`, `PATCH /domain/{d}/renew/`. Eine Registrierung mit Status `Pending` wird stündlich nachgeprüft; `Failed` führt zu `needs_attention`.

Verlängerung: `SIGNUP_DOMAIN_RENEW_DAYS_BEFORE` (30) Tage vor Ablauf verlängert der Scheduler die Domain um ein Jahr, wenn die neueste Rechnung bezahlt und das Abo aktiv ist. Sonst wird nicht verlängert und das Ticket bekommt einmal pro Ablaufdatum eine Notiz.

### reBill: erste Rechnung sofort, Folgerechnung einen Monat vorher

Verifiziert am reBill-Quelltext (`app/Http/Controllers/Api/SubscriptionApiController.php`, `app/Models/RecurringInvoice.php::scheduleAfterRun`, `app/Jobs/ProcessRecurringInvoiceJob.php`):

* `run_now: true` mit `start_date` = heute: der Controller setzt den Lock `recurring:processing:{id}` und dispatcht `ProcessRecurringInvoiceJob` sofort in die Queue (Antwort `first_invoice_queued: true`). Die Rechnung wird in bexio erstellt, ausgestellt und versendet (`auto_issue`/`auto_send` sind fest `true`), ohne auf den täglichen Lauf um 07:00 zu warten. Voraussetzung: der Queue-Worker von reBill läuft.
* `lead_months: 1`: beim ersten Lauf ist `periodStart` = Laufdatum (heute), `periodEnd` = heute + 1 Jahr - 1 Tag; `nextRun` = Beginn der nächsten Periode minus `lead_months`. Die Folgerechnung wird also einen Monat vor Beginn der neuen Jahresperiode erstellt und gesendet; `next_period_start` in der API-Antwort ist der Beginn dieser Periode, daraus berechnet der Dienst `period_end`.
* Positionen: `AI Hosting {{year}}/{{nextYear}}` (Textvariablen von reBill) zu CHF 60.00 und bei neuer Domain `Domain <name>` zum Listenpreis; `mwst_type 0` (inkl. MwSt), `currency_id 1`. Steuer, Konto und Einheit kommen aus den Organisationsdefaults von reBill (müssen dort gesetzt sein, sonst 422).
* `external_ref` = `aihosting-<bestell-id>`: ein zweiter Aufruf liefert 409 mit dem bestehenden Abo, die Bestellung bleibt eindeutig.

Zahlungsstatus kommt direkt aus bexio (`GET /2.0/kb_invoice/{id}`, `kb_item_status_id`; `BEXIO_PAID_STATUS_IDS` Standard 9, `BEXIO_CANCELLED_STATUS_IDS` Standard 19), nicht aus dem täglichen Payment-Sync von reBill. Die Rechnungs-ID liefert `GET /subscriptions/{ref}` (`invoices[]`, neueste zuerst nach `created_at`).

### Sperren, Löschen, Kündigung

* Neueste Rechnung des Abos offen und `SIGNUP_SUSPEND_AFTER_DAYS` (10) Tage nach Fälligkeit: `customer set status 16` (gesperrt durch Administrator), Notiz. Zahlung danach: `status 0`, Notiz.
* Kündigung: das Abo wird in reBill deaktiviert (`is_active: false`). Der Dienst merkt sich `cancelled_at`, sperrt am Ende der bezahlten Laufzeit (`period_end`) und löscht `SIGNUP_DELETE_AFTER_DAYS` (60) Tage später.
* Löschung: `SIGNUP_DELETE_BACKUP_MODE=manual` (Standard) setzt `pending_deletion`, schreibt eine Notiz ("Backup erstellen") und wartet auf die Bestätigung in der Admin-Übersicht; `none` löscht direkt. Gelöscht wird `webspace del` plus `customer del`.
* Schutz gegen Doppelverarbeitung: Redis-Lock `signup:lock:<id>` (10 min) um jede Bestellung, der Scheduler läuft ohnehin nur als Leader.

### Einrichtung

1. Plesk: eigenen Admin-Secret-Key mit Schreibrechten anlegen (`plesk bin secret_key -c -ip-address <docker host ip> -description "PleskMCP signup"`) als `PLESK_SIGNUP_API_KEY`; der bestehende `PLESK_ADMIN_API_KEY` bleibt lesend. Plan "AI Hosting" muss existieren (`SIGNUP_PLAN_NAME`), `PLESK_SIGNUP_IP` ist die IP, auf der Abos angelegt werden. `ACCESS_PROFILES` braucht einen Eintrag für den Plan, sonst hat der neue Kunde keinen KI-Zugang.
2. reBill: Token für die Organisation (Settings → API tokens) als `REBILL_API_TOKEN`, `REBILL_API_URL` = `https://<rebill>/api/v1`. Organisationsdefaults für Steuer, Konto und Einheit setzen; Plan muss `yearly` erlauben.
3. bexio: API-Token mit Kontakt lesen/schreiben und Rechnungen lesen (`BEXIO_API_TOKEN`), `BEXIO_USER_ID` für neu angelegte Kontakte.
4. Netim (optional, sonst nur eigene Domains): `NETIM_LOGIN`/`NETIM_SECRET`, Kontakt-IDs Admin/Tech/Billing (isOwner 0), `NETIM_NAMESERVERS`.
5. Zammad: Token eines Agenten mit Rechten auf die Gruppe (`ZAMMAD_GROUP`, Standard "Web TAB").
6. SMTP und Absender (`SMTP_*`, `MAIL_FROM`), AGB (`SIGNUP_TERMS_VERSION`, `SIGNUP_TERMS_URL`), Website-Origin (`SIGNUP_ALLOWED_ORIGINS`), Bestätigungsseite (`SIGNUP_SUCCESS_URL`), Admin-Zugang (`SIGNUP_ADMIN_USER`/`-PASSWORD`).
7. `pleskmcp migrate` (Migration `0002_signup`), Stack neu starten. `/readyz` zeigt `"signup": "enabled"`.
8. Website: Dateien aus `website/` ins Website-Repo übernehmen (`website/README.md`), `SIGNUP_BASE` in `assets/signup.js` auf die `PUBLIC_BASE_URL` setzen, `assets/domains.json` mit der Preisliste gleich halten.

Alle Variablen mit Defaults stehen in `.env.example` (Abschnitt Self-Signup). Fehlt bei `SIGNUP_ENABLED=true` eine Pflichtvariable, startet der Dienst nicht und nennt sie.

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
| Kontingent und Belegung | `webspace get` mit Dataset `limits` liefert `disk_space` in Bytes (`-1` = unbegrenzt) und `overuse` (`not_suspend_notify`: Überbeanspruchung erlaubt), Dataset `gen_info` liefert `real_size` (belegte Bytes). Beides im Kundenkontext lesbar. |
| Plan und Add-ons eines Abos | Dataset `subscriptions` liefert `subscription/plan/plan-guid` je Plan und Add-on, nur GUIDs. `service-plan get` und `service-plan-addon get` liefern Kunden `1006`; Namen gibt es nur mit Admin-Key. |
| Datenbanken lesen | `database get-db` mit `<filter><webspace-name>` funktioniert im Kundenkontext und zeigt die Datenbanken des Abos. Der Filter `<webspace-id>` löst einen Parser-Fehler `1014` aus. |
| Datenbanken anlegen/löschen im Kundenkontext (`add-db`, `add-db-user`, `del-db`) | **Noch nicht am Server verifiziert.** Belegt ist nur das Rechtemodell: Plesk kennt für Abos keinen separaten Schalter "Datenbanken verwalten"; die Datenbankverwaltung hängt am Plan-Limit `max_db` (Testkunde: 10), dazu `remote_db_connection` und `select_db_server`. Der XML-API-Aufruf selbst konnte aus der Entwicklungsumgebung nicht ausgeführt werden (schreibender Zugriff auf den Produktionsserver war blockiert). Vorgehen: `scripts/verify-db-api.sh` mit einem Testkunden ausführen, Fehlercodes für Plan-Limit und fehlende Berechtigung hier eintragen und erst dann `DB_MANAGEMENT_ENABLED=true` setzen. Bis dahin ist `db_create`/`db_drop` abgeschaltet; alle übrigen Datenbank-Tools sind unabhängig davon nutzbar. Der Code behandelt `1006` als fehlende Berechtigung (Meldung an den Kunden mit Hinweis auf den Hoster) und `1023` bzw. Texte mit "limit" als Plan-Limit. |

## Einrichtung auf dem Plesk-Server

Voraussetzung: Linux-Plesk, Python 3.6 oder neuer (`/usr/libexec/platform-python` auf CloudLinux/RHEL 8 reicht), für Datenbank-Tools `mysql` und `mysqldump` im Pfad.

1. Auf dem Docker-Host ein Schlüsselpaar erzeugen (ohne Passphrase):
   ```
   ssh-keygen -t ed25519 -N "" -f pleskmcp_ssh_key -C pleskmcp
   ```
2. `server-setup/` und `helper/pleskmcp_helper.py` auf den Plesk-Server kopieren (oder das Repo klonen) und als root installieren:
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
   Erwartet: `{"ok": true, "result": {"uid": ..., "home": "/var/www/vhosts/example.com", "version": 2, ...}}`.

**Nach jedem Deploy einer neuen Version:** auf dem Plesk-Server `git pull` (bzw. die neuen Dateien kopieren) und `install.sh` erneut ausführen, damit das Hilfsskript zur api passt. Die Version des Hilfsskripts steht in der Antwort von `ping`.

Hinweise:
- Das Hilfsskript prüft bei jedem Aufruf, dass der übergebene Document Root im Home des Systembenutzers (`/var/www/vhosts/<abo>`) liegt und ihm gehört. Ein fremder Docroot wird abgelehnt, selbst wenn der Dienst ihn übergeben würde.
- Logs der Domain (`search_log`) werden aus `/var/www/vhosts/<abo>/logs/` bzw. für Addon-Domains aus `/var/www/vhosts/system/<domain>/logs/` gelesen, sofern der Systembenutzer sie lesen darf; höchstens `LOG_MAX_SCAN_BYTES` (200 MB, gz unkomprimiert gezählt), sonst `truncated: true`.

## Deployment (Docker, Portainer)

Das Image wird bei jedem Push auf `main` von GitHub Actions gebaut und nach `ghcr.io/tabside/pleskmcp:latest` veröffentlicht (`.github/workflows/docker-publish.yml`; Tests, Lint, Helper-Syntaxprüfung und ein Smoke-Test der drei Startbefehle laufen vorher). Ist das GHCR-Package privat, braucht Portainer unter Registries einen `ghcr.io`-Eintrag mit einem GitHub-Token (Scope `read:packages`).

1. In Portainer einen Stack aus `docker-compose.yml` anlegen, Umgebungsvariablen aus `.env.example` setzen. Pflicht: `PUBLIC_BASE_URL`, `PLESK_URL`, `PLESK_SSH_HOST`, `PLESK_SSH_USER`, `PLESK_SSH_KEY_PATH` (Secret), `PLESK_SSH_HOST_KEY` oder `PLESK_SSH_KNOWN_HOSTS`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `DATA_ENCRYPTION_KEY`, `ACCESS_PROFILES`. Fehlt eine Pflichtvariable, startet der Container nicht und nennt sie im Log.
2. `DATA_ENCRYPTION_KEY` erzeugen: `docker run --rm ghcr.io/tabside/pleskmcp pleskmcp generate-key`. Passwörter: `openssl rand -hex 24`.
3. Den privaten SSH-Key als Docker-Secret bereitstellen (Compose: `secrets.pleskmcp_ssh_key.file`).
4. Der Stack bindet nur die api auf `127.0.0.1:8426`. Davor gehört ein Reverse-Proxy mit TLS. Redis und Postgres sind nur im Stack-Netz erreichbar.
5. Beim ersten Start legt der `migrate`-Container das Schema an; danach starten api, worker und scheduler. `docker compose logs migrate` zeigt "database schema is up to date".

### Migration von Version 0.1 (SQLite)

1. Neuen Stack hochfahren (Schema wird angelegt), alten Container stoppen.
2. Die alte SQLite-Datei (`pleskmcp.sqlite3` aus dem Volume `/data`) in das Volume des neuen Stacks kopieren und importieren:
   ```
   docker compose run --rm api pleskmcp migrate-sqlite /data/pleskmcp.sqlite3
   ```
   Übernommen werden Clients, Tokens, Konten (mit verschlüsselten Secret-Keys; `DATA_ENCRYPTION_KEY` muss derselbe bleiben) und Login-Versuche. Offene Auth-Codes und Anmeldeanfragen nicht (Kunden starten eine laufende Anmeldung einfach neu).
3. Hilfsskript aktualisieren (`install.sh`). Alte Sicherungen werden beim ersten Zugriff migriert, nichts ist zu tun.

### Skalierung

`API_WORKERS` (uvicorn-Prozesse pro api-Container, Standard 2) und `WORKER_REPLICAS` (Standard 2) reichen für einen Server. Mehrere api-Container brauchen einen Load-Balancer im Stack-Netz (z.B. Traefik oder nginx), das Port-Mapping der api entfällt dann; der Dienst selbst ist zustandslos (Sessions, Limits, Queue und Caches liegen in Redis). Worker lassen sich beliebig vervielfachen, jeder hält eine SSH-Verbindung mit `SSH_MAX_CONCURRENCY` Kanälen. Der Scheduler darf mehrfach laufen, aktiv ist immer nur der Inhaber des Leader-Locks.

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

`TRUSTED_PROXIES` muss die IP enthalten, von der der Proxy den Container anspricht (Standard `127.0.0.1`), sonst sieht der Dienst für Rate-Limits und Audit-Log die Proxy-IP statt der Client-IP. `/metrics` sollte der Proxy nicht öffentlich durchreichen (oder `METRICS_ENABLED=false`).

Prüfung nach dem Deploy:

```
curl -s https://mcp.example.com/.well-known/oauth-protected-resource/plesk/mcp
curl -s https://mcp.example.com/.well-known/oauth-authorization-server/plesk
curl -si https://mcp.example.com/plesk/mcp      # 401 mit WWW-Authenticate: Bearer resource_metadata=...
curl -s https://mcp.example.com/plesk/readyz    # {"status":"ok","checks":{"database":true,"redis":true,"workers":2}}
```

### Statusprüfung: die drei Modi

| `ACCOUNT_CHECK_MODE` | Funktionsweise | Benötigt |
|---|---|---|
| `customer_key` (Standard) | Beim Login legt der Dienst mit den Kundendaten einen Plesk-Secret-Key für diesen Kunden an und speichert ihn verschlüsselt (Fernet). Statusprüfung, Domainliste, DNS und Datenbankverwaltung laufen damit im Kontext des Kunden. Kein Admin-Zugang im Dienst. | `DATA_ENCRYPTION_KEY`; Kunden müssen `secret_key create` aufrufen dürfen (sonst Login mit 503 und klarem Hinweis im Log). |
| `admin_key` | Ein Admin-Secret-Key (`plesk bin secret_key -c -ip-address <docker-host-ip>`) liest Kundenstatus und Webspaces. Der Code nutzt ihn ausschliesslich lesend; `db_create`/`db_drop` sind in diesem Modus nicht verfügbar. | `PLESK_ADMIN_API_KEY` |
| `login_only` | Keine Prüfung nach dem Login. Die Domainliste vom Login bleibt bis zum nächsten Login, Tokens laufen normal ab. DNS- und Datenbank-Tools nicht verfügbar. | nichts |

Unabhängig vom Modus wird das Passwort immer nur gegen die XML API geprüft und nie gespeichert.

### Login-Sperren und Fail2ban

Fehlversuche werden pro IP (`LOGIN_FAIL_LIMIT_IP`) und pro Login (`LOGIN_FAIL_LIMIT_LOGIN`) in Redis gezählt. Zusätzlich gibt es `PLESK_FAIL_BUDGET`: ein globales Budget fehlgeschlagener Plesk-Logins, die der Dienst innerhalb von `PLESK_FAIL_BUDGET_WINDOW` an Plesk weiterreicht. Es existiert, weil Plesks Fail2ban (Jail `plesk-panel`, 5 Fehlversuche in 10 Minuten) sonst die IP des Dienstes sperren und damit alle Kunden aussperren würde. Steht die IP des Docker-Hosts in Plesks Trusted-Liste (Schritt 3 der Einrichtung), ist das Budget unnötig: `PLESK_FAIL_BUDGET=0` schaltet es ab. Bleibt es an, zählt es nur Fehlversuche von IPs, die nicht schon selbst gesperrt sind; wer Passwörter durchprobiert, wird per IP gesperrt und verbraucht das Budget danach nicht mehr für alle anderen.

## Betrieb

CLI im Container (`docker compose exec api pleskmcp <befehl>`):

| Befehl | Zweck |
|---|---|
| `api` / `worker` / `scheduler` | Die drei Dienste. |
| `migrate [revision]` | Alembic-Migrationen anwenden (läuft im Stack automatisch). |
| `migrate-sqlite <pfad>` | Einmaliger Import des 0.1-SQLite-Stores. |
| `revoke --login <plesk-login>` | Alle Tokens eines Logins widerrufen, gespeicherten Secret-Key löschen (auch in Plesk). Kunden können das selbst unter `/account`. |
| `revoke --all` | Alle Tokens widerrufen. |
| `accounts` / `clients` / `tokens` / `connections --login X` | Bekannte Konten, registrierte OAuth-Clients, aktive Tokens, Verbindungen eines Logins. |
| `prune` | Abgelaufene Einträge löschen (macht der Scheduler stündlich). |
| `report-ownership --domain X` / `--all` | Dateien und Ordner im Docroot, die nicht dem Systembenutzer gehören (read-only). |
| `generate-key` | Neuen `DATA_ENCRYPTION_KEY` erzeugen. |
| `check [--sysuser X --domain Y --docroot Z]` | Erreichbarkeit von XML API, Postgres, Redis und (optional) des SSH-Hilfsskripts prüfen. |

Daten: Postgres und Redis in eigenen Volumes, das Audit-Log im Volume `/data` (`audit.log`) und zusätzlich auf stdout. Sicherungen, Papierkorb und Dumps liegen in den Abonnements der Kunden und zählen zu deren Speicherplatz.

### Fehlersuche: Fehlercodes in Tool-Antworten

Jede Fehlermeldung an den Client endet mit einem Code in eckigen Klammern. Details wie Hostnamen, Pfade oder Ausnahmetexte stehen nur im Log des Workers (`docker compose logs worker`), nie in der Antwort.

| Code | Bedeutung | Abhilfe |
|---|---|---|
| `ssh_config` | Der Worker kann den privaten Schlüssel (`PLESK_SSH_KEY_PATH`) oder den Host-Key (`PLESK_SSH_HOST_KEY`/`PLESK_SSH_KNOWN_HOSTS`) nicht verwenden (Datei fehlt, nicht lesbar, Schlüssel mit Passphrase, falsches Format), oder asyncssh lehnt die Client-Optionen ab (z.B. kein lokaler Benutzername: der Container setzt dafür `USER`/`LOGNAME`, da uid 1000 keinen passwd-Eintrag hat). | `/readyz` zeigt unter `ssh_preflight_errors` die genaue Ursache (der Worker prüft beides beim Start). `pleskmcp check` im Container. Schlüssel ohne Passphrase (`ssh-keygen -N ""`), Host-Key nur als `typ base64`. |
| `ssh_auth` | Der Plesk-Server lehnt den Schlüssel ab. | `install.sh` mit dem passenden Public Key erneut ausführen; `authorized_keys` des Benutzers `pleskmcp` prüfen. |
| `ssh_unreachable` | Verbindung zum Plesk-Server scheitert oder bricht ab (Netz, Firewall, Port, Timeout). | Erreichbarkeit von `PLESK_SSH_HOST:PLESK_SSH_PORT` aus dem Worker-Container prüfen. |
| `sudo_refused` | sudoers-Regel fehlt oder passt nicht zum Systembenutzer. | `install.sh` erneut ausführen; `/var/log/secure` auf dem Plesk-Server zeigt den abgelehnten Aufruf. |
| `helper_crash` | Das Hilfsskript hat kein gültiges JSON geliefert (veraltete Version, Absturz). | `git pull` und `install.sh` auf dem Plesk-Server; Traceback im Worker-Log. |
| `helper_timeout` / `timeout` | Zeitlimit des Aufrufs bzw. des Hilfsskripts überschritten. | Bei grossen Logs oder Verzeichnissen: Hintergrundjob abwarten (`job_status`), Limits prüfen. |
| `worker_lost` | Der Job wurde zweimal von einem verschwundenen Worker zurückgestellt. | Worker-Container prüfen (Healthcheck, Neustarts). |
| `internal` | Unerwartete Ausnahme im Worker; die Antwort nennt den Ausnahmetyp in Klammern. | Traceback im Worker-Log, Fehler bitte melden. |
| `not_owner`, `quota_exceeded`, `not_found`, `protected`, ... | Fachliche Fehler des Hilfsskripts, Meldung an den Kunden ist selbsterklärend. | |

`/readyz` liefert zusätzlich `ssh_preflight` (`ok`, `failed`, `unknown`): jeder Worker prüft beim Start Schlüsseldatei und Host-Key und hinterlegt das Ergebnis in Redis.

### Umgebungsvariablen mit Defaults

| Variable | Default | Bedeutung |
|---|---|---|
| `DATABASE_URL`, `REDIS_URL` | (Pflicht, aus `POSTGRES_PASSWORD`/`REDIS_PASSWORD` im Compose) | Postgres (asyncpg) und Redis |
| `ACCESS_PROFILES`, `ACCESS_PROFILES_FILE` | leer (niemand hat Zugang) | Profile pro Plan/Add-on |
| `PLAN_CACHE_TTL` | 600 | Cache der Plan-Zuordnung (s) |
| `PLESK_ADMIN_API_KEY` | leer | Admin-Key (lesend); löst Plan-Namen auf |
| `SSH_MAX_CONCURRENCY` | 8 | parallele Helper-Läufe pro Worker |
| `LOGIN_MAX_CONCURRENCY` | 2 | laufende Jobs pro Login |
| `TOOL_SYNC_WAIT` | 25 | Sekunden, die die api auf ein Ergebnis wartet |
| `JOB_RESULT_TTL` | 3600 | Aufbewahrung von Job-Ergebnissen (s) |
| `HELPER_TIME_LIMIT` / `JOB_TIME_LIMIT` | 30 / 300 | Zeitlimit im Hilfsskript, normal / Hintergrundjob (s) |
| `TOOL_CALLS_PER_MINUTE` / `TOOL_WRITES_PER_MINUTE` / `WRITE_BYTES_PER_HOUR` | 60 / 30 / 209715200 | Limits pro Login (Profil kann überschreiben) |
| `TRASH_RETENTION_DAYS` / `BACKUP_RETENTION_DAYS` / `BACKUP_MIN_KEEP_DAYS` | 30 / 30 / 7 | Aufbewahrung |
| `STORE_MAX_PERCENT` / `STORE_MAX_BYTES` | 10 / 1073741824 | Budget für `.pleskmcp` |
| `RETENTION_INTERVAL_HOURS` / `QUOTA_CACHE_TTL` | 6 / 600 | Scheduler-Intervalle |
| `BACKUP_MAX_FILE_BYTES` | 20971520 | grössere Dateien werden nicht gesichert |
| `LOG_MAX_SCAN_BYTES` | 209715200 | Lesegrenze für `search_log` |
| `PROTECTED_FILES` | siehe oben | geschützte Dateien (Globs) |
| `DB_CONFIG_SOURCES` / `DB_REDACT_COLUMNS` | siehe `.env.example` | Quellen für DB-Zugangsdaten, geschwärzte Spalten |
| `DB_MAX_ROWS` / `DB_MAX_AFFECTED_ROWS` / `DB_QUERY_TIME_LIMIT` | 500 / 1000 / 20 | Datenbank-Limits |
| `DB_MANAGEMENT_ENABLED` / `MAX_DATABASES_CREATED` | false / 3 | `db_create`/`db_drop` freischalten, Default-Limit |
| `ACCOUNT_SESSION_TTL` | 900 | Session der Kontoseite (s) |
| `PLESK_FAIL_BUDGET` / `PLESK_FAIL_BUDGET_WINDOW` | 4 / 600 | globales Budget, 0 = aus |
| `METRICS_ENABLED` | true | `/metrics` |
| `LOG_FORMAT` / `LOG_LEVEL` | json / INFO | Logging |
| `API_WORKERS` / `WORKER_REPLICAS` | 2 / 2 | Skalierung (Compose) |
| `SIGNUP_ENABLED` | false | Self-Signup "AI Hosting" (eigener Abschnitt; Variablen in `.env.example`) |

Die übrigen Variablen (Plesk-URL, SSH, Token-Laufzeiten, Lese-/Schreiblimits, Login-Limits, Proxy) sind in `.env.example` beschrieben.

## Tools

| Tool | Scope | Beschreibung |
|---|---|---|
| `list_domains` | | Domains des Kontos mit gebuchtem Profil, Document Root, Profilname und effektiven Rechten |
| `job_status(job_id)` | | Status und Ergebnis eines Hintergrund-Auftrags (nur eigene) |
| `list_dir`, `read_file` | `files:read` | Verzeichnis auflisten (mit `protected`/`owner_ok`), Datei lesen (Text oder Base64, geschützte Dateien geschwärzt) |
| `write_file`, `replace_in_file`, `move_file` | `files:write` | Schreiben, ersetzen, verschieben; immer mit Version |
| `delete_file`, `restore_file` | `files:write` | Papierkorb |
| `list_versions`, `list_changes` | `files:read` | Versionen einer Datei, letzte Änderungen der Domain |
| `restore_version` | `files:write` | Version zurückspielen |
| `storage_status` | `files:read` | Belegung, Kontingent, Budget, Rate-Limit-Stand |
| `purge_store` | `files:write` | Sicherungen gezielt löschen (Vorschau ohne `confirm`) |
| `search_log` | `files:read` | Webserver-Logs durchsuchen (geschwärzt, grosse Logs als Hintergrundjob) |
| `dns_list_records` | `dns:read` | Zone lesen (SOA/NS `locked`) |
| `dns_add_record`, `dns_update_record`, `dns_delete_record` | `dns:write` | Änderungen mit `confirm`, vorher Zonen-Export |
| `dns_restore_zone` | `dns:write` | Exporte auflisten, Unterschiede zeigen, Zone zurücksetzen |
| `db_list`, `db_schema`, `db_query` | `db:read` | siehe Datenbanken |
| `db_execute`, `db_restore` | `db:write` | siehe Datenbanken |
| `db_apply_schema`, `db_create`, `db_drop` | `db:admin` | siehe Datenbanken |

Kein Tool für freie Shell-Befehle. Schreibende Tools melden `preview: true`, solange `confirm` fehlt, wo eine Bestätigung verlangt wird.

**DNS im Detail.** Die DNS-Tools laufen über die Plesk XML API im Kontext des Kunden (Modus `customer_key`) oder mit dem Admin-Key (Modus `admin_key`, dann prüft der Code zusätzlich jeden Eintrag gegen die Zone). Plesk selbst entscheidet, ob die Zone dem Kunden gehört (fremde Zonen liefern `1006 Permission denied`). SOA- und NS-Einträge sind gesperrt. Feldformat der XML API (am Server bestätigt): `host` ist der FQDN mit Punkt am Ende, Hostnamen in `value` ebenso, `opt` trägt bei MX die Priorität und bei SRV `Priorität Gewicht Port`. Subdomains haben in Plesk keine eigene Zone.

## Anleitung für Kunden

Du brauchst nur deinen Plesk-Benutzernamen und dein Plesk-Passwort. Freigegeben werden ausschliesslich die eigenen Abonnements, für die KI-Zugang gebucht ist.

**Claude (claude.ai, Desktop, Mobile):** Einstellungen → Connectors → Eigenen Connector hinzufügen. Als URL `https://mcp.example.com/plesk/mcp` eintragen, speichern und auf Verbinden klicken. Es öffnet sich die Anmeldeseite des Dienstes: Plesk-Benutzername und Passwort eingeben, "Verbinden" bestätigen. Die Option "Andere Verbindungen trennen" (standardmässig aktiv) trennt alle bisher verbundenen Anwendungen, z.B. nach einem Passwortwechsel; wer mehrere Anwendungen parallel nutzt, nimmt den Haken raus.

**ChatGPT:** Einstellungen → Connectors → Connector erstellen (Entwicklermodus). Name vergeben, als MCP-Server-URL `https://mcp.example.com/plesk/mcp` eintragen, Authentifizierung OAuth, erstellen. Beim ersten Verbinden erscheint dieselbe Anmeldeseite.

**Claude Code:**
```
claude mcp add --transport http plesk https://mcp.example.com/plesk/mcp
```
Beim ersten Aufruf startet die Anmeldung im Browser.

**Kontoseite `https://mcp.example.com/plesk/account`:** Anmeldung mit den Plesk-Zugangsdaten. Dort siehst du, welche Anwendungen verbunden sind und wann sie zuletzt benutzt wurden, trennst einzelne Verbindungen oder alle auf einmal (dann muss jede Anwendung neu verbunden werden) und hinterlegst Datenbank-Zugangsdaten für Datenbanken, deren Zugangsdaten nicht aus der Konfiguration deiner Website gelesen werden können. Hinterlegte Werte werden verschlüsselt gespeichert und nie angezeigt. Nach einem Passwortwechsel in Plesk: auf der Kontoseite "Alle trennen" oder beim nächsten Verbinden den Haken "Andere Verbindungen trennen" stehen lassen.

**Rückgängig machen:** Bitte die KI um `list_changes` für die Domain, dann `restore_version`, `restore_file`, `dns_restore_zone` oder `db_restore` mit der passenden ID. Alle Sicherungen liegen in deinem Abo unter `.pleskmcp/` (ausserhalb der Webverzeichnisse) und zählen zu deinem Speicherplatz; der Dienst räumt sie nach den Aufbewahrungsfristen automatisch auf, `storage_status` zeigt den Stand.

## Entwicklung

```
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/python tests/load/run_load.py --seconds 20   # Lasttest, nicht in CI
```

Die Tests dürfen nicht als root laufen (das Hilfsskript verweigert das). Redis ist fakeredis (mit Lua), die Datenbank SQLite über aiosqlite mit denselben SQLAlchemy-Modellen wie Postgres, der Worker läuft im Prozess und ruft das Hilfsskript direkt auf, MariaDB wird durch einen SQLite-gestützten Ersatz für das `mysql`-CLI nachgebildet. Abgedeckt sind unter anderem: Path-Traversal und Symlink-Ausbruch, fremde Domain, Abo ohne Profil, effektive Scopes als Schnittmenge, Schwärzung von `wp-config.php`/`.env` und Ablehnung von `***` beim Zurückschreiben, Kontingent trotz erlaubter Überbeanspruchung, EDQUOT, Aufbewahrung, Versionen und `list_changes`, Idempotenz, Zeitlimit, `db_query` mit verschachtelten und kommentierten Schreibversuchen, Vorschauen ohne Änderung, `db_restore` nach `db_execute`, `db_create` (Zugangsdaten nur ausserhalb des Docroots, nie im Ergebnis), `db_drop` fremder Datenbanken, Fairness zwischen Logins, Hintergrundjobs, Scheduler-Leader-Lock, Kontoseite, Login-Checkbox, DNS-Restore, Health und Metrics. Das Hilfsskript muss Python-3.6-kompatibel bleiben und darf nur die Standardbibliothek nutzen (CI prüft beides).

Verwendete Bausteine des offiziellen MCP Python SDK (`mcp` 2.x): `OAuthAuthorizationServerProvider`, Authorization-, Token-, Registration- und Revocation-Handler, Protected Resource Metadata, Bearer-Middleware mit Audience-Prüfung (RFC 8707), PKCE S256. Client-ID-Metadata-Documents werden in `pleskmcp/auth/cimd.py` ergänzt, weil das SDK sie serverseitig noch nicht abholt.
