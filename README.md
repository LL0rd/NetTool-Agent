# NetTool LAN-Agent

Kostenloser, quelloffener Messpunkt für die NetTool-App. Du installierst und
betreibst ihn selbst auf einem Linux-Rechner, Raspberry Pi oder geeigneten NAS.
Wir stellen den Code bereit. Lokale Zeitpläne und Aufzeichnungen benötigen kein
Cloud-Konto; die Bedienung in der App gehört zu Pro. Monitor ist ein optionales
Abo für Cloud-Verlauf, externe HTTPS-Prüfungen und Push. Die App funktioniert
auch vollständig ohne Agenten.

**Voraussetzungen:** Linux, Python 3.11+, bewusst ausgewähltes LAN-Interface,
HTTPS-Zertifikat mit auf dem iPhone vertrauenswürdiger Zertifikatskette. Für
ICMP `iputils-ping`, für Durchsatz `iperf3`. Die Agent-Anwendung verwendet die
Python-Standardbibliothek. Docker Desktop ist kein direkter Messpunkt für das
physische LAN; die Compose-Datei setzt Docker auf Linux voraus.

## Was gemessen wird

| Werkzeug | Ausführung und Grenzen |
|---|---|
| TCP, HTTP(S), System-DNS, ICMP | Manuell oder lokaler Zeitplan ab 60 Sekunden. HTTP HEAD ohne Weiterleitung, TLS mit Systemvertrauen. |
| DHCPv4 | Ein DISCOVER, höchstens 3 Sekunden/16 Angebote; keine Lease-Anforderung. Zeitplan ab einer Stunde. |
| IPv6 | Passive 5-Sekunden-Stichprobe von RA/DHCPv6; kein promiscuous mode, keine Rohpakete/DUIDs gespeichert. Ab 5 Minuten. |
| SSDP | 2-Sekunden-Suche, höchstens 64 Antworten, keine automatisch aufgerufenen LOCATION-URLs. Ab 5 Minuten. |
| OpenWrt | Lesende RPCs: Board, Schnittstellen, Leases, Reservierungen/Poolkonfiguration, WLAN-Clients. Ab 5 Minuten. |
| iperf3 | Manuell, TCP, 3 Sekunden, ein Stream, 100 Mbit/s angefordert; ca. 37,5 MB Nutzdaten. Eigener Server erforderlich. |
| Wake-on-LAN | Manuelles UDP Magic Packet an Geräte-/Subnetzbroadcastadresse; kein Beweis, dass das Gerät startet. |

Maximal 16 konfigurierte Prüfungen, eine Messung gleichzeitig. Lokaler Verlauf:
30 Tage standardmäßig, einstellbar 1–365 Tage, höchstens 100.000 Einträge. Neue
SSDP-Identitäten, geänderte DHCP-Optionen/RA-Konfigurationen und OpenWrt-DHCP-
Konfigurationen werden gegen eine gespeicherte Ausgangsbeobachtung verglichen.
Ein erstes Ergebnis ist keine Änderung. Fehlende Beobachtungen in einer kurzen
Stichprobe bedeuten nicht, dass Geräte verschwunden sind. Baselines speichern
höchstens 512 Identitäten je Prüfung; ältere Identitäten können nach Verdrängung
wieder als neu erscheinen.

DHCP nutzt die feste synthetische Identität `02:4e:54:00:00:01`; **nur einen
solchen DHCP-Messpunkt pro Broadcast-Domain betreiben**. Server können ein OFFER
kurz reservieren. Ein bereits belegter UDP-Port 68 wird nicht übernommen und der
DHCP-Client des Rechners nicht verändert. Die Ergebnisse betreffen den Agenten,
niemals den DHCP-Lease des iPhones. VLANs brauchen jeweils einen passenden
Messpunkt oder ein ausdrücklich konfiguriertes Interface.

## Docker Compose auf NAS/Raspberry Pi/Linux

```sh
git clone https://github.com/LL0rd/NetTool-Agent.git
cd NetTool-Agent
umask 077
mkdir -p secrets data
chmod 700 secrets data
python3 -c 'import secrets; from pathlib import Path; p=Path("secrets/agent-token"); p.open("x").write(secrets.token_hex(32)+"\n")'
cp deploy/config.example.json secrets/config.json
```

Lege deine Zertifikatskette in `secrets/agent-chain.pem` und den privaten Schlüssel
in `secrets/agent-key.pem` ab. Der Zertifikatsname muss zur in der App verwendeten
Adresse passen. Verwende eine eigene Domain mit öffentlichem Zertifikat oder eine
auf deinen Geräten ausdrücklich installierte/vertraute private CA. NetTool bietet
keinen Schalter zum Abschalten der Zertifikatsprüfung. Zertifikate erneuerst du
selbst; starte den Container anschließend neu.

Erstelle `.env` mit deinen echten Werten, beispielsweise:

```dotenv
NETTOOL_INTERFACE=eth0
NETTOOL_BIND=192.168.1.20
```

```sh
chmod 600 secrets/* .env
docker compose up -d --build
docker compose logs --tail 30
```

In NetTool: **Diagnose → LAN-Agenten → Agent hinzufügen**. Name,
`https://dein-zertifikatsname:8742` und Inhalt von `secrets/agent-token` eintragen.
Das iPhone muss den Host im LAN oder über dein eigenes VPN erreichen können.
Die Compose-Datei nutzt Host-Netzwerk, ein schreibgeschütztes Root-Dateisystem
und nur NET_RAW/NET_BIND_SERVICE. Daten liegen dauerhaft unter `data/`.
Kein WAN-Port, keine Cloud und kein Zeitplan wird automatisch aktiviert.

Unter **Prüfungen und Zeitpläne** kannst du Ziele anlegen, messen, planen und
Verlauf exportieren/löschen. Für direkte CLI-Nutzung und Requests siehe
[PROTOCOL.md](PROTOCOL.md). Ein Zeitplan läuft auch bei gesperrtem iPhone weiter,
solange der Agent läuft. Eine überlange Prüfung verzögert weitere Prüfungen.

## Installation ohne Docker (systemd)

1. Python 3.11+, `iputils-ping` und `iperf3` aus deiner Distribution installieren.
2. Repository nach `/opt/nettool-agent` kopieren. Systemnutzer/Gruppe `nettool`
   anlegen. `/etc/nettool` mit Modus 0750 und Gruppe `nettool` anlegen.
3. Token, Zertifikat, Schlüssel und `config.json` wie oben in `/etc/nettool`
   anlegen, lesbar nur für root/nettool (0640). Keine Standardpasswörter verwenden.
4. `/etc/nettool/environment` mit `NETTOOL_INTERFACE=eth0` und deiner
   `NETTOOL_BIND=...` anlegen (anpassen).
5. `deploy/nettool-agent.service` nach `/etc/systemd/system/` kopieren, dann
   `sudo systemctl daemon-reload` und `sudo systemctl enable --now nettool-agent`.
6. `sudo journalctl -u nettool-agent -n 30` prüfen. Zustand unter `/var/lib/nettool`.

Alternativ im Repository manuell starten:

```sh
python3 -m nettool_agent --interface eth0 --bind 192.168.1.20 \
  --token-file secrets/agent-token --cert secrets/agent-chain.pem \
  --key secrets/agent-key.pem --config secrets/config.json --data-dir data
```

Die benötigten Linux-Capabilities müssen beim manuellen Start separat vorhanden
sein. Der Agent erweitert seine Rechte nicht selbst. Lokale Tests können ohne
TLS nur an `127.0.0.1` laufen; die App akzeptiert ausschließlich HTTPS.

## OpenWrt lesend anbinden

Installiere auf dem Router `rpcd-mod-iwinfo` und einen HTTPS-fähigen ubus-Zugang
(zum Beispiel LuCI/uhttpd mit eigenem Zertifikat). Kopiere
`deploy/openwrt-acl.json` nach `/usr/share/rpcd/acl.d/nettool.json`. Lege einen
eigenen rpcd-Login `nettool` mit sicherem Passwort-Hash und ausschließlich
`list read 'nettool-readonly'` an; **kein `write` und kein `*`**. Danach rpcd neu
laden. Vorgehen und Login-Hash hängen von deiner OpenWrt-Version ab; siehe
[OpenWrt rpcd](https://openwrt.org/docs/techref/rpcd) und
[ubus ACL](https://openwrt.org/docs/techref/ubus).

Ergänze die geschützte `secrets/config.json` und starte den Agenten neu:

```json
{"retentionDays":30,"checks":[],"routers":{"home":{
  "url":"https://router.example/ubus","username":"nettool",
  "password":"DEIN-EIGENES-PASSWORT","caFile":"/run/secrets/router-ca.pem"
}}}
```

`caFile` bei öffentlichem Systemvertrauen weglassen. In der App eine OpenWrt-
Prüfung mit Alias `home` erstellen. Nicht verfügbare/abgewiesene RPCs erscheinen
als solche. Poolgrenzen und gemeldete Leases sind Rohbeobachtungen; daraus wird
keine unbelegte Auslastungsquote berechnet. WLAN-Schlüssel werden nicht abgefragt.

## Optional mit NetTool Monitor koppeln

1. In der App Monitor-Konto anlegen, Wiederherstellungsschlüssel sicher sichern
   und ein Monitor-Abo aktivieren. Alten Cloud-Zugriff auf neuen Geräten stellst
   du mit diesem Schlüssel wieder her; Apple-Kaufwiederherstellung allein reicht
   aus Datenschutzgründen nicht.
2. Agentennamen eingeben und einen einmaligen, zehn Minuten gültigen Code erzeugen.
3. Bereits lokal konfigurierte Prüfungs-IDs auswählen. Die IDs stehen im Status
   oder in `data/checks.json`. Auf dem Agenten:

```sh
docker compose exec agent python3 -m nettool_agent.monitor \
  --data-dir /data --check DEINE-PRUEFUNGS-ID
```

Der Code wird verdeckt abgefragt. `--check` für jede gewünschte Prüfung wiederholen.
Optional `--allow-remote-checks` erlaubt erneute TCP/HTTP/DNS/ICMP-Messungen nur für
diese ausgewählten, lokal konfigurierten Prüfungen. Keine Remote-Shell, kein
WoL/iperf/DHCP aus der Cloud. systemd-Nutzer verwenden denselben Befehl ohne Docker
mit `--data-dir /var/lib/nettool` und passenden Dateirechten.

Alle 30 Sekunden wird ausgehend HTTPS genutzt. Nur ausgewählte Ergebnis-
Zusammenfassungen verlassen das LAN: Name, Typ, Ziel, Zeitpunkt, Status,
Erläuterung, Laufzeit und Änderungskennzeichen. **Keine** Paketmitschnitte,
Routerantworten oder Passwörter. Der NetTool-Betreiber kann diese Zusammenfassungen
lesen. Cloud-Aufbewahrung 90 Tage/maximal 100.000 Ereignisse pro Konto. Bei
Unterbrechung werden aufbewahrte lokale Ergebnisse später nachgeliefert; alte
Ergebnisse lösen keine nachträglichen Push-Warnungen aus. Historie und Quellen-
Kennzeichnung bleiben sichtbar. Datenschutzerklärung: https://nettool.d-r.dev/privacy.

Entkoppeln: Agent in der App widerrufen und `data/monitor.json` entfernen. Lokale
Messungen laufen weiter. Cloud-Kontolöschung ist in der App möglich und kündigt
kein Apple-Abo.

## Eigener Internet-Messendpunkt

[speed/README.md](speed/README.md) enthält einen optionalen eigenen Endpunkt für
Download/Upload-Tests der App. Er ist getrennt vom LAN-Agenten und kann auf einem
eigenen öffentlich erreichbaren HTTPS-Host betrieben werden.

## Tests, Updates und Grenzen

```sh
python3 -m unittest discover -s tests -v
python3 -m nettool_agent --help
```

Tests verwenden konstruierte Pakete, simulierte Routerantworten und echte
Loopback-Kommunikation. Sie senden keine DHCP-Probe in dein LAN. Physische
Interfaces, VLANs, Routerversionen und Zertifikatsvertrauen prüfst du in deiner
Umgebung. Falsche Rechte, Filterung und ein belegter DHCP-Port werden als Fehler
angezeigt. Eine kurze passive Stichprobe ist kein vollständiges Inventar.

Vor einem Update `data/` und `secrets/` geschützt sichern, Release prüfen,
`git pull --ff-only`, Tests ausführen und `docker compose up -d --build` bzw.
systemd neu starten. Es gibt keinen automatischen Updater. Zum Entfernen Dienst
stoppen, Daten/Schlüssel bewusst löschen und gegebenenfalls Monitor-Agent widerrufen.
Siehe [SECURITY.md](SECURITY.md). Lizenz: [MIT](LICENSE).
