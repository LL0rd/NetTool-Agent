# NetTool Agent API v1

HTTPS, JSON, UTF-8. Every route requires `Authorization: Bearer <local token>`.
There is no endpoint that reveals or changes a token. Responses have
`schemaVersion:1` and identify the source. Clients reject redirects and validate
normal TLS trust/hostname. Never put keys in URLs or reports.

| Method/path | Body or query | Result |
|---|---|---|
| GET `/v1/health` | none | interface presence, capabilities, limits; no probe |
| POST `/v1/dhcp/discover` | `{"timeoutSeconds":3}` | one DHCPDISCOVER, offer/options/latency list; 1–5 s |
| GET `/v1/status` | none | checks, interface, retentionDays, routerAliases, cloudConfigured, cloudLastSuccess/error |
| GET `/v1/checks` | none | same as status |
| POST `/v1/checks` | `{"checks":[...],"expectedChecks":[...]}` | replace local schedule atomically; 409 if expected list changed |
| POST `/v1/checks/run` | `{"id":"router"}` | run a configured check, persist and return event |
| GET `/v1/history` | `limit=1..200`, optional `after=sequence` | newest first without cursor; ascending after cursor |
| DELETE `/v1/history` | none | delete stored local events, preserve configured checks |

Check example (disabled until explicitly enabled):

```json
{"id":"router","name":"Router HTTPS","kind":"tcp","target":"192.0.2.1",
 "port":443,"intervalSeconds":300,"enabled":false,"ipv6":false}
```

IDs: 1–64 letters/digits/dash/underscore, unique. Name 1–80 chars, target ≤2048.
Kinds: tcp,http,dns,ping,dhcp,ssdp,ipv6-observe,openwrt,iperf,wol. Optional booleans
ipv6/reverse and MAC string `mac`. Port 1–65535. Max 16 checks, minimum intervals
60 s for connection checks, 300 s for observation/router checks, 3600 s DHCP;
max 86400 s. WoL/iperf are manual. `expectedChecks` implements compare-and-swap;
send the complete list from the last status response. New clients should always
use it. Unknown keys and invalid types are rejected.

Events contain id, sequence, checkID, name, kind, target, ISO8601 timestamp,
source, status (passed/failed/warning/unavailable), detail, durationMS or null,
optional structured data and changed. `sequence` is a monotonically increasing
local cursor. A history deletion does not reset it. Data can contain LAN
identifiers and is limited to 1 MiB/event. The app's report export offers redaction.
Delete-history does not erase observation baselines; remove/re-add a check to
establish a new baseline.

API errors carry a machine code and message; authentication 401, invalid request
400, concurrent probe/config conflict 409, rate limit 429 with Retry-After,
capability unavailable 503. One engine check at a time; manual starts ≥3 seconds
apart. DHCP discovery and saved DHCP checks share a 60 s minimum cooldown, including failed attempts. Requests and
responses are bounded. No generic command execution, arbitrary code or router
writes are supported.

## Monitor relay

Separate outbound protocol. The local API token is never sent to Monitor.
Pairing consumes one 256-bit code over HTTPS and returns a separate revocable
agent key. Only selected check summaries are uploaded in batches ≤50 and ≤256 KiB.
Remote checks require local opt-in, a selected configured ID and type
TCP/HTTP/DNS/ICMP; commands expire after 90 seconds and are persisted before
execution for at-most-once handling. This favors avoiding duplicate execution
over retry after a crash. Raw event `data`, packet bytes and credentials are
excluded by an explicit upload allowlist. See README for customer consent and
[NetTool privacy](https://nettool.d-r.dev/privacy) for hosted retention/deletion.
