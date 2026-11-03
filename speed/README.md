# Optional standalone speed endpoint

This is separate from the LAN agent. It implements the Internet speed-test
protocol used by NetTool Pro. Run it on your own HTTPS host. It has no NetTool
account, billing connection, router access or Monitor secret. MIT licensed.

```sh
python3 -m venv .venv
.venv/bin/pip install -r speed/requirements.txt
umask 077
.venv/bin/uvicorn speed.server:app --host 127.0.0.1 --port 8750 --workers 1
```

Put a reverse proxy with a publicly trusted HTTPS certificate in front of this
loopback listener. Set its body limit to 25 MiB, disable response compression,
request buffering, response buffering and caching. Preserve Content-Length.
Set a 30-second request deadline and a connection limit. The service itself
allows one download and one upload per 120-second session, 100 MiB per client IP
per UTC day and 2 GiB globally per UTC day. Failed/abandoned reservations consume
quota; a server restart invalidates sessions but preserves the daily budget.
Run **one** worker; sessions are intentionally in memory.

Uvicorn trusts proxy headers only from loopback by default. If using another
proxy address, explicitly set `--forwarded-allow-ips` to that exact trusted
address, never `*`. Do not expose this listener directly. Preserve the real
client IP at the proxy; otherwise all clients share the proxy's 100 MiB budget.
The service ignores `X-NetTool-Client` from requests. Configure your host firewall,
certificate renewal and process supervision yourself.

In the app select Internet speed test → custom HTTPS base URL (no path/query).
Fast connections can complete too quickly for a stable estimate; this is a
bounded transfer test, not a promise of line-rate benchmarking. For sustained LAN
throughput use an independent iperf3 server and the app's iperf3 tool.

## Protocol

- `POST /v1/speed/session`, JSON `{"bytes":5242880}`: reserve 1–25 MiB per
  direction. Response `schemaVersion:1,token,bytes,expiresIn:120`.
- `GET /v1/speed/download`, `Authorization: Bearer <token>`: exactly the reserved
  number of incompressible binary bytes, Content-Length, no-store/no-transform.
- `POST /v1/speed/upload`, same authorization, application/octet-stream,
  matching Content-Length: discard streamed bytes; acknowledge only after full
  receipt with `{"schemaVersion":1,"receivedBytes":...}`.
- `GET /v1/speed/latency`: one uncached byte. The native app currently compares
  TCP establishment latency before/during transfer and labels it accordingly.
- Session token is bound to the observed public IP. Redirects are rejected by
  the app. HTTP 429 means quota/capacity reached; 401 expired/wrong session;
  409 reused transfer; 400/422 incomplete/mismatched body.

Data: upload payloads are discarded, never stored. Budget records contain daily
SHA-256(day + public IP) keys, byte counts and the day; current and previous day
are retained. Hashing an IP is pseudonymization, not anonymization. Review your
reverse proxy's logs separately. Database defaults to `data/speed.sqlite`; set
`NETTOOL_SPEED_DATABASE` to change it. Keep this file private.
