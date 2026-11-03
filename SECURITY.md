# Security and data

Report a vulnerability privately to dr@dr-it.biz. Do not include access keys,
router passwords, packet captures or customer addresses in a public issue.

The agent is a customer-operated LAN service. Bind its API only to a LAN/VPN IP;
do not expose port 8742 to the WAN. Use a unique random token and trusted HTTPS.
The app refuses insecure TLS and redirects. Local API authentication grants full
control of this agent's configured diagnostics and local history. Monitor's
separate token grants only event ingestion and polling of explicitly permitted
checks. It cannot open a shell or change router settings.

Local history and configuration are plaintext files in a private directory.
Use encrypted host storage/backups if required. Rotate the local token by
replacing its file and restarting; update the app's saved token. For Monitor,
revoke the agent in the app and remove data/monitor.json before pairing again.
Monitor checkpoints, selected check IDs and optional remote permission live in
that file/data directory; keep it private and never commit it.

Images are built locally from reviewed source. There is no automatic updater:
review a release, back up data and secrets, pull the release, run tests, rebuild
and restart. Do not grant NET_ADMIN, privileged mode or the Docker socket.
