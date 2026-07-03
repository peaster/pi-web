---
"@jmfederico/pi-web": minor
---

Add a network-facing request guard to the web/API gateway. The already-existing `allowedHosts` config is now enforced as a Host-header allowlist on the running server (not just the dev server), WebSocket upgrades whose `Origin` does not match the request host are rejected, and an optional shared secret can be required via the `PI_WEB_AUTH_TOKEN` environment variable. Together these close the cross-site-WebSocket and DNS-rebinding vectors when PI WEB is reached through a reverse proxy. A public `/livez` liveness endpoint is added so health checks keep working when the shared secret is set.
