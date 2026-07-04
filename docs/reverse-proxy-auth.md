# Reverse-proxy authentication

PI WEB ships no built-in user authentication. Reaching the web/API port means
full control of the machine the agents run on, so any deployment that is not
strictly single-user-on-loopback must put authentication in front of PI WEB.

This guide shows a hardened setup for the common case: PI WEB running on a
workstation or server, reached from other devices over a private network
(Tailscale/WireGuard) through Nginx Proxy Manager (NPM), with
[Authelia](https://www.authelia.com/) providing single sign-on.

## Threat model recap

- PI WEB binds `127.0.0.1:8504` by default. Keep it there (or on a private VPN
  address). Do not set `host`/`PI_WEB_BIND_ADDR` to `0.0.0.0`.
- PI WEB has no CSRF tokens and, by itself, no `Origin`/`Host` checks beyond the
  guard described below. Prefer **forward-auth with a `SameSite` cookie** over
  HTTP Basic auth: Basic credentials are ambient (the browser replays them on
  every request to the origin, including cross-site WebSocket handshakes), so
  they do not stop a malicious page from driving PI WEB. A `SameSite=Lax`/`Strict`
  session cookie is not sent on cross-site WebSocket upgrades or cross-site form
  posts, which closes that vector at the proxy.

## Defense in depth inside PI WEB

Set these before exposing PI WEB through the proxy. They work regardless of the
proxy and are cheap to enable:

```bash
# Only accept requests whose Host header matches your proxy hostname.
# Loopback names and IP literals are always accepted.
export PI_WEB_ALLOWED_HOSTS="pi-web.example.ts.net"

# Optional shared secret required on every request. Read only from the
# environment; never stored in or returned by the config API.
export PI_WEB_AUTH_TOKEN="$(head -c 32 /dev/urandom | base64)"
```

`PI_WEB_ALLOWED_HOSTS` blocks DNS-rebinding access. `PI_WEB_AUTH_TOKEN` is an
independent gate: present it as `Authorization: Bearer <token>`, an
`x-pi-web-token` header, a `pi_web_auth` cookie, or a one-time
`?__auth=<token>` bootstrap query (which PI WEB exchanges for a `SameSite=Strict`
cookie and strips from the URL). The proxy's own auth is still the primary
control; the shared secret is a backstop for direct access to the port.

The WebSocket `Origin` check is always on: an upgrade whose `Origin` host does
not match the request `Host` is refused, so terminal/session sockets cannot be
hijacked cross-site.

Health checks should target `GET /livez`, which is always public.

## Authelia forward-auth

Minimal `configuration.yml` for a single user (adapt the session/secret and
storage to your environment):

```yaml
server:
  address: tcp://0.0.0.0:9091

authentication_backend:
  file:
    path: /config/users_database.yml

access_control:
  default_policy: deny
  rules:
    - domain: pi-web.example.ts.net
      policy: two_factor   # or one_factor for username/password only

session:
  name: authelia_session
  # A SameSite cookie is what protects PI WEB's CSRF/WebSocket surface.
  same_site: lax
  cookies:
    - domain: example.ts.net
      authelia_url: https://auth.example.ts.net
  secret: <generate-a-long-random-secret>

storage:
  local:
    path: /config/db.sqlite3

notifier:
  filesystem:
    filename: /config/notification.txt
```

`users_database.yml`:

```yaml
users:
  you:
    displayname: You
    # generate with: docker run authelia/authelia:latest authelia crypto hash generate argon2
    password: "$argon2id$v=19$m=65536,t=3,p=4$..."
    email: you@example.com
```

## Nginx Proxy Manager

NPM does not expose forward-auth in its UI, so add it as a custom Nginx snippet
on the PI WEB proxy host (Edit proxy host → **Advanced** → *Custom Nginx
Configuration*):

```nginx
# --- Authelia forward-auth ---
location /authelia {
    internal;
    proxy_pass http://authelia:9091/api/verify;
    proxy_set_header X-Original-URL $scheme://$host$request_uri;
    proxy_set_header Content-Length "";
    proxy_pass_request_body off;
}

location / {
    auth_request /authelia;
    auth_request_set $redirect $scheme://$host$request_uri;
    error_page 401 =302 https://auth.example.ts.net/?rd=$redirect;

    # Pass the request to PI WEB only after Authelia approves it.
    proxy_pass http://127.0.0.1:8504;

    # WebSocket upgrade (terminals, session/activity streams).
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $http_upgrade;

    # Preserve Host so PI WEB's allowedHosts check and its WebSocket
    # Origin check line up with the browser's origin.
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

In the NPM proxy host settings also enable **Websockets Support** and an SSL
certificate. Point the upstream at `127.0.0.1:8504` (the default PI WEB bind).

## Checklist

1. PI WEB bound to `127.0.0.1` (or a private VPN address), never `0.0.0.0`.
2. `PI_WEB_ALLOWED_HOSTS` set to your proxy hostname.
3. Forward-auth (Authelia/authentik/oauth2-proxy) with a `SameSite` cookie in
   front of PI WEB — not HTTP Basic auth.
4. Private-network ACLs (e.g. Tailscale) restrict which devices can reach the
   proxy at all.
5. Optionally set `PI_WEB_AUTH_TOKEN` as an independent backstop.
6. Health checks target `GET /livez`.
