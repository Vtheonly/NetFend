# ADR-004 — Dashboard: stdlib HTTP server, localhost, token+CSRF, read-only default

**Status:** Accepted 2026-10-15
**Context:** Requirement: a lightweight monitoring dashboard that must not
become an attack surface. No framework was justified; the deployment
target is a single machine.

**Decision:**

- Backend: Python stdlib `http.server.ThreadingHTTPServer` — no Flask/FastAPI
  dependency. Binds `127.0.0.1` by default (configurable, with warning when
  widened).
- Static frontend: plain HTML/CSS/JS, no CDN, no build step, works offline.
  Charts are hand-rolled `<canvas>` renderers (~100 lines) instead of a
  chart library.
- Auth: GET endpoints (read-only telemetry) are available from localhost
  without a token **only** when `dashboard.allow_local_readonly=true`
  (default). Any state-changing POST (and all access when readonly=false)
  requires `X-NetFend-Token` matching the token file
  (`/var/lib/netfend/dashboard.token`, 0600, generated at install) **and**
  a per-session CSRF token issued via `/api/session`. Login rate-limited.
- API surface: fixed allowlist of actions (reload-config,
  gateway-rebaseline, firewall-toggle-profile, wifi-rescan). No shell
  execution, no raw firewall strings, no secrets in responses (token file
  content itself is never returned; `nmcli --show-secrets` is never called).

**Consequences:** Minimal attack surface, zero extra dependencies, easily
auditable. Remote access requires an SSH tunnel (documented) which keeps
the trust boundary sane.
