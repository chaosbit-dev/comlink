# Exposing an MCP server through Cloudflare Access + Managed OAuth

Team runbook for putting a remote MCP server (Comlink, Home-Assistant MCP, etc.)
on the public internet so the **Claude mobile / web app** can connect, gated by
**Cloudflare Access** (GitHub IdP, email-only policy) acting as the OAuth
authorization server.

This is the exact path proven working for `mcp-comlink.chaosbit.dev` on
2026-06-29. Use it verbatim for new services (e.g. `mcp-ha`). It captures the
four traps we hit so you don't re-hit them.

> **Scope note:** Cloudflare Access is the OAuth **authorization server**. The
> MCP server itself does NOT need to implement OAuth. (A later hardening step
> adds in-server validation of the `Cf-Access-Jwt-Assertion` as a second gate —
> out of scope for *getting connected*, which is what this doc covers.)

---

## Prerequisites

- The `chaosbit.dev` zone on Cloudflare, **Universal SSL active with a
  `*.chaosbit.dev` wildcard** (free).
- A Cloudflare Tunnel (`cloudflared`) running on Gonk that can route a public
  hostname to a local service.
- A Cloudflare **API token** with: `Zone → Read`, `Access: Apps and Policies →
  Edit`, and `Zone → SSL and Certificates → Edit`. Store it in Keychain:
  `security add-generic-password -s cloudflare-api -a "$USER" -w`
- The helper scripts in `experiments/auth_probe/` (in this repo).

---

## The four traps (read first — they cost us hours)

1. **Use a SINGLE-LEVEL hostname.** `mcp-ha.chaosbit.dev` ✅. A two-level name
   like `mcp-ha.remote.chaosbit.dev` ❌ — the free Universal SSL wildcard
   `*.chaosbit.dev` covers ONE level only, so a deeper name has no edge cert and
   the browser shows `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`.
2. **A new hostname needs its edge cert to provision.** If a fresh single-level
   name still fails TLS, the Universal SSL cert hasn't deployed. Check
   **SSL/TLS → Edge Certificates** status; if stuck on "Active" but not serving,
   force a reissue (disable→enable Universal SSL — see below). Do NOT pay for
   Total TLS; the free wildcard is enough for single-level names.
3. **Managed OAuth's DCR is OFF by default and the dashboard doesn't expose it.**
   The Claude app self-registers via Dynamic Client Registration (RFC 7591); CF
   refuses ("couldn't register… `ofid_…`") until you add the Claude redirect URIs
   to the app's `oauth_configuration`. There is **no UI** for this — set it via
   API (script below).
4. **Managed OAuth is DCR-only — there is no manual "OAuth Client ID."** Ignore
   the Claude error's suggestion to paste a Client ID; you can't mint one in CF.
   Fixing DCR (trap 3) is the only path.

---

## Steps

### 1. DNS + Tunnel

Add the public hostname to the tunnel (single-level!), routing to the MCP
service's local port on Gonk. If you edit the tunnel `config.yml` directly,
**also create the DNS record** (`cloudflared tunnel route dns <tunnel> <fqdn>`),
or the name won't resolve (`ERR_NAME_NOT_RESOLVED`). The record must be
**orange-clouded** (proxied).

Verify public DNS (not your local resolver, which may cache a stale NXDOMAIN):
```
dig @1.1.1.1 +short mcp-ha.chaosbit.dev      # expect Cloudflare IPs
```
If your browser still says `ERR_NAME_NOT_RESOLVED` while `@1.1.1.1` resolves,
flush local DNS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
(and Chrome `chrome://net-internals/#dns` → Clear host cache). If you run a
local resolver (Pi-hole/router), clear it there too.

### 2. Cloudflare Access application

**Zero Trust → Access → Applications → Add → Self-hosted.** Set the application
domain to the hostname, and add an **allow policy** scoped to your email(s).
Note the **Application Audience (AUD) Tag** (Overview) — you'll validate against
it in the in-server hardening step later.

### 3. Confirm the edge cert is live

```
curl -sS -o /dev/null -w "%{http_code}\n" --max-time 8 https://mcp-ha.chaosbit.dev/
```
- TLS error / no code → cert not provisioned yet. Wait, or force a reissue:
  ```
  T=$(security find-generic-password -s cloudflare-api -w)
  Z=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=chaosbit.dev" -H "Authorization: Bearer $T" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"][0]["id"])')
  curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$Z/ssl/universal/settings" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"enabled":false}' -o /dev/null -w "disable %{http_code}\n"
  sleep 45
  curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$Z/ssl/universal/settings" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"enabled":true}' -o /dev/null -w "enable %{http_code}\n"
  ```
  (⚠️ briefly drops TLS for all proxied hostnames on the zone while it reissues.)
- `302`/`403` (redirect to `…cloudflareaccess.com/…/login`) → edge + Access
  healthy. Proceed.

### 4. Enable Managed OAuth DCR (the load-bearing step)

Inspect the app, then enable DCR. Both scripts find the app by hostname via
`MCP_APP_DOMAIN`:

```
# see current OAuth config (read-only)
MCP_APP_DOMAIN=mcp-ha.chaosbit.dev \
  CF_API_TOKEN=$(security find-generic-password -s cloudflare-api -w) \
  uv run python experiments/auth_probe/cf_inspect.py

# dry run — backs up the app, prints the exact PUT body, writes nothing
MCP_APP_DOMAIN=mcp-ha.chaosbit.dev \
  CF_API_TOKEN=$(security find-generic-password -s cloudflare-api -w) \
  uv run python experiments/auth_probe/cf_enable_dcr.py

# review the body (policy preserved by ID? domains intact?), then apply
MCP_APP_DOMAIN=mcp-ha.chaosbit.dev \
  CF_API_TOKEN=$(security find-generic-password -s cloudflare-api -w) \
  uv run python experiments/auth_probe/cf_enable_dcr.py --apply
```
This adds `oauth_configuration.dynamic_client_registration` with the Claude
callbacks (`https://claude.ai/api/mcp/auth_callback`,
`https://claude.com/api/mcp/auth_callback`) plus loopback (so Claude Code keeps
working). The Access apps API rejects `PATCH` (405) — the script does
GET→merge→PUT and preserves your policy by reference.

Confirm DCR went live (should flip `404` → `200` with a registered client):
```
uv run python experiments/auth_probe/cf_dcr_probe.py
```

### 5. Deploy the MCP origin

Run the actual MCP server (streamable-http) behind the tunnel at the hostname's
target port. For a quick auth-only smoke test you can use the throwaway probe:
```
PROBE_HOST=0.0.0.0 PROBE_PORT=<tunnel-target-port> \
  PROBE_ALLOWED_HOSTS=mcp-ha.chaosbit.dev \
  uv run python experiments/auth_probe/auth_probe.py
```

### 6. Connect the Claude app

Add a custom connector → `https://mcp-ha.chaosbit.dev/mcp`. Complete the CF →
GitHub login (your email). Success looks like `POST /mcp 200 OK`, a session ID,
and `ListToolsRequest` in the origin logs.

---

## Troubleshooting (symptom → cause → fix)

| Symptom | Cause | Fix |
|---|---|---|
| `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` | No edge cert for that SNI | Use single-level hostname (trap 1); wait/reissue cert (step 3) |
| `ERR_NAME_NOT_RESOLVED` (but `dig @1.1.1.1` resolves) | Local stale negative DNS cache | Flush OS/browser/local-resolver DNS |
| Connector: "couldn't register… `ofid_…`" | DCR not enabled on the app | Run `cf_enable_dcr.py --apply` (step 4) |
| `cf_dcr_probe.py` → `404` at registration_endpoint | DCR not enabled | Same — step 4 |
| API `405 / 10405 "Method not allowed"` | Access apps API doesn't accept PATCH | Use the GET→merge→PUT script (it handles this) |
| Connector says "add an OAuth Client ID" | Managed OAuth is DCR-only | Ignore it; fix DCR (trap 4) |
| API `403` on the enable script | Token missing `Access: Apps → Edit` | Re-scope/re-mint the token |

---

## Reference: helper scripts (`experiments/auth_probe/`)

- `cf_inspect.py` — dump an Access app's OAuth/DCR config (read-only).
- `cf_enable_dcr.py` — enable DCR (dry-run by default; `--apply` to write; backs up first).
- `cf_dcr_probe.py` — POST a registration request and read CF's real response.
- `auth_probe.py` — throwaway minimal streamable-http MCP server for auth smoke tests.

All take `MCP_APP_DOMAIN` (default `mcp-comlink.chaosbit.dev`) so they're reusable
per service. `<domain>.app_backup.json` files are gitignored — they hold app
config and are local-only.
