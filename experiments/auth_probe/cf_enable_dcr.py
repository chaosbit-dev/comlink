"""Enable OAuth Dynamic Client Registration on a Cloudflare Access MCP app.

Service-agnostic: finds the Access application by its public hostname, so this
works for mcp-comlink, mcp-ha, or any future MCP service in the chaosbit.dev
zone. The app needs DCR enabled or CF's registration endpoint 404s and the
Claude connector cannot self-register.

The Access apps API rejects PATCH (405), so this does GET -> merge -> PUT.

SAFETY:
- Always GETs + backs up the current app to <domain>.app_backup.json first.
- DRY RUN by default: prints the exact PUT body and writes nothing.
- Only writes with --apply.
- Preserves existing policies by referencing them by ID (never redefines them).

Run:
    MCP_APP_DOMAIN=mcp-ha.chaosbit.dev \
    CF_API_TOKEN=$(security find-generic-password -s cloudflare-api -w) \
        uv run python experiments/auth_probe/cf_enable_dcr.py            # dry run
    ... same, with --apply                                              # writes
    # --wildcard uses the https://claude.ai/api/mcp/* redirect form

Token needs: Access: Apps and Policies > Edit  (and Zone > Read for the zone lookup).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.cloudflare.com/client/v4"
ZONE_NAME = os.environ.get("CF_ZONE_NAME", "chaosbit.dev")
APP_DOMAIN = os.environ.get("MCP_APP_DOMAIN", "mcp-comlink.chaosbit.dev")
READONLY = {"id", "aud", "uid", "created_at", "updated_at"}

token = os.environ.get("CF_API_TOKEN", "").strip()
if not token:
    sys.exit("CF_API_TOKEN not set")

apply = "--apply" in sys.argv
uris = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]
if "--wildcard" in sys.argv:
    uris = ["https://claude.ai/api/mcp/*", "https://claude.com/api/mcp/*"]


def call(method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw}


# account id from the zone
_, z = call("GET", f"/zones?name={ZONE_NAME}")
try:
    account_id = z["result"][0]["account"]["id"]
except Exception:
    sys.exit(f"Could not resolve account id for zone {ZONE_NAME}: {json.dumps(z)[:400]}")

# find the Access app by hostname
_, apps = call("GET", f"/accounts/{account_id}/access/apps?per_page=100")
if not apps.get("success"):
    print("Access apps API failed — token likely lacks 'Access: Apps' permission.")
    sys.exit(json.dumps(apps, indent=2)[:600])
app = next(
    (
        a
        for a in apps["result"]
        if APP_DOMAIN in (str(a.get("domain", "")) + " " + json.dumps(a.get("self_hosted_domains", [])))
    ),
    None,
)
if not app:
    sys.exit(f"No Access app found for {APP_DOMAIN}")
app_id = app["id"]
print(f"account={account_id}  app={app_id}  domain={APP_DOMAIN}")

# fresh GET of the full app, then back it up
_, got = call("GET", f"/accounts/{account_id}/access/apps/{app_id}")
app = got["result"]
backup = Path(__file__).with_name(f"{APP_DOMAIN}.app_backup.json")
backup.write_text(json.dumps(app, indent=2))
print(f"Backed up -> {backup}\n")

payload = {k: v for k, v in app.items() if k not in READONLY}
payload["oauth_configuration"] = {
    "dynamic_client_registration": {
        "enabled": True,
        "allowed_uris": uris,
        "allow_any_on_localhost": True,
        "allow_any_on_loopback": True,
    }
}
if app.get("policies"):
    payload["policies"] = [
        {"id": p["id"], "precedence": p.get("precedence", i + 1)}
        for i, p in enumerate(app["policies"])
    ]

print("PUT body to send:")
print(json.dumps(payload, indent=2))
if not apply:
    print("\nDRY RUN — nothing written. Re-run with --apply to PUT this.")
    sys.exit(0)

print("\n--apply set: PUTting...")
status, res = call("PUT", f"/accounts/{account_id}/access/apps/{app_id}", payload)
print(f"HTTP {status}  success={res.get('success')}")
if res.get("errors"):
    print("errors:", json.dumps(res["errors"], indent=2))
if res.get("success"):
    r = res["result"]
    print("oauth_configuration now:", json.dumps(r.get("oauth_configuration"), indent=2))
    print("policies now:", [p.get("name") or p.get("id") for p in r.get("policies", [])])
    print("aud still:", r.get("aud"))
