"""Probe Cloudflare Access's OAuth Dynamic Client Registration directly.

Throwaway debugging tool (Epic 5 auth). Reproduces, outside the Claude app, the
RFC 7591 client-registration call that is failing — so we see Cloudflare's ACTUAL
error JSON instead of the app's opaque "couldn't register / ofid_..." message.

Run:
    uv run python experiments/auth_probe/cf_dcr_probe.py
    uv run python experiments/auth_probe/cf_dcr_probe.py --wildcard   # try /* form
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

AS_METADATA = "https://chaosbit.cloudflareaccess.com/.well-known/oauth-authorization-server"

CALLBACKS = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]
if "--wildcard" in sys.argv:
    CALLBACKS = ["https://claude.ai/api/mcp/*", "https://claude.com/api/mcp/*"]


def fetch(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return {"status": r.status, "body": json.load(r)}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


print(f"== AS metadata: {AS_METADATA} ==")
meta = fetch(AS_METADATA)
print("status:", meta["status"])
body = meta["body"]
if not isinstance(body, dict):
    print(body[:800])
    sys.exit("AS metadata not JSON — cannot find registration_endpoint")
reg = body.get("registration_endpoint")
print("registration_endpoint:", reg)
print("authorization_endpoint:", body.get("authorization_endpoint"))
print("token_endpoint:", body.get("token_endpoint"))
if not reg:
    sys.exit("No registration_endpoint advertised — DCR is not offered by this AS.")

payload = {
    "client_name": "comlink-dcr-probe",
    "redirect_uris": CALLBACKS,
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
}
print(f"\n== POST {reg} ==")
print("redirect_uris:", CALLBACKS)
req = urllib.request.Request(
    reg,
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json", "Accept": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        print("HTTP", r.status, "— SUCCESS, client registered:")
        print(json.dumps(json.load(r), indent=2)[:1500])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, "— Cloudflare REJECTED registration. Body:")
    print(e.read().decode("utf-8", "replace")[:2000])
except Exception as e:  # noqa: BLE001
    print("request error:", e)
