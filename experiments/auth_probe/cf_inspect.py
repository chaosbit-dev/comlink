"""Read-only inspector for the Comlink Cloudflare Access app's OAuth/DCR config.

Throwaway debugging tool (Epic 5 auth). Finds the mcp-comlink Access application
and dumps the OAuth / dynamic-client-registration configuration so we can see the
real API schema before changing anything. Makes only GET requests.

Run:
    CF_API_TOKEN=$(security find-generic-password -s cloudflare-api -w) \
        uv run python experiments/auth_probe/cf_inspect.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE_NAME = os.environ.get("CF_ZONE_NAME", "chaosbit.dev")
APP_DOMAIN = os.environ.get("MCP_APP_DOMAIN", "mcp-comlink.chaosbit.dev")

token = os.environ.get("CF_API_TOKEN", "").strip()
if not token:
    sys.exit("CF_API_TOKEN not set")


def get(path: str) -> dict:
    req = urllib.request.Request(f"{API}{path}", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"success": False, "http_status": e.code, "body": e.read().decode("utf-8", "replace")}


# account id via the zone
zinfo = get(f"/zones?name={ZONE_NAME}")
try:
    account_id = zinfo["result"][0]["account"]["id"]
except Exception:
    print("Could not get account id from zone:", json.dumps(zinfo)[:400])
    sys.exit(1)
print(f"account_id = {account_id}\n")

apps = get(f"/accounts/{account_id}/access/apps?per_page=100")
if not apps.get("success"):
    print("Access apps API call FAILED — token likely lacks the 'Access: Apps Read' permission.")
    print(json.dumps(apps, indent=2)[:800])
    print("\nFix: create/edit a CF API token with 'Access: Apps and Policies > Edit', store it, retry.")
    sys.exit(1)

match = None
for app in apps["result"]:
    dom = str(app.get("domain", "")) + " " + json.dumps(app.get("self_hosted_domains", []))
    if APP_DOMAIN in dom:
        match = app
        break

if not match:
    print(f"Did not find the {APP_DOMAIN} app. Apps seen:")
    for app in apps["result"]:
        print(f"  - {app.get('name')!r:30} domain={app.get('domain')} aud={app.get('aud')}")
    sys.exit(1)

print(f"FOUND app_id = {match.get('id')}")
print(f"name={match.get('name')!r}  type={match.get('type')!r}  domain={match.get('domain')!r}")
print(f"top-level keys: {sorted(match.keys())}\n")

for key in ("oauth_configuration", "saas_app", "allowed_idps", "self_hosted_domains", "policies"):
    if key in match:
        print(f"---- {key} ----")
        print(json.dumps(match[key], indent=2)[:2500])
        print()
