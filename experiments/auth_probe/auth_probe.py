"""Throwaway MCP auth probe — NOT part of Comlink production.

Purpose (Epic 5, T2 empirical test): stand a minimal streamable-http MCP server
behind the Cloudflare Access "comlink" app (Managed OAuth enabled) and try adding
it as a custom connector in the Claude *mobile* app. This isolates the single
load-bearing unknown — does the claude.ai mobile/web connector complete CF
Managed OAuth against a self-hosted origin (vs. GitHub issue #410, where the
/mcp 401 omitted WWW-Authenticate and mobile failed while Claude Code worked).

The probe carries NO auth of its own: Cloudflare Access + Managed OAuth is the
gate in front. The probe only needs to exist so the mobile app has an MCP origin
to reach *after* the OAuth redirect. If the app lists/calls `ping`, the primary
path (CF as the AS) is confirmed. If it stalls in the OAuth handshake and never
reaches this process (watch the logs — no request arrives), that's #410 and we
pivot to the fallback AS.

Run locally:
    PROBE_HOST=127.0.0.1 PROBE_PORT=8000 uv run python experiments/auth_probe/auth_probe.py

Run on Gonk behind the existing Cloudflare route (bind all interfaces):
    PROBE_HOST=0.0.0.0 PROBE_PORT=8000 \
        PROBE_ALLOWED_HOSTS=comlink.chaosbit.dev \
        uv run python experiments/auth_probe/auth_probe.py

Env:
    PROBE_HOST           bind address (default 127.0.0.1; use 0.0.0.0 in a container)
    PROBE_PORT           bind port (default 8000)
    PROBE_PATH           streamable-http mount path (default /mcp)
    PROBE_ALLOWED_HOSTS  comma-separated Host allowlist for DNS-rebinding
                         protection. If set, protection is ON and only these
                         Host headers are accepted (set this to your public
                         hostname, e.g. comlink.chaosbit.dev). If unset,
                         protection is DISABLED for frictionless testing — fine
                         for a throwaway probe behind CF Access, NOT for prod.
    PROBE_STATELESS      "1" to enable stateless_http (default off).
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("auth_probe")


def _transport_security() -> TransportSecuritySettings:
    raw = os.environ.get("PROBE_ALLOWED_HOSTS", "").strip()
    if raw:
        hosts = [h.strip() for h in raw.split(",") if h.strip()]
        logger.info("DNS-rebinding protection ON; allowed_hosts=%s", hosts)
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=hosts,
            allowed_origins=[f"https://{h}" for h in hosts],
        )
    logger.warning(
        "DNS-rebinding protection DISABLED (PROBE_ALLOWED_HOSTS unset) — "
        "acceptable for a throwaway probe behind CF Access, never for production."
    )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


mcp = FastMCP(
    name="comlink_auth_probe",
    instructions="A disposable probe to verify the Cloudflare Access + Managed OAuth path.",
    host=os.environ.get("PROBE_HOST", "127.0.0.1"),
    port=int(os.environ.get("PROBE_PORT", "8000")),
    streamable_http_path=os.environ.get("PROBE_PATH", "/mcp"),
    stateless_http=os.environ.get("PROBE_STATELESS") == "1",
    transport_security=_transport_security(),
)


@mcp.tool()
def ping(message: str = "hello") -> str:
    """Echo a message back with a server timestamp — proves the full chain works.

    If you can call this from the Claude mobile app, the Cloudflare Access +
    Managed OAuth path reached this origin successfully.
    """
    now = datetime.now(UTC).isoformat()
    logger.info("ping called: message=%r", message)
    return f"pong @ {now} — auth probe reached. you said: {message!r}"


if __name__ == "__main__":
    logger.info(
        "Starting auth probe on %s:%s%s (transport=streamable-http)",
        mcp.settings.host,
        mcp.settings.port,
        mcp.settings.streamable_http_path,
    )
    mcp.run(transport="streamable-http")
