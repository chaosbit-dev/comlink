"""Guardrails: audit log, send gate / allowlist / rate limit (§5, §7).

Two slices:

- Audit-append (Epic 2): every successful delete/send writes one JSONL line so
  an agent's destructive/outbound actions are reconstructable (§5, §7.5).
- Send guardrails (Epic 3): recipient allowlist + sliding-window rate limit.
  The master env gate (``COMLINK_ALLOW_SEND``) is enforced at *registration*
  time in server.py — when off, ``proton_send_message`` is not even registered
  (§7.1), so this module only covers the second and third layers.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections import deque
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from comlink.audit_context import current_principal
from comlink.config import ComlinkSettings
from comlink.errors import SendBlocked

logger = logging.getLogger("comlink.guardrails")

_SECONDS_PER_HOUR = 3600.0

# Default requesting-context transport tag (§6) when no real transport is threaded in
# — i.e. the local stdio case. Call sites in server.py pass ``settings.transport``
# explicitly so the remote deployment records ``"streamable-http"`` instead. Never
# carries a secret or the body.
DEFAULT_TRANSPORT = "stdio"


def audit_timestamp() -> str:
    """ISO 8601 UTC timestamp for audit entries."""
    return datetime.now(UTC).isoformat()


def delete_audit_entry(
    folder: str,
    succeeded: list[int],
    failed: list[int],
    transport: str = DEFAULT_TRANSPORT,
) -> dict[str, Any]:
    """Build the delete audit entry. No secrets ever go in audit entries (§7.4).

    ``transport`` and ``principal`` are the design-§6 "requesting context": the
    channel the delete arrived on and the authenticated identity that drove it (read
    from :func:`comlink.audit_context.current_principal`). Both are non-secret tags;
    ``principal`` is ``None`` under the stdio/local transport. A delete needs the same
    attribution as a send — an injected destructive action must be traceable.
    """
    return {
        "ts": audit_timestamp(),
        "action": "delete",
        "transport": transport,
        "principal": current_principal(),
        "folder": folder,
        "uids": list(succeeded) + list(failed),
        "succeeded": list(succeeded),
        "failed": list(failed),
    }


def send_audit_entry(
    recipients: list[str], subject: str, message_id: str, transport: str = DEFAULT_TRANSPORT
) -> dict[str, Any]:
    """Build the send audit entry. No body, no password, no secrets (§7.4).

    ``transport`` and ``principal`` are the design-§6 "requesting context".
    ``transport`` is the channel the send arrived on (default ``"stdio"``; call sites
    pass the real ``settings.transport``). ``principal`` is the authenticated identity
    that drove the send, read from :func:`comlink.audit_context.current_principal`
    (the Access email/subject under streamable-http; ``None`` under stdio/local). The
    principal is a non-secret identifier — safe to log, unlike the body or password.
    """
    return {
        "ts": audit_timestamp(),
        "action": "send",
        "transport": transport,
        "principal": current_principal(),
        "recipients": list(recipients),
        "subject": subject,
        "message_id": message_id,
    }


# ---------------------------------------------------------------------------
# Send guardrails: recipient allowlist (layer 2) + rate limit (layer 3) (§7.1)
# ---------------------------------------------------------------------------


def recipient_allowed(addr: str, allowlist: list[str]) -> bool:
    """Whether *addr* is permitted by *allowlist*.

    Two forms only (deliberate v1 decision — no bare-domain matching):

    - exact, lowercased address match (``kendra@chaosbit.dev``)
    - ``*@domain`` wildcard (``*@chaosbit.dev``)

    An empty *allowlist* means any-recipient mode and always returns True.
    *allowlist* is expected to already be normalized (lowercased, blanks
    dropped) via :meth:`ComlinkSettings.parsed_allowlist`.
    """
    if not allowlist:
        return True
    candidate = addr.strip().lower()
    domain = candidate.rsplit("@", 1)[1] if "@" in candidate else ""
    for entry in allowlist:
        if entry == candidate:
            return True
        if entry.startswith("*@") and domain and entry[2:] == domain:
            return True
    return False


def check_allowlist(recipients: list[str], settings: ComlinkSettings) -> None:
    """Raise :class:`SendBlocked` naming the first non-allowlisted recipient.

    No-op when the allowlist is empty (any-recipient mode — warned at startup).
    """
    allowlist = settings.parsed_allowlist()
    if not allowlist:
        return
    for addr in recipients:
        if not recipient_allowed(addr, allowlist):
            raise SendBlocked.not_allowlisted(addr)


class RateLimiter:
    """In-memory sliding-window send rate limit (layer 3, §7.1).

    Holds the timestamps of recent sends. ``check`` is called *before* a send
    and raises when the window is full; ``commit`` is called *after* a
    successful send so a failed send never burns budget. State is process-local
    only (restart resets the budget — acceptable for v1; the audit JSONL is the
    durable record). ``now`` is injected for deterministic tests.
    """

    def __init__(self) -> None:
        self._timestamps: deque[float] = deque()

    def _evict(self, now: float) -> None:
        cutoff = now - _SECONDS_PER_HOUR
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    def check(self, now: float, max_per_hour: int) -> None:
        """Raise :class:`SendBlocked` if sending now would exceed *max_per_hour*."""
        self._evict(now)
        if len(self._timestamps) >= max_per_hour:
            oldest = self._timestamps[0]
            retry_after = max(0, int(oldest + _SECONDS_PER_HOUR - now) + 1)
            raise SendBlocked.rate_limited(max_per_hour, retry_after)

    def commit(self, now: float) -> None:
        """Record a successful send at *now*."""
        self._timestamps.append(now)

    def reserve(self, now: float, max_per_hour: int) -> None:
        """Atomically check the window and claim a slot (race-free; §7.1 layer 3).

        ``check`` and ``commit`` straddle the ``await`` points of the send path
        (reply fetch, SMTP send), so two concurrent sends could each observe free
        budget before either commits and burst past the cap. ``reserve`` collapses
        check-and-claim into one synchronous, await-free step — atomic under the
        single-threaded event loop — so the budget can never be double-spent. The
        caller MUST :meth:`release` the slot if the send subsequently fails, so a
        failed send still burns no budget.
        """
        self.check(now, max_per_hour)
        self._timestamps.append(now)

    def release(self, now: float) -> None:
        """Return a slot reserved by :meth:`reserve` after a failed send."""
        with contextlib.suppress(ValueError):
            self._timestamps.remove(now)

    def remaining_budget(self, now: float, max_per_hour: int) -> int:
        """Sends still permitted in the current window (never negative)."""
        self._evict(now)
        return max(0, max_per_hour - len(self._timestamps))


def append_audit(settings: ComlinkSettings, entry: Mapping[str, Any]) -> bool:
    """Append one JSON line to the audit log, creating parent dirs as needed.

    Audit-write failure is log-and-continue (Open Question 3): we never fail a
    user's delete just because the audit append threw. Returns True on success.
    """
    path = settings.audit_log.expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("Failed to append audit entry to %s: %s", path, exc)
        return False
    return True
