"""Request-scoped authenticated principal for audit attribution (§6).

The audit log records the design-§6 "requesting context" of every send/delete. The
transport tag answers *how* the action arrived (``stdio`` vs ``streamable-http``);
the principal answers *who* drove it.

Under the streamable-http transport each request is authenticated by Cloudflare
Access (see :mod:`comlink.access`). After a JWT validates, the middleware records
the authenticated identity (``email``, falling back to the Access ``sub``) in this
contextvar so the audit builder can attribute the action to a concrete principal —
critical on the remote, injection-exposed deployment where an injected send must be
traceable to an identity, not just a transport.

Under the stdio/local transport there is no per-request principal: the contextvar is
unset and the audit entry records ``None``.

The principal is a non-secret identifier (an email address or Access subject), so it
is safe to log — unlike the Bridge password, which never appears in audit entries.
"""

from __future__ import annotations

from contextvars import ContextVar, Token

# Default ``None`` => no authenticated principal in scope (stdio/local, or any code
# path not running inside an Access-validated request).
_principal: ContextVar[str | None] = ContextVar("comlink_audit_principal", default=None)


def set_principal(principal: str | None) -> Token[str | None]:
    """Bind ``principal`` to the current context; return a token to reset it."""
    return _principal.set(principal)


def reset_principal(token: Token[str | None]) -> None:
    """Restore the principal to its prior value using a :func:`set_principal` token."""
    _principal.reset(token)


def current_principal() -> str | None:
    """Authenticated principal for the current context, or ``None`` when unset."""
    return _principal.get()
