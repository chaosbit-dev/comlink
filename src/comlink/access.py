"""Cloudflare Access JWT validation for the streamable-http transport (Epic 5).

Defense-in-depth second gate. Cloudflare Access terminates authentication at the
edge and injects a ``Cf-Access-Jwt-Assertion`` header, but the origin must not
blindly trust the network: any in-cluster foothold could otherwise reach the
ClusterIP directly. This middleware re-validates that JWT in-process — RS256
signature against the team JWKS, plus ``aud``/``iss``/``exp``/``iat`` and an
optional ``email`` allowlist — before any request reaches the MCP application.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any

import httpx
import jwt
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from comlink.config import ComlinkSettings

logger = logging.getLogger("comlink.access")

_ACCESS_HEADER = "cf-access-jwt-assertion"

# DESIGN-GAP: design doc §5 has no JWKS-fetch timeout setting and comlink's config
# carries no generic request_timeout (unlike the HA-MCP reference). The JWKS endpoint
# is a small, fast Cloudflare-hosted document; 10s is the boring, safe default and is
# not worth a dedicated env var until operational evidence says otherwise.
_JWKS_FETCH_TIMEOUT_SECONDS = 10.0

# Minimum wall-clock interval between JWKS refreshes triggered by an unknown ``kid``.
# Without it, an attacker hitting the ClusterIP directly with JWTs carrying random
# kids would force an unbounded stream of outbound JWKS fetches (MEDIUM-1). Genuine
# key rotation still recovers: once this interval has elapsed, the next unknown kid
# triggers a single refresh that picks up the rotated key.
_JWKS_MIN_REFRESH_SECONDS = 60.0


class AccessValidationError(Exception):
    """Raised when a Cloudflare Access JWT fails validation."""


class CloudflareAccessValidator:
    """Validate Cloudflare Access JWTs against the team JWKS.

    Verifies the RS256 signature, ``aud``, ``iss``, and the standard time claims
    (``exp``/``iat``), and optionally that the ``email`` claim is allow-listed.
    Signing keys are cached and refreshed once on encountering an unknown ``kid``.

    ``algorithms`` is hardcoded to ``["RS256"]``: this is the alg-confusion defense
    (an attacker must not be able to downgrade the verification to ``none`` or to an
    HMAC algorithm keyed off the public key). It is deliberately not configurable.
    """

    def __init__(self, settings: ComlinkSettings) -> None:
        self._jwks_url = settings.access_jwks_url
        self._audience = settings.access_aud
        self._issuer = settings.access_issuer
        self._allowed_emails = frozenset(settings.access_allowed_emails)
        self._keys: dict[str, jwt.PyJWK] = {}
        # Monotonic timestamp of the last *successful* JWKS fetch; ``None`` until the
        # first one. Drives the unknown-kid refresh throttle (MEDIUM-1).
        self._last_fetch_monotonic: float | None = None
        # Single-flight guard: concurrent unknown-kid requests must not each fire a
        # fetch (MEDIUM-1). Only the first holder refetches; the rest re-check the
        # cache after acquiring the lock.
        self._fetch_lock = asyncio.Lock()
        # One client for the validator's lifetime instead of one per fetch (INFO-2).
        # Built lazily, only inside the fetch lock, so construction is never raced.
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Return the shared HTTP client, constructing it once on first use."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=_JWKS_FETCH_TIMEOUT_SECONDS)
        return self._client

    async def _fetch_jwks(self) -> None:
        """Fetch the JWKS and replace the local key cache.

        Fail-closed (MEDIUM-2): any network / HTTP-status / JSON-parse failure is
        converted to ``AccessValidationError`` so the middleware turns it into a
        deliberate 401 reject, rather than letting a raw httpx/json exception escape
        ``validate()`` as a 500. The wrapped app is never reached either way, but the
        explicit reject keeps the failure mode intentional and testable.
        """
        client = self._get_client()
        try:
            response = await client.get(self._jwks_url)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # ValueError covers json.JSONDecodeError (malformed body).
            raise AccessValidationError("jwks fetch failed") from exc
        if not isinstance(payload, dict):
            raise AccessValidationError("jwks fetch failed: unexpected payload")
        keys: dict[str, jwt.PyJWK] = {}
        for entry in payload.get("keys", []):
            kid = entry.get("kid")
            if kid is None:
                continue
            try:
                keys[kid] = jwt.PyJWK.from_dict(entry)
            except jwt.PyJWKError:
                # Skip keys we cannot construct rather than failing the refresh.
                continue
        self._keys = keys
        self._last_fetch_monotonic = time.monotonic()

    def _refresh_throttled(self) -> bool:
        """True if a JWKS refresh happened within ``_JWKS_MIN_REFRESH_SECONDS``."""
        last = self._last_fetch_monotonic
        return last is not None and (time.monotonic() - last) < _JWKS_MIN_REFRESH_SECONDS

    async def _signing_key(self, kid: str) -> jwt.PyJWK:
        """Return the signing key for ``kid``, refreshing the JWKS once if needed.

        On an unknown ``kid`` the refresh is throttled (MEDIUM-1): if the last
        successful fetch was less than ``_JWKS_MIN_REFRESH_SECONDS`` ago, reject
        immediately instead of refetching. Refreshes are single-flighted under
        ``_fetch_lock`` with a double-checked cache read so concurrent unknown-kid
        requests trigger at most one fetch.
        """
        key = self._keys.get(kid)
        if key is not None:
            return key
        async with self._fetch_lock:
            # Double-check: another request may have refreshed while we waited.
            key = self._keys.get(kid)
            if key is not None:
                return key
            if self._refresh_throttled():
                raise AccessValidationError("unknown signing key")
            await self._fetch_jwks()
        key = self._keys.get(kid)
        if key is None:
            raise AccessValidationError("unknown signing key")
        return key

    async def validate(self, token: str) -> dict[str, Any]:
        """Validate ``token`` and return its claims, or raise AccessValidationError."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise AccessValidationError("malformed token") from exc

        kid = header.get("kid")
        if not kid:
            raise AccessValidationError("token missing kid")

        signing_key = await self._signing_key(kid)

        # LOW-2 (replay): ``exp`` is the only temporal bound enforced here — a captured
        # assertion replays freely until it expires. There is no nonce/jti tracking
        # (inherent to stateless JWT validation); the lever is the Cloudflare Access
        # token TTL, kept short in the team config. No code change is warranted.
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key,
                # Hardcoded: alg-confusion defense. Do NOT make configurable.
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.InvalidTokenError as exc:
            raise AccessValidationError("invalid token") from exc

        if self._allowed_emails:
            email = claims.get("email")
            if email not in self._allowed_emails:
                raise AccessValidationError("email not allowed")

        return claims


class CloudflareAccessMiddleware:
    """ASGI middleware that enforces Cloudflare Access JWT validation.

    Non-HTTP scopes (e.g. lifespan) pass straight through. Every HTTP request must
    carry a valid ``Cf-Access-Jwt-Assertion`` header or it is rejected with 401
    before reaching the wrapped application.
    """

    def __init__(self, app: ASGIApp, validator: CloudflareAccessValidator) -> None:
        self._app = app
        self._validator = validator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        token = headers.get(_ACCESS_HEADER)
        if not token:
            # WARNING (not DEBUG) on purpose: a missing assertion on a request that
            # reached the origin means either a direct in-cluster hit (the threat this
            # gate exists for) or that Cloudflare is not injecting the header on this
            # path — e.g. the Claude-app Managed-OAuth flow. The log is the signal that
            # tells us which before we ever flip COMLINK_REQUIRE_ACCESS_JWT to true.
            logger.warning(
                "Rejecting request to %s: no Cf-Access-Jwt-Assertion header. Either a "
                "direct (non-Cloudflare) origin hit, or Cloudflare is not injecting the "
                "assertion on this path.",
                scope.get("path", "<unknown>"),
            )
            await self._reject(scope, receive, send, "missing access assertion")
            return

        try:
            await self._validator.validate(token)
        except AccessValidationError:
            await self._reject(scope, receive, send, "invalid access assertion")
            return

        await self._app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, detail: str) -> None:
        """Send a 401 response without invoking the wrapped application."""
        response = JSONResponse({"error": "unauthorized", "detail": detail}, status_code=401)
        await response(scope, receive, send)
