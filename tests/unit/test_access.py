"""Cloudflare Access JWT validation and ASGI middleware (Epic 5).

Tokens are minted in-process with a self-signed RSA key; the validator's key cache
is monkeypatched directly (or its _fetch_jwks replaced) so no test ever touches the
network. The hardcoded ``algorithms=["RS256"]`` is exercised as the alg-confusion
defense: alg=none and an HS256 forgery keyed off the public key must both be rejected.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from comlink.access import (
    _JWKS_MIN_REFRESH_SECONDS,
    AccessValidationError,
    CloudflareAccessMiddleware,
    CloudflareAccessValidator,
)
from comlink.config import ComlinkSettings

from ..conftest import make_settings

if TYPE_CHECKING:
    from starlette.requests import Request

TEAM_DOMAIN = "chaosbit.cloudflareaccess.com"
ISSUER = f"https://{TEAM_DOMAIN}"
JWKS_URL = f"https://{TEAM_DOMAIN}/cdn-cgi/access/certs"
AUD = "test-aud-tag"
ALLOWED_EMAIL = "brandon@chaosbit.dev"


def _make_key(kid: str) -> tuple[rsa.RSAPrivateKey, jwt.PyJWK]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    assert isinstance(jwk_dict, dict)
    jwk_dict["kid"] = kid
    jwk_dict["alg"] = "RS256"
    jwk_dict["use"] = "sig"
    return private_key, jwt.PyJWK.from_dict(jwk_dict)


def _sign(
    private_key: rsa.RSAPrivateKey,
    kid: str,
    *,
    aud: str = AUD,
    iss: str = ISSUER,
    email: str = ALLOWED_EMAIL,
    exp_delta: int = 300,
) -> str:
    now = int(time.time())
    claims = {
        "aud": aud,
        "iss": iss,
        "email": email,
        "iat": now,
        "exp": now + exp_delta,
        "sub": "user-123",
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _validator_with_key(
    settings: ComlinkSettings, kid: str, key: jwt.PyJWK
) -> CloudflareAccessValidator:
    """Build a validator whose key cache is pre-seeded — no network fetch."""
    validator = CloudflareAccessValidator(settings)
    validator._keys = {kid: key}
    return validator


class _RaisingClient:
    """Stand-in for the validator's httpx client whose GET always fails."""

    async def get(self, url: str) -> httpx.Response:
        raise httpx.ConnectError("simulated JWKS network failure")


@pytest.fixture
def keypair() -> tuple[rsa.RSAPrivateKey, jwt.PyJWK]:
    return _make_key("kid-1")


@pytest.fixture
def settings() -> ComlinkSettings:
    return make_settings(
        require_access_jwt=True,
        access_aud=AUD,
        access_team_domain=TEAM_DOMAIN,
        access_allowed_emails=[ALLOWED_EMAIL],
    )


class TestValidator:
    async def test_valid_token_passes(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        validator = _validator_with_key(settings, "kid-1", jwk)
        claims = await validator.validate(_sign(private_key, "kid-1"))
        assert claims["email"] == ALLOWED_EMAIL

    async def test_bad_signature_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        _, jwk = keypair
        # Sign with a *different* key than the one in the cache.
        other_key, _ = _make_key("kid-1")
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(other_key, "kid-1"))

    async def test_wrong_aud_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(private_key, "kid-1", aud="someone-else"))

    async def test_wrong_issuer_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(private_key, "kid-1", iss="https://evil.example"))

    async def test_expired_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(private_key, "kid-1", exp_delta=-10))

    async def test_missing_required_claim_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        # A token with no iat must be rejected by options={"require": [...]}.
        private_key, jwk = keypair
        now = int(time.time())
        token = jwt.encode(
            {"aud": AUD, "iss": ISSUER, "exp": now + 300, "email": ALLOWED_EMAIL},
            private_key,
            algorithm="RS256",
            headers={"kid": "kid-1"},
        )
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(token)

    async def test_email_not_allowed_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(private_key, "kid-1", email="intruder@evil.example"))

    async def test_empty_allowlist_skips_email_check(
        self,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        settings = make_settings(
            access_aud=AUD,
            access_team_domain=TEAM_DOMAIN,
            access_allowed_emails=[],
        )
        validator = _validator_with_key(settings, "kid-1", jwk)
        claims = await validator.validate(_sign(private_key, "kid-1", email="anyone@example.com"))
        assert claims["email"] == "anyone@example.com"

    async def test_alg_none_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        # alg=none forgery — the unsigned-token attack. Must never validate.
        _, jwk = keypair
        now = int(time.time())
        token = jwt.encode(
            {"aud": AUD, "iss": ISSUER, "iat": now, "exp": now + 300, "email": ALLOWED_EMAIL},
            key="",
            algorithm="none",
            headers={"kid": "kid-1"},
        )
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(token)

    async def test_hs256_forgery_rejected(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        # Alg-confusion: the classic attack forges an HS256 token keyed off the RSA
        # public key. Because algorithms is hardcoded to RS256, the validator never
        # attempts HMAC verification, so any HS256 token — whatever its secret — is
        # rejected. (Modern PyJWT also refuses to *encode* HS256 with a PEM key, so the
        # forgery here uses an arbitrary secret; the rejection is the same either way.)
        _, jwk = keypair
        now = int(time.time())
        token = jwt.encode(
            {"aud": AUD, "iss": ISSUER, "iat": now, "exp": now + 300, "email": ALLOWED_EMAIL},
            key="attacker-controlled-secret-padded-to-32-bytes-minimum",
            algorithm="HS256",
            headers={"kid": "kid-1"},
        )
        validator = _validator_with_key(settings, "kid-1", jwk)
        with pytest.raises(AccessValidationError):
            await validator.validate(token)

    async def test_unknown_kid_triggers_single_refresh(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Cache empty -> first unknown kid forces exactly one refresh that publishes it.
        new_priv, new_jwk = _make_key("kid-new")
        validator = CloudflareAccessValidator(settings)
        calls = {"n": 0}

        async def fake_fetch() -> None:
            calls["n"] += 1
            validator._keys = {"kid-new": new_jwk}

        monkeypatch.setattr(validator, "_fetch_jwks", fake_fetch)
        claims = await validator.validate(_sign(new_priv, "kid-new"))
        assert claims["sub"] == "user-123"
        assert calls["n"] == 1

    async def test_unknown_kid_after_refresh_rejected(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The refresh publishes kid-1, but the token's kid is never present, so even
        # after the single refresh the lookup fails with "unknown signing key".
        _, jwk = _make_key("kid-1")
        validator = CloudflareAccessValidator(settings)

        async def fake_fetch() -> None:
            validator._keys = {"kid-1": jwk}

        monkeypatch.setattr(validator, "_fetch_jwks", fake_fetch)
        other_priv, _ = _make_key("kid-missing")
        with pytest.raises(AccessValidationError, match="unknown signing key"):
            await validator.validate(_sign(other_priv, "kid-missing"))

    async def test_malformed_token_rejected(self, settings: ComlinkSettings) -> None:
        validator = CloudflareAccessValidator(settings)
        with pytest.raises(AccessValidationError, match="malformed token"):
            await validator.validate("not-a-jwt")

    async def test_jwks_fetch_failure_raises_access_error(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # MEDIUM-2: a JWKS fetch failure must surface as AccessValidationError (a
        # deliberate reject), never a raw httpx error that would escape as a 500.
        validator = CloudflareAccessValidator(settings)
        monkeypatch.setattr(validator, "_get_client", lambda: _RaisingClient())
        priv, _ = _make_key("kid-x")
        with pytest.raises(AccessValidationError):
            await validator.validate(_sign(priv, "kid-x"))

    async def test_unknown_kid_refresh_throttled(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # MEDIUM-1: the first unknown kid forces one (unsuccessful) refresh; a second
        # unknown kid within the min-refresh interval must NOT trigger another fetch.
        validator = CloudflareAccessValidator(settings)
        calls = {"n": 0}

        async def fake_fetch() -> None:
            calls["n"] += 1
            validator._keys = {}  # refresh succeeds but publishes nothing useful
            validator._last_fetch_monotonic = time.monotonic()

        monkeypatch.setattr(validator, "_fetch_jwks", fake_fetch)

        priv_a, _ = _make_key("kid-A")
        with pytest.raises(AccessValidationError, match="unknown signing key"):
            await validator.validate(_sign(priv_a, "kid-A"))
        assert calls["n"] == 1

        priv_b, _ = _make_key("kid-B")
        with pytest.raises(AccessValidationError, match="unknown signing key"):
            await validator.validate(_sign(priv_b, "kid-B"))
        assert calls["n"] == 1  # throttled — no second fetch

    async def test_unknown_kid_refetches_after_interval(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Genuine key rotation still recovers: once the interval has elapsed since the
        # last successful fetch, a new kid triggers a single refresh that publishes it.
        new_priv, new_jwk = _make_key("kid-rot")
        validator = CloudflareAccessValidator(settings)
        validator._last_fetch_monotonic = time.monotonic() - (_JWKS_MIN_REFRESH_SECONDS + 1.0)
        calls = {"n": 0}

        async def fake_fetch() -> None:
            calls["n"] += 1
            validator._keys = {"kid-rot": new_jwk}
            validator._last_fetch_monotonic = time.monotonic()

        monkeypatch.setattr(validator, "_fetch_jwks", fake_fetch)
        claims = await validator.validate(_sign(new_priv, "kid-rot"))
        assert claims["sub"] == "user-123"
        assert calls["n"] == 1

    async def test_concurrent_unknown_kid_single_flight(
        self,
        settings: ComlinkSettings,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # MEDIUM-1 single-flight: concurrent requests for the same new kid trigger at
        # most one fetch; the rest re-check the cache after the lock and reuse it.
        import asyncio

        new_priv, new_jwk = _make_key("kid-sf")
        validator = CloudflareAccessValidator(settings)
        calls = {"n": 0}

        async def fake_fetch() -> None:
            calls["n"] += 1
            await asyncio.sleep(0.05)
            validator._keys = {"kid-sf": new_jwk}
            validator._last_fetch_monotonic = time.monotonic()

        monkeypatch.setattr(validator, "_fetch_jwks", fake_fetch)
        token = _sign(new_priv, "kid-sf")
        results = await asyncio.gather(*(validator.validate(token) for _ in range(5)))
        assert all(claims["sub"] == "user-123" for claims in results)
        assert calls["n"] == 1


def _build_app(validator: CloudflareAccessValidator) -> CloudflareAccessMiddleware:
    async def endpoint(request: Request) -> PlainTextResponse:
        _ = request
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/mcp", endpoint, methods=["GET", "POST"])])
    return CloudflareAccessMiddleware(inner, validator)


class TestMiddleware:
    def test_missing_header_returns_401(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        _, jwk = keypair
        client = TestClient(_build_app(_validator_with_key(settings, "kid-1", jwk)))
        resp = client.get("/mcp")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "missing access assertion"

    def test_valid_header_passes_through(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        private_key, jwk = keypair
        client = TestClient(_build_app(_validator_with_key(settings, "kid-1", jwk)))
        resp = client.get("/mcp", headers={"Cf-Access-Jwt-Assertion": _sign(private_key, "kid-1")})
        assert resp.status_code == 200
        assert resp.text == "ok"

    def test_invalid_header_returns_401(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        _, jwk = keypair
        client = TestClient(_build_app(_validator_with_key(settings, "kid-1", jwk)))
        resp = client.get("/mcp", headers={"Cf-Access-Jwt-Assertion": "not-a-jwt"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "invalid access assertion"

    def test_missing_header_logs_warning(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The WARNING is the operational signal that Cloudflare may not be injecting
        # the assertion on a given path — assert it fires on a header-less request.
        _, jwk = keypair
        client = TestClient(_build_app(_validator_with_key(settings, "kid-1", jwk)))
        with caplog.at_level("WARNING", logger="comlink.access"):
            client.get("/mcp")
        assert any("Cf-Access-Jwt-Assertion" in rec.message for rec in caplog.records)

    def test_jwks_fetch_failure_fails_closed(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The auth-gate property: when the JWKS fetch fails (unknown kid, no cache),
        # the request is rejected non-2xx AND the wrapped app is NEVER invoked. Goes
        # through the real _fetch_jwks (client stubbed to raise) to pin the MEDIUM-2
        # conversion end-to-end.
        private_key, _ = keypair
        validator = CloudflareAccessValidator(settings)  # empty key cache
        monkeypatch.setattr(validator, "_get_client", lambda: _RaisingClient())

        called = {"n": 0}

        async def endpoint(request: Request) -> PlainTextResponse:
            _ = request
            called["n"] += 1
            return PlainTextResponse("ok")

        inner = Starlette(routes=[Route("/mcp", endpoint, methods=["GET"])])
        client = TestClient(CloudflareAccessMiddleware(inner, validator))
        resp = client.get(
            "/mcp", headers={"Cf-Access-Jwt-Assertion": _sign(private_key, "kid-unknown")}
        )
        assert resp.status_code == 401
        assert called["n"] == 0  # wrapped app never reached

    def test_non_http_scope_passes_through(
        self,
        settings: ComlinkSettings,
        keypair: tuple[rsa.RSAPrivateKey, jwt.PyJWK],
    ) -> None:
        # A lifespan (non-http) scope must reach the wrapped app unvalidated, so the
        # MCP session manager's lifespan still runs.
        _, jwk = keypair
        seen: list[str] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            seen.append(scope["type"])

        middleware = CloudflareAccessMiddleware(inner, _validator_with_key(settings, "kid-1", jwk))

        async def receive() -> dict[str, Any]:
            return {"type": "lifespan.startup"}

        async def send(message: Any) -> None:
            return None

        import anyio

        anyio.run(middleware.__call__, {"type": "lifespan"}, receive, send)
        assert seen == ["lifespan"]


class TestConfig:
    def test_default_does_not_require_jwt(self) -> None:
        assert make_settings().require_access_jwt is False

    def test_derived_urls(self) -> None:
        settings = make_settings(access_team_domain=TEAM_DOMAIN)
        assert settings.access_issuer == ISSUER
        assert settings.access_jwks_url == JWKS_URL

    def test_comma_separated_emails_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMLINK_USERNAME", "tester@example.com")
        monkeypatch.setenv("COMLINK_PASSWORD", "bridge-app-password")
        monkeypatch.setenv("COMLINK_TLS_MODE", "no-verify")
        monkeypatch.setenv("COMLINK_ACCESS_ALLOWED_EMAILS", "a@example.com, b@example.com")
        settings = ComlinkSettings()
        assert settings.access_allowed_emails == ["a@example.com", "b@example.com"]

    @pytest.mark.parametrize(
        ("overrides", "needle"),
        [
            ({"access_team_domain": TEAM_DOMAIN}, "COMLINK_ACCESS_AUD"),
            ({"access_aud": AUD}, "COMLINK_ACCESS_TEAM_DOMAIN"),
            ({}, "COMLINK_ACCESS_AUD"),
        ],
    )
    def test_gate_requires_aud_and_team(self, overrides: dict[str, Any], needle: str) -> None:
        with pytest.raises(ValueError, match=needle):
            make_settings(require_access_jwt=True, **overrides)

    def test_gate_valid_when_aud_and_team_set(self) -> None:
        settings = make_settings(
            require_access_jwt=True, access_aud=AUD, access_team_domain=TEAM_DOMAIN
        )
        assert settings.require_access_jwt is True


class _FakeServer:
    def streamable_http_app(self) -> object:
        return "inner-app"


def _patch_uvicorn(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub uvicorn so _run_http builds the app without binding a socket."""
    captured: dict[str, Any] = {}

    class _FakeUvicornServer:
        def __init__(self, config: Any) -> None:
            captured["app"] = config.app

        def run(self) -> None:
            return None

    class _FakeConfig:
        def __init__(self, app: Any, **_: Any) -> None:
            self.app = app

    import uvicorn

    monkeypatch.setattr(uvicorn, "Config", _FakeConfig)
    monkeypatch.setattr(uvicorn, "Server", _FakeUvicornServer)
    return captured


class TestStartupWarnings:
    def test_empty_email_allowlist_warns_when_gate_on(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        # LOW-1: gate ON + empty email allowlist => loud warning (no email values).
        from comlink import server as server_module

        _patch_uvicorn(monkeypatch)
        on = make_settings(
            transport="streamable-http",
            require_access_jwt=True,
            access_aud=AUD,
            access_team_domain=TEAM_DOMAIN,
        )
        with caplog.at_level("WARNING", logger="comlink.server"):
            server_module._run_http(_FakeServer(), on)  # type: ignore[arg-type]
        assert any(
            "any Cloudflare-authenticated identity is accepted" in rec.message
            for rec in caplog.records
        )

    def test_populated_email_allowlist_no_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from comlink import server as server_module

        _patch_uvicorn(monkeypatch)
        on = make_settings(
            transport="streamable-http",
            require_access_jwt=True,
            access_aud=AUD,
            access_team_domain=TEAM_DOMAIN,
            access_allowed_emails=[ALLOWED_EMAIL],
        )
        with caplog.at_level("WARNING", logger="comlink.server"):
            server_module._run_http(_FakeServer(), on)  # type: ignore[arg-type]
        assert not any(
            "any Cloudflare-authenticated identity is accepted" in rec.message
            for rec in caplog.records
        )

    def test_stdio_with_gate_warns_noop(self, caplog: pytest.LogCaptureFixture) -> None:
        # INFO-1: require_access_jwt on a non-http transport is a silent no-op -> warn.
        from comlink.server import create_server

        settings = make_settings(
            transport="stdio",
            require_access_jwt=True,
            access_aud=AUD,
            access_team_domain=TEAM_DOMAIN,
        )
        with caplog.at_level("WARNING", logger="comlink.server"):
            create_server(settings)
        assert any("no-op" in rec.message for rec in caplog.records)


class TestServerWiring:
    def test_app_wrapped_only_when_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from comlink import server as server_module

        captured: dict[str, Any] = {}

        class _FakeServer:
            def streamable_http_app(self) -> object:
                return "inner-app"

        class _FakeUvicornServer:
            def __init__(self, config: Any) -> None:
                captured["app"] = config.app

            def run(self) -> None:
                return None

        class _FakeConfig:
            def __init__(self, app: Any, **_: Any) -> None:
                self.app = app

        import uvicorn

        monkeypatch.setattr(uvicorn, "Config", _FakeConfig)
        monkeypatch.setattr(uvicorn, "Server", _FakeUvicornServer)

        # Gate OFF -> the inner app is served unwrapped.
        off = make_settings(transport="streamable-http")
        server_module._run_http(_FakeServer(), off)  # type: ignore[arg-type]
        assert captured["app"] == "inner-app"

        # Gate ON -> the app is wrapped in CloudflareAccessMiddleware.
        on = make_settings(
            transport="streamable-http",
            require_access_jwt=True,
            access_aud=AUD,
            access_team_domain=TEAM_DOMAIN,
        )
        server_module._run_http(_FakeServer(), on)  # type: ignore[arg-type]
        assert isinstance(captured["app"], CloudflareAccessMiddleware)
