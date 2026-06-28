# Phase 2 / Epic 5 — T1: Remote-Deployment Auth Intel

**Author:** Echo (intel/comms)
**Date:** 2026-06-28
**Scope:** Authoritative findings the squad needs before any auth/transport code is written for Comlink's public HTTPS streamable-http deployment (K3s "Gonk", behind Traefik, reachable from Claude mobile / claude.ai).
**Ground truth (given, not re-derived):** installed SDK is `mcp` 1.27.2; full server-auth package present under `mcp/server/auth/`; Comlink uses `from mcp.server.fastmcp import FastMCP` and today runs stdio only.

Confidence legend: **verified** = read from installed source or quoted from a dated spec/vendor doc; **inferred** = reasoned from those; **unknown** = not determinable from available sources.

---

## 1. MCP authorization spec (current) — what the server MUST be

**Source:** MCP Authorization spec, revision **2025-06-18** — https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization (fetched 2026-06-28). This is the current authorization revision; it builds on OAuth 2.1 draft-13, RFC 8414, RFC 7591, RFC 9728, RFC 8707. **Confidence: verified.**

Normative requirements relevant to Comlink:

- **The MCP server IS an OAuth 2.1 Protected Resource / Resource Server.** "A protected *MCP server* acts as an OAuth 2.1 resource server." Authorization itself is OPTIONAL, but HTTP transports that protect data **SHOULD** conform — and a public, identity-scoped mailbox server is squarely in scope.
- **Audience-bound tokens are mandatory.** "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2." And: servers "**MUST** reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient." This is the load-bearing requirement for Comlink.
- **Protected Resource Metadata (RFC 9728) is mandatory on the server.** "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata." The document **MUST** include `authorization_servers` (≥1). Discovery endpoint: `GET /.well-known/oauth-protected-resource[/<path>]`.
- **Authorization Server Metadata (RFC 8414) is mandatory on the AS** (not necessarily the MCP server if AS is separate): `GET /.well-known/oauth-authorization-server`. MCP clients **MUST** use it.
- **401 + `WWW-Authenticate` is mandatory.** On missing/invalid token the server **MUST** return HTTP 401 and **MUST** use `WWW-Authenticate` to point at the resource-metadata URL (RFC 9728 §5.1). 403 for insufficient scope, 400 for malformed request.
- **Client side (informational):** clients **MUST** send `resource` (RFC 8707) on both authorize and token requests, **MUST** use PKCE S256, **MUST** use registered redirect URIs. DCR (RFC 7591) is **SHOULD** for both client and AS.
- **No token passthrough:** if the MCP server calls upstream APIs it MUST use a separately-issued token, never forward the client's token.

**Bottom line:** the spec requires *real* audience-bound resource-server validation living logically at the MCP resource server, plus RFC 9728 metadata + 401/`WWW-Authenticate` discovery affordances. "Someone logged in at the edge" does not satisfy it.

---

## 2. How Claude (mobile / claude.ai) initiates OAuth against a remote MCP server

**Sources:** Claude developer docs — "Authentication for connectors," https://claude.com/docs/connectors/building/authentication (fetched 2026-06-28); Claude Help Center "Get started with custom connectors using remote MCP." **Confidence: verified (vendor doc, quoted).**

- **Registration:** Claude supports three mechanisms, auto-selected:
  1. **Dynamic Client Registration (RFC 7591)** — default; Claude "registers a new client on every fresh connection" if CIMD isn't advertised. (Note the churn implication: a *new* `client_id` per fresh connection.)
  2. **Client ID Metadata Documents (CIMD)** — chosen only when AS metadata advertises both `"client_id_metadata_document_supported": true` and `"none"` in `token_endpoint_auth_methods_supported`.
  3. **Anthropic-held credentials** — manual, via `mcp-review@anthropic.com`.
- **PKCE:** Claude "includes a PKCE `code_challenge` with `code_challenge_method=S256` on every authorization request, regardless of which registration mechanism it uses." PKCE S256 is non-negotiable.
- **Resource / audience parameter:** the Protected Resource Metadata `resource` field "must match your MCP server URL exactly as the user enters it in Claude, including any path component." Claude sends that value as the RFC 8707 `resource` in token requests. **Practical consequence for Comlink:** pick one canonical URL (e.g. `https://comlink.chaosbit.dev/mcp`), advertise it as `resource`, and validate `aud`/`resource` against exactly that.
- **Discovery probing order** (when the 401 lacks a `WWW-Authenticate: Bearer resource_metadata=…` header): `/.well-known/oauth-protected-resource/<your-mcp-path>` first, then `/.well-known/oauth-protected-resource` at the origin. Emitting the `WWW-Authenticate` pointer is the deterministic path and is what the SDK does.
- **Redirect/callback URLs:**
  - Hosted Claude (mobile/claude.ai): `https://claude.ai/api/mcp/auth_callback`.
  - Claude Code: RFC 8252 loopback, e.g. `http://localhost:3118/callback`; must accept both `localhost` and `127.0.0.1`, port-agnostic.
  - Comlink's AS must register/accept the hosted callback exactly.

---

## 3. The installed FastMCP auth API — concretely, from source

All paths below are under `/Users/brandon/projects/comlink/.venv/lib/python3.13/site-packages/`. **Confidence: verified (read directly).**

### 3a. How FastMCP accepts auth config
`mcp/server/fastmcp/server.py` `FastMCP.__init__` (lines ~150–231) takes three relevant params:
- `auth_server_provider: OAuthAuthorizationServerProvider | None = None` — full AS (you mint/store tokens).
- `token_verifier: TokenVerifier | None = None` — RS-only (you verify someone else's tokens).
- `auth: AuthSettings | None = None` — the settings object that turns the feature on.

Validation rules enforced in the constructor (lines 218–224):
- If `auth` set, you **MUST** supply exactly one of `auth_server_provider` / `token_verifier` (not both, not neither).
- If `auth` is `None`, supplying either provider raises.
- If `auth_server_provider` is given without `token_verifier`, FastMCP wraps it: `self._token_verifier = ProviderTokenVerifier(auth_server_provider)` (line 231).

`AuthSettings` fields — `mcp/server/auth/settings.py`:
- `issuer_url: AnyHttpUrl` (required) — the AS that issues tokens.
- `resource_server_url: AnyHttpUrl | None` — **this is what triggers RFC 9728 Protected Resource Metadata routes and the `WWW-Authenticate` `resource_metadata` pointer.** For RS-mode it must be set to Comlink's canonical URL.
- `required_scopes: list[str] | None` — enforced by `RequireAuthMiddleware`.
- `service_documentation_url`, `client_registration_options: ClientRegistrationOptions` (DCR on/off, valid/default scopes), `revocation_options`.

Transport `Settings` fields (same `server.py`, lines ~98–129): `host` (default `127.0.0.1`), `port` (8000), `streamable_http_path` (default `/mcp`), `json_response` (bool), `stateless_http` (bool), `mount_path`, `transport_security: TransportSecuritySettings | None`.

### 3b. The interfaces you implement / supply
`mcp/server/auth/provider.py`:
- **`TokenVerifier` (Protocol, line 96)** — the minimal RS contract. One method:
  ```python
  async def verify_token(self, token: str) -> AccessToken | None: ...
  ```
  Return an `AccessToken` if valid, `None` if not. **This is the only place Comlink can enforce audience/signature/issuer.** The SDK does NOT do it for you (see §3c and §6).
- **`AccessToken` (BaseModel, line 39)** — fields: `token`, `client_id`, `scopes: list[str]`, `expires_at: int | None`, `resource: str | None` (RFC 8707), `subject: str | None` (the `sub`/resource-owner), `claims: dict | None` (e.g. `iss`, `act`).
- **`OAuthAuthorizationServerProvider` (Protocol, line 110)** — the full-AS contract: `get_client`, `register_client`, `authorize`, `load_authorization_code`, `exchange_authorization_code`, `load_refresh_token`, `exchange_refresh_token`, `load_access_token`, `revoke_token`. Only needed if Comlink itself is the authorization server.
- **`ProviderTokenVerifier` (line 292)** — adapter that calls `provider.load_access_token`; "backwards compatibility" shim. Docstring explicitly steers new RS/AS-separation deployments toward a dedicated `TokenVerifier` "like `IntrospectionTokenVerifier`" — **note that class is NOT in the installed package** (see §6).

### 3c. `bearer_auth.py` middleware and what it actually checks
`mcp/server/auth/middleware/bearer_auth.py`:
- `BearerAuthBackend.authenticate` (line 54): pulls the `Authorization: Bearer <token>` header, calls `token_verifier.verify_token(token)`, and — the only checks the SDK itself performs — rejects if the verifier returns falsy (line 67) or if `auth_info.expires_at < now` (line 70). **It does NOT check audience, issuer, or signature.** Those are entirely the verifier's job.
- On success it produces `AuthenticatedUser(auth_info)` (a Starlette `SimpleUser` whose username is `client_id`) plus `AuthCredentials(auth_info.scopes)`.
- `RequireAuthMiddleware` (line 76): rejects with **401 `invalid_token`** if no authenticated user; **403 `insufficient_scope`** if a `required_scopes` entry is missing. `_send_auth_error` emits the `WWW-Authenticate: Bearer ...` header and, when `resource_metadata_url` is set, appends `resource_metadata="<url>"` (lines 125–129) — satisfying the spec's discovery pointer.

### 3d. Reading subject/scopes inside a tool
`mcp/server/auth/middleware/auth_context.py`:
- `AuthContextMiddleware` stows the authenticated user in a `contextvars.ContextVar`.
- `get_access_token() -> AccessToken | None` (line 13) is the call a tool uses at request time. From the returned `AccessToken` you read `.subject` (the user identity — exactly the "scoped to the user's identity" check Comlink wants), `.scopes`, `.client_id`, `.claims`.
  ```python
  from mcp.server.auth.middleware.auth_context import get_access_token
  tok = get_access_token()
  if tok is None or tok.subject != EXPECTED_SUBJECT:
      raise PermissionError("not the mailbox owner")
  ```

### 3e. streamable-http wiring (host/port/path/stateless/session)
`mcp/server/fastmcp/server.py` `streamable_http_app()` (lines 950–1045):
- Lazily builds a `StreamableHTTPSessionManager` (line 956) with `json_response=settings.json_response`, `stateless=settings.stateless_http`, `security_settings=settings.transport_security`.
- If `auth` + `token_verifier` are set: installs `AuthenticationMiddleware(backend=BearerAuthBackend(token_verifier))` then `AuthContextMiddleware` (lines 978–985), and wraps the `/mcp` route (`settings.streamable_http_path`) in `RequireAuthMiddleware(...)` with the resource-metadata URL (lines 1002–1016).
- If `auth.resource_server_url` is set, mounts the RFC 9728 routes via `create_protected_resource_routes(...)` (lines 1027–1036) — i.e. `/.well-known/oauth-protected-resource[/<path>]` listing `authorization_servers=[issuer_url]`.
- `run(transport="streamable-http")` (line 281, dispatch at 300) calls `run_streamable_http_async` → uvicorn on `settings.host:settings.port`.

**Transport-security gotcha (verified):** in `__init__` (lines 178–182), DNS-rebinding protection (`allowed_hosts`/`allowed_origins`) is auto-enabled **only** when `host in ("127.0.0.1","localhost","::1")`. On a public bind it is **off unless you pass `TransportSecuritySettings` explicitly.** Behind Traefik, set `allowed_hosts`/`allowed_origins` to the public hostname. **Confidence: verified.**

### 3f. Minimal correct code sketches (from the real signatures)
RS-only mode (Comlink validates tokens issued by an external AS — the recommended shape):
```python
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.provider import TokenVerifier, AccessToken
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth_utils import check_resource_allowed  # see §3g

CANONICAL_RESOURCE = "https://comlink.chaosbit.dev/mcp"

class ComlinkTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        # Tech must implement: verify signature (JWKS) OR introspect (RFC 7662),
        # check iss == issuer, exp/nbf, and audience == CANONICAL_RESOURCE.
        claims = await _validate_jwt_or_introspect(token)   # hand-built
        if claims is None:
            return None
        aud = claims.get("aud") or claims.get("resource")
        if not aud or not check_resource_allowed(str(aud), CANONICAL_RESOURCE):
            return None  # audience binding — NOT done by the SDK
        return AccessToken(
            token=token,
            client_id=claims.get("client_id", claims["sub"]),
            scopes=claims.get("scope", "").split(),
            expires_at=claims.get("exp"),
            resource=CANONICAL_RESOURCE,
            subject=claims["sub"],
            claims=claims,
        )

mcp = FastMCP(
    "comlink",
    host="0.0.0.0",            # bind for in-cluster; Traefik terminates TLS
    port=8000,
    streamable_http_path="/mcp",
    stateless_http=True,       # see §4 note on K3s/Traefik horizontal scaling
    token_verifier=ComlinkTokenVerifier(),
    auth=AuthSettings(
        issuer_url="https://<your-AS>/",          # e.g. the OIDC provider
        resource_server_url=CANONICAL_RESOURCE,   # triggers RFC 9728 + WWW-Authenticate
        required_scopes=["comlink.read"],         # optional
    ),
    transport_security=TransportSecuritySettings(
        allowed_hosts=["comlink.chaosbit.dev"],
        allowed_origins=["https://comlink.chaosbit.dev"],
    ),
)
# mcp.run(transport="streamable-http")
```

### 3g. Helper that exists (use it, don't reinvent the matcher)
`mcp/shared/auth_utils.py`: `check_resource_allowed(requested, configured)` does origin + hierarchical-path matching; `resource_url_from_server_url(...)` canonicalizes (lowercase scheme/host, strip fragment). These are pure helpers — the **server bearer path never calls them for you**, but your `verify_token` should. **Confidence: verified.**

---

## 4. Validation placement — proxy vs in-server vs both

The decisive question: *can a generic edge proxy satisfy the discovery + audience-bound RS validation the Claude app probes?*

- **What Claude requires to live at the MCP resource server:** the RFC 9728 Protected Resource Metadata at `/.well-known/oauth-protected-resource[/mcp]` (matching the canonical `resource`) and the 401 + `WWW-Authenticate` pointer. The SDK emits both *only* when `auth` + `token_verifier` + `resource_server_url` are configured. A bolt-on proxy *could* serve those static JSON/headers, but it must advertise the exact canonical resource and the matching AS — and then *something* must still verify the `aud` claim per request.

- **(a) In-server `TokenVerifier`** — validates signature/issuer/expiry **and audience** per request inside `verify_token`. This is the only option that natively produces the spec-required audience binding *and* exposes `subject`/`scopes` to tools via `get_access_token()`. **Recommended core.**

- **(b) oauth2-proxy / Traefik forward-auth sidecar ALONE** — **does NOT give audience-bound RS validation.** oauth2-proxy authenticates a *browser/user session* (it logs someone in against an IdP and checks their email/group) and forwards the request; it generally validates an ID/session, not that a *bearer access token's `aud` equals Comlink's canonical URL*. It also does not speak the MCP 401/`WWW-Authenticate`/RFC 9728 discovery handshake the Claude app drives. **Plainly: an edge proxy alone proves "someone logged in," not "this token was minted for Comlink."** That is exactly the gap the user is worried about. If today's DNS+OAuth layer is oauth2-proxy-style edge login, it is **not** audience-bound RS validation and does not meet the spec.

- **(c) Defense-in-depth (both)** — Traefik/IdP at the edge for network-level gating and TLS, **plus** the in-server `TokenVerifier` doing real RFC 8707 audience + signature + scope checks and feeding `subject` to tools. Edge can reduce blast radius (rate-limit, IP allowlist, drop unauthenticated noise) but is never the audience authority.

**Recommendation for Comlink:** Adopt **(c) with (a) as the authoritative gate.** Run FastMCP in RS-only mode with a hand-built `ComlinkTokenVerifier` that enforces `aud == https://comlink.chaosbit.dev/mcp`, issuer, expiry, signature, and the owner `subject`; set `AuthSettings.resource_server_url` so the SDK serves RFC 9728 metadata and the 401 pointer the Claude app needs. Keep Traefik/IdP at the edge for TLS + coarse gating only — never rely on it for audience binding. This directly contains the memory-flagged threat (email-borne prompt injection of Brandon's own session): the send gate plus a per-request audience/subject check means a stolen or wrong-audience token is rejected at the resource server, not merely waved through by an edge login. Pair with `stateless_http=True` if running >1 replica behind Traefik, since session affinity across pods otherwise needs an `EventStore`/sticky sessions (transport detail, not auth).

---

## 5. Executive summary (one bullet per question)

- **Q1 (spec):** The 2025-06-18 MCP authorization spec makes the MCP server an OAuth 2.1 Resource Server that **MUST** validate audience-bound (RFC 8707) tokens, **MUST** serve RFC 9728 Protected Resource Metadata, and **MUST** return 401 + `WWW-Authenticate` resource-metadata pointer on missing/invalid tokens.
- **Q2 (Claude client):** Claude defaults to **DCR (new client per fresh connection)** or CIMD, always sends **PKCE S256**, sends an RFC 8707 `resource` that **must exactly match** the advertised MCP URL, probes `/.well-known/oauth-protected-resource/<path>` then origin, and uses callback `https://claude.ai/api/mcp/auth_callback`.
- **Q3 (SDK API):** FastMCP 1.27.2 wires auth via `auth=AuthSettings(...)` + one of `token_verifier`/`auth_server_provider`; `TokenVerifier.verify_token` is the single RS hook; bearer middleware only checks presence + expiry; tools read identity via `get_access_token().subject/.scopes`; streamable-http is `run(transport="streamable-http")` on `host:port` + `streamable_http_path=/mcp`.
- **Q4 (placement):** Audience-bound validation must be in-server (`TokenVerifier`); an edge proxy alone gives "someone logged in," not RFC 8707 audience binding, and can't satisfy the discovery handshake — recommend defense-in-depth with the in-server verifier as the authority.

**Single most important finding:** The installed SDK can *enforce* audience-bound validation, **but it does not perform any audience/signature/issuer check itself** — `BearerAuthBackend` only checks token presence and `expires_at`. Whether Comlink is actually audience-bound depends entirely on a `TokenVerifier.verify_token` that Tech must hand-write to check `aud == https://comlink.chaosbit.dev/mcp` (the SDK ships the `check_resource_allowed` helper but never calls it on the server path, and ships **no** concrete JWT/introspection verifier). So: yes, Comlink can rely on the SDK for the *plumbing and discovery*, but **not** for the audience validation logic — that is custom code, and it is exactly what stands between Brandon's mailbox and a wrong-audience/stolen token.

---

## 6. What the SDK does NOT provide — Tech must hand-build

- **A concrete token verifier.** No `IntrospectionTokenVerifier`, no JWT/JWKS verifier, no `aud`/signature/issuer checking exists in the installed package (`TokenVerifier` is a bare Protocol; `ProviderTokenVerifier` only delegates to `load_access_token`). Verified by enumerating `mcp/server/auth/` — only `provider.py`, `routes.py`, `settings.py`, `handlers/*`, `middleware/*`. Tech writes the verifier (JWKS validation or RFC 7662 introspection).
- **Audience enforcement.** Not done anywhere in the server bearer path; must live inside `verify_token` (use `mcp/shared/auth_utils.check_resource_allowed`).
- **An authorization server.** If Comlink can't lean on an external AS/IdP (Authentik, Keycloak, Auth0, etc.), implementing `OAuthAuthorizationServerProvider` is a large build (authorize/token/register/refresh/revoke + secure code/token storage). Strongly prefer RS-only mode + external AS.
- **Public-bind transport security.** DNS-rebinding `allowed_hosts`/`allowed_origins` are NOT auto-set off-localhost; must pass `TransportSecuritySettings` explicitly.
- **Multi-replica session continuity.** Streamable-http sessions are per-process; horizontal scaling on K3s needs `stateless_http=True` or a shared `EventStore` + sticky routing (transport concern, flagged for Hunter).
- **DCR client churn handling (unknown / needs empirical test).** Claude's default DCR registers a *new* `client_id` per fresh connection. How the chosen AS handles a flood of dynamic registrations, and whether to prefer CIMD (advertise `client_id_metadata_document_supported`) instead, is **unknown** from docs alone — recommend Wrecker run an empirical connect test against the candidate AS once selected. **Confidence: unknown.**

---

## Sources
- MCP Authorization spec, rev 2025-06-18 — https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- Claude developer docs, "Authentication for connectors" — https://claude.com/docs/connectors/building/authentication
- Claude Help Center, custom connectors via remote MCP — https://support.claude.com/en/articles/11503834-building-custom-connectors-via-remote-mcp-servers
- Installed SDK `mcp` 1.27.2 source under `/Users/brandon/projects/comlink/.venv/lib/python3.13/site-packages/mcp/` (files cited inline).
