# Phase 2 / Epic 5 — T2: Cloudflare Access × MCP OAuth Intel

**Author:** Echo (intel/comms)
**Date:** 2026-06-28
**Scope:** How Comlink's remote MCP server should authenticate the Claude mobile app / claude.ai *given the user's existing Cloudflare Access (Zero Trust) setup* — GitHub IdP, Access policy restricted to Brandon's own email, FastMCP (`mcp` 1.27.2) on K3s "Gonk" behind Traefik, fronted by Cloudflare (DNS + Access).
**Builds on:** `docs/phase2-auth-research.md` (T1, rev 2025-06-18 MCP auth spec; SDK ships no concrete token verifier — audience validation is hand-written) and `docs/design-doc.md` §Epic 5.

Confidence legend: **verified** = quoted from a dated vendor doc / spec / installed source; **inferred** = reasoned from those; **unknown** = not determinable from available sources → flagged for empirical test (Wrecker).

> **Terminology / design-doc note (not a silent fix):** `design-doc.md` §Epic 5 (lines 245–252) specifies "public HTTPS endpoint via Traefik fronted by OAuth, audience-bound." It is **silent on Cloudflare Access specifically** and assumes the "Comlink-is-the-OAuth-AS, validate `aud == MCP URL`" model. Cloudflare Access introduces a *second* audience (the CF AUD tag) and a CF-as-AS option the design doc does not contemplate. This is a gap to reconcile in the design doc when Epic 5 graduates from design-only, **not** stale spec to overwrite now. Flagged for Brandon.

---

## Q1 — Do CF Access and the MCP OAuth handshake compose, or does Access break discovery?

**Short answer: a default Cloudflare Access self-hosted app in front of `/mcp` BREAKS the MCP OAuth handshake. You must either (a) bypass the OAuth-relevant paths, or (b) turn on Managed OAuth (Q2/Q3).**

- **Default Access intercepts with a browser login redirect, not a spec 401.** A self-hosted Access application in front of an origin answers unauthenticated requests with a 302 to the Cloudflare login page (HTML), which is *not* the RFC 9728 `401 + WWW-Authenticate: Bearer resource_metadata=…` that the Claude app's discovery depends on. Cloudflare's own Managed OAuth doc confirms this by negation: enabling Managed OAuth "**replaces the `401` response behavior on the protected application**," i.e. the un-managed default is not a usable 401 for programmatic OAuth clients. **Source:** Managed OAuth · Cloudflare One docs, `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/` (fetched 2026-06-28). **Confidence: verified.**

- **Specific paths CAN be excluded from Access (Bypass).** The supported pattern: create a *second*, more-specific Access application scoped to the exact path (e.g. `/.well-known/*`, `/mcp`, and your AS's authorize/token/register endpoints) with action **Bypass → Everyone**. Cloudflare evaluates the most-specific path first, so those paths become public while the rest of the hostname stays login-gated. **Sources:** "Application paths" + "Access policies" · Cloudflare One docs, `https://developers.cloudflare.com/cloudflare-one/policies/access/app-paths/` and `https://developers.cloudflare.com/cloudflare-one/access-controls/policies/`; corroborated by community/how-to writeups (2025). **Confidence: verified (mechanism); inferred (exact path list for Comlink).**

- **Consequence for the "Comlink is its own OAuth AS" model:** you must Bypass `/.well-known/*`, `/mcp`, and the OAuth endpoints from Access, which means **Access provides no auth on the MCP traffic itself** — Comlink's own bearer validation becomes the sole gate on `/mcp`, and CF Access is demoted to pure network edge (TLS, WAF, DDoS, rate-limit) on those paths. That is spec-correct (matches T1 §4/§5) but it removes CF Access as a defense-in-depth layer *on `/mcp`*.

---

## Q2 — Can Cloudflare Access itself be the MCP OAuth Authorization Server?

**Yes — via "Managed OAuth," which is purpose-built for exactly this. It is a real OAuth 2.1 AS for non-browser/agent clients.** **Confidence: verified.**

- **What it is / when it shipped.** "Managed OAuth … allows non-browser clients — such as CLIs, AI agents, SDKs, and scripts — to authenticate with Access-protected applications using a standard OAuth 2.0 authorization code flow." GA changelog dated **2026-03-20**; launch blog "Managed OAuth for Access" dated **2026-04-14**. **Sources:** `https://developers.cloudflare.com/changelog/post/2026-03-20-managed-oauth/`; `https://blog.cloudflare.com/managed-oauth-for-access/`; Managed OAuth docs (fetched 2026-06-28).

- **Standards it supports (verified from docs + blog):**
  - **DCR (RFC 7591):** yes — "the agent dynamically registers itself as a client." Configurable: **Allowed redirect URIs** for dynamically registered clients (`https`, may end in `/*`), **Allow localhost clients**, **Allow loopback clients** (`127.0.0.1`). *(This is the knob that lets you pin Claude's callback `https://claude.ai/api/mcp/auth_callback`.)*
  - **PKCE (RFC 7636):** yes — agents go "through a PKCE authorization flow."
  - **Discovery metadata:** exposes **`/.well-known/oauth-authorization-server`** that "conforms to RFC 8414 and RFC 9728."
  - **RFC 8707 resource indicators:** the prerequisites say "An OAuth client that supports RFC 8707" is required — so CF expects/consumes the `resource` parameter, but the docs do **not** spell out CF's own resource-binding semantics. **Confidence: inferred → mark for test.**

- **Token format — important.** "Managed OAuth issues **opaque** access tokens (for example, `oauth:CvNoo…`), **not JSON Web Tokens (JWTs)**." So the token Claude holds carries **no client-visible `aud`**; CF resolves it server-side and forwards the request to the origin with a `Cf-Access-Jwt-Assertion` JWT injected (whose `aud` is the CF **AUD tag** — see Q4). In this model the origin never validates an MCP-URL-audience token from Claude; CF owns that. **Confidence: verified.**

- **Opt-in, and why it matters here.** Managed OAuth is **opt-in**: "If you run your own OAuth server behind an Access application and rely on your own `WWW-Authenticate` headers, do not enable this feature. Enabling managed OAuth **replaces the `401` response behavior**." → Managed OAuth and "Comlink-is-its-own-AS" are **mutually exclusive on the same app**. **Confidence: verified.**

- **The other CF mode — "Access for SaaS (OIDC)."** A SaaS-OIDC Access app makes CF an **OIDC provider** issuing JWTs, with fixed `client_id`/`client_secret` and endpoints at `…cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client_id>/{authorization,token,jwks}`. **But this does not serve Claude's DCR flow directly** — there is one static client (the MCP server), so in this mode **Comlink is still its own AS to Claude** and uses CF only as an upstream IdP. More moving parts than either pure model; see Q5(C). **Source:** "Secure MCP servers" · Cloudflare One docs (fetched 2026-06-28). **Confidence: verified.**

---

## Q3 — Is there a Cloudflare-native remote-MCP auth pattern, and does it work for a non-Workers origin?

**Yes, and crucially it is NOT Workers-only — the Access/Managed-OAuth path applies to self-hosted origins like Gonk.** **Confidence: verified.**

- **`workers-oauth-provider`** (`https://github.com/cloudflare/workers-oauth-provider`) is a TypeScript library that wraps a **Cloudflare Worker**. That specific library **is Workers-only** and is **not** applicable to a FastMCP origin on K3s. **Confidence: verified.**

- **But the relevant native pattern is Cloudflare One "Secure MCP servers" + Managed OAuth, which is origin-agnostic.** The launch blog states it works for "**any internal app, whether it's one built on Cloudflare Workers, or hosted elsewhere**," and the Managed OAuth docs say it can be enabled on "**any self-hosted Access application or MCP server portal.**" The "Secure MCP servers" guide names exactly two approaches — **"Self-hosted Application (recommended)"** and **"Access for SaaS (OIDC)."** The walkthrough's example happens to deploy a Worker, but the auth mechanism (a self-hosted Access app with Managed OAuth in front of an HTTP origin) is what Comlink would reuse, pointing Access at `https://comlink.chaosbit.dev`. **Sources:** blog `https://blog.cloudflare.com/managed-oauth-for-access/`; "Secure MCP servers" + "Managed OAuth" docs (fetched 2026-06-28). **Confidence: verified (origin-agnostic); inferred (FastMCP-specific wiring untested by CF docs).**

- **MCP server portals** also accept any HTTP MCP URL (self-hosted or SaaS) and front them with Access — relevant only if Brandon wants to aggregate multiple servers; not needed for a single mailbox server. **Source:** `https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/`. **Confidence: verified.**

- **⚠️ Reality check that undercuts the native path for Brandon's exact client — see Q5.** A dated, concrete bug report shows **claude.ai web/mobile failing** against a CF Managed-OAuth-protected MCP endpoint while **Claude Code succeeds on the same URL** (GitHub issue, 2026-06-07). Because Brandon's whole point is the **mobile app**, this is the load-bearing risk, detailed in Q5.

---

## Q4 — Defense-in-depth: validating `Cf-Access-Jwt-Assertion` in-server, and the two-audience problem

When CF Access stays in front of `/mcp` (i.e. the Managed-OAuth or SaaS models, **not** the bypass model), CF injects a signed JWT into the request that the origin can validate as a second gate. **Confidence: verified (CF JWT validation is a long-standing, documented feature).**

- **Where/how to validate.** Header: **`Cf-Access-Jwt-Assertion`**. JWKS/certs: **`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`**. Checks: signature against those keys, **`iss` == `https://<team>.cloudflareaccess.com`** (team domain), **`aud` == the application AUD tag**, and `exp`. **Source:** "Validate JWTs" · Cloudflare One docs, `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/` (search-confirmed 2026-06-28). **Confidence: verified.**

- **THE TWO-AUDIENCE SITUATION (call this out explicitly):**
  | | Audience value | Who validates it | Present in which model |
  |---|---|---|---|
  | **MCP/RFC 8707 audience** | the MCP server URL, e.g. `https://comlink.chaosbit.dev/mcp` | Comlink's `TokenVerifier` (hand-written, per T1 §3f) | Comlink-is-AS model (Q5 A/A′) |
  | **CF Access AUD tag** | a Cloudflare-assigned UUID (the app's "Application Audience (AUD) Tag") | a CF-JWT check on the `Cf-Access-Jwt-Assertion` header | Managed-OAuth / SaaS models (Q5 B/C) |

  These are **different audiences with different purposes.** The CF AUD tag proves "Cloudflare authenticated *a* session for *this Access app*"; the RFC 8707 MCP-URL audience proves "this token was minted *for Comlink's MCP endpoint specifically*." Do not conflate them.

- **Wiring into FastMCP — a real friction point, not a drop-in.** FastMCP's `BearerAuthBackend.verify_token` reads the **`Authorization: Bearer`** header (T1 §3c). The CF JWT arrives in a **different header (`Cf-Access-Jwt-Assertion`)**, and under Managed OAuth the `Authorization` token Claude sent is an **opaque** CF token CF already consumed at the edge. So validating the CF JWT is **not** a clean fit for `TokenVerifier`; it wants a **custom Starlette middleware** ahead of the MCP route that reads `Cf-Access-Jwt-Assertion`, verifies it against the certs endpoint, and 403s on mismatch. This is "documentation/docstring-adjacent plumbing" — Tech (not Echo) writes it. **Confidence: inferred (from installed SDK source in T1 §3c + CF header semantics) → confirm header passthrough empirically.**

- **Net:** CF-JWT validation is a legitimate, cheap second gate **only on paths that remain Access-protected.** In the bypass model (Q5 A/A′) `/mcp` is *not* Access-protected, so there is no `Cf-Access-Jwt-Assertion` to check there and the in-server MCP-URL-audience `TokenVerifier` is the sole authority — which is exactly T1's recommendation.

---

## Q5 — Recommendation for this exact setup

### The architectures on the table

**(A) Comlink is its own OAuth AS via the SDK `auth_server_provider`** issuing MCP-URL-audience tokens; CF Access demoted to network edge with **Bypass** on `/.well-known/*`, `/mcp`, and the authorize/token/register endpoints (Managed OAuth OFF).
- *Pro:* spec-clean; Comlink controls the `401 + WWW-Authenticate` header, so the claude.ai-mobile failure mode in issue #410 does not apply; reuses T1's verifier design.
- *Con:* implementing a full `OAuthAuthorizationServerProvider` (authorize/token/register/refresh/revoke + secure storage) is a large build (T1 §6). CF identity (GitHub IdP + email policy) is **not** reused — Comlink would re-implement identity.

**(A′) Comlink RS-only + an external DCR-capable AS** (candidates: **Stytch, Auth0, WorkOS, Descope** — all named in CF's own MCP authz docs as "bring your own OAuth"; or self-hostable **Authentik / Keycloak** which fit Gonk). Comlink hand-writes the `TokenVerifier` validating `aud == https://comlink.chaosbit.dev/mcp` (T1 §3f). CF Access at the edge with the same Bypass paths as (A).
- *Pro:* spec-clean and claude.ai-mobile-compatible (the external AS owns `WWW-Authenticate`); no AS to build; DCR + PKCE + RFC 8707 handled by a product that advertises them. **This is the natural extension of T1's recommended RS-only shape.**
- *Con:* a new external dependency + DCR-churn behavior to validate (T1 §6 already flagged this as unknown); CF's GitHub-IdP+email policy is reused only if the external AS federates to it (most do via OIDC/social).

**(B) CF Access Managed OAuth as the AS (one click), self-hosted Access app in front of `https://comlink.chaosbit.dev`.** Comlink validates the injected `Cf-Access-Jwt-Assertion` (Q4) and reads identity from it.
- *Pro:* **lowest build by far** — reuses Brandon's *existing* CF Access app, GitHub IdP, and email-only policy verbatim; CF stays in front of `/mcp` so there's genuine edge enforcement + defense-in-depth; no AS to write; opaque tokens never expose claims to the client.
- *Con (decisive):* **a dated report (GitHub issue #410, 2026-06-07) shows claude.ai web AND mobile failing** against a CF Managed-OAuth MCP endpoint — error "Authorization with the MCP server failed … reference ofid_…", thrown **immediately on Connect, before any login** — while **Claude Code succeeds on the identical URL**. Diagnosed root cause: the `401` on `/mcp` **omits `WWW-Authenticate`**; Claude Code tolerates this and probes `/.well-known/oauth-protected-resource` directly, but **claude.ai web/mobile requires the header** and bails before discovery. Issue **closed "not planned."** **This directly threatens Brandon's only goal (the phone).** **Source:** `https://github.com/anthropics/claude-ai-mcp/issues/410`. **Confidence: verified (report is concrete + dated).**

**(C) Access for SaaS (OIDC).** Comlink is its own AS *to Claude* and an OIDC *client to CF*. Combines the AS build of (A) with the CF dependency of (B). **Not recommended** unless reusing CF identity is mandatory *and* (B) is blocked by the #410 bug. Listed for completeness.

### The conflict you must resolve before coding — and it's a docs disagreement

CF's **blog (2026-04-14)** says Managed OAuth **emits** `www-authenticate` pointing agents at `/.well-known/oauth-authorization-server`. The **GitHub issue (2026-06-07)** says in practice the `/mcp` 401 had **no** `WWW-Authenticate`, which is exactly what breaks claude.ai mobile. Two further wrinkles keep this genuinely **unknown**:
1. Issue #410 was against an **MCP server *portal***, not a plain **self-hosted Access app** — the header behavior may differ between the two. The blog's claim may hold for self-hosted apps specifically.
2. Managed OAuth is recent (GA 2026-03-20); CF may have shipped a fix after 2026-06-07. **Not verifiable from docs alone.**

**→ This is a `WebFetch`-can't-settle-it question. Hand it to Wrecker for an empirical connect test (see below) rather than betting the architecture on the blog.**

### RECOMMENDATION (data-first, two-phase)

1. **First, run the cheap test of (B).** Enable Managed OAuth on a **self-hosted Access app** (NOT a portal) in front of a throwaway `https://comlink-test.chaosbit.dev`, set the allowed redirect URI to `https://claude.ai/api/mcp/auth_callback`, keep the email-only policy, and have Wrecker attempt a **connect from the Claude *mobile* app**. If it completes the login + tool list, (B) wins outright — it's the least code, reuses everything Brandon already configured, and keeps CF Access as real defense-in-depth on `/mcp`. Validate the `Cf-Access-Jwt-Assertion` in a small middleware (Q4) as the second gate.

2. **If mobile fails like #410, fall back to (A′):** FastMCP RS-only + an external DCR-capable AS, with CF Access reduced to the network edge and **Bypass** on `/.well-known/*`, `/mcp`, and the AS's OAuth endpoints. This is spec-clean, puts the `WWW-Authenticate` header under Comlink/AS control (sidestepping the exact #410 failure), and matches T1's recommended shape. Comlink's hand-written `TokenVerifier` enforcing `aud == https://comlink.chaosbit.dev/mcp` + owner `subject` remains the authoritative gate, with the structural send gate as the real injection defense (per memory + design-doc §2).

   *Do not pick (A) over (A′)* unless an external AS is unacceptable — building a full OAuth AS is strictly more work for no spec benefit.

This sequencing is honest about the uncertainty: (B) is best *if it works for mobile*, and that is precisely the thing the docs disagree on, so we test it instead of asserting it.

### Flagged for empirical test (Wrecker) — docs are silent or conflicting

1. **(LOAD-BEARING) Does claude.ai *mobile* complete OAuth against a CF Managed-OAuth *self-hosted Access app*?** Blog says yes (header emitted); issue #410 says no for a *portal*. Test the self-hosted-app case directly from the phone. **Confidence today: unknown.**
2. **Does CF Managed OAuth honor the RFC 8707 `resource` parameter** the way Claude sends it, and what `aud`/`resource` binding (if any) results? Docs only say a client "that supports RFC 8707" is required. **Unknown.**
3. **Does the origin actually receive `Cf-Access-Jwt-Assertion` (and is the original `Authorization` header stripped/preserved) under Managed OAuth?** Determines the Q4 middleware shape. **Inferred, confirm.**
4. **Claude's DCR churn** against whichever AS is chosen (new `client_id` per fresh connection) — carried over from T1 §6, still **unknown** until the AS is selected.
5. **Exact Bypass path list** that lets the OAuth flow through while keeping everything else gated (does `/.well-known/*` need to be fully public, or only the protected-resource doc?). **Inferred, confirm by connect test.**

---

## Executive summary (one bullet per question)

- **Q1 — Compose?** Not by default: a plain CF Access self-hosted app answers with a browser-login 302, not the RFC 9728 `401 + WWW-Authenticate` the Claude app needs — it **breaks discovery**. You fix this either by **Bypassing** `/.well-known/*` + `/mcp` + OAuth paths (Comlink-as-AS) or by enabling **Managed OAuth** (CF-as-AS). **Verified.**
- **Q2 — CF as the AS?** **Yes, via "Managed OAuth"** (GA 2026-03-20): a real OAuth 2.1 AS for agents supporting **DCR (RFC 7591), PKCE, RFC 8414/9728 metadata at `/.well-known/oauth-authorization-server`**, expecting an **RFC 8707-capable client**, issuing **opaque** tokens (no client-visible `aud`). It's mutually exclusive with running your own AS. A separate "Access for SaaS (OIDC)" mode exists but doesn't serve Claude's DCR directly. **Verified.**
- **Q3 — CF-native, non-Workers?** `workers-oauth-provider` is Workers-only, **but** the Access + Managed OAuth path is **origin-agnostic** — CF explicitly supports apps "hosted elsewhere," so it applies to Comlink on Gonk. **Verified.**
- **Q4 — In-server CF JWT check?** Validate `Cf-Access-Jwt-Assertion` against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (`iss` = team domain, `aud` = the **CF AUD tag**, `exp`). This **CF AUD tag ≠ the RFC 8707 MCP-URL audience** — two distinct audiences; it slots in as a **custom middleware** (not FastMCP's `Authorization`-reading `TokenVerifier`), and only on paths still behind Access. **Verified (mechanism); inferred (wiring).**
- **Q5 — Recommendation:** Test **(B) Managed OAuth on a self-hosted Access app** from the phone first (lowest build, reuses Brandon's exact GitHub-IdP+email setup, keeps CF defense-in-depth); **if mobile fails (per issue #410), fall back to (A′) FastMCP RS-only + external DCR-capable AS with CF demoted to edge + Bypass paths.** Don't build a full AS (A) when (A′) is strictly less work.

## Single most important finding

**CF Access *can* compose with the MCP OAuth flow — Cloudflare shipped "Managed OAuth" (GA 2026-03-20) specifically to make Access an OAuth AS for agent clients, and it works for self-hosted origins, not just Workers. BUT there is a dated, concrete report (GitHub issue #410, 2026-06-07) that the *claude.ai web/mobile* connector — Brandon's entire target — *fails* against a CF Managed-OAuth MCP endpoint (missing `WWW-Authenticate` on the `/mcp` 401), while Claude Code succeeds on the same URL.** Cloudflare's blog claims the header *is* emitted, and the failing case was a *portal* not a self-hosted app, so the truth is **genuinely unresolved by the docs** and must be settled by a mobile connect test before committing. If mobile works → use Managed OAuth (least code). If not → Comlink owns the OAuth/`WWW-Authenticate` path (external DCR-capable AS, RS-only FastMCP, CF as edge), which structurally avoids the #410 failure.

## Recommended architecture (one line)

**Primary:** CF Access **self-hosted app + Managed OAuth** as the AS, Comlink validating `Cf-Access-Jwt-Assertion` as a second gate — *contingent on a passing claude.ai-mobile connect test.* **Fallback if that test fails:** FastMCP **RS-only** + **external DCR-capable AS** (Stytch/Auth0/WorkOS/Authentik/Keycloak), CF Access **demoted to network edge** with **Bypass** on `/.well-known/*`, `/mcp`, and the OAuth endpoints, Comlink's hand-written `TokenVerifier` enforcing `aud == https://comlink.chaosbit.dev/mcp` + owner `subject` as the authority.

---

## DCR / client registration (live blocker)

**Added 2026-06-29.** Live situation, not theoretical: Comlink's remote endpoint is up behind Cloudflare Access with Managed OAuth **active and advertising correctly** — `/mcp` returns `302 + WWW-Authenticate: Cloudflare-Access resource_metadata=…`, the protected-resource metadata returns 200 with `authorization_servers: ["https://chaosbit.cloudflareaccess.com"]`, team domain `chaosbit.cloudflareaccess.com`, app AUD tag `35ba36c8…615300`. **Discovery succeeds** (we are past the #410 problem entirely). The Claude **mobile** connector then fails at **client registration**: *"Couldn't register with Comlink's sign-in service… add an OAuth Client ID in the connector settings… reference ofid_afb02aaf6d3fe0d4."* This is an **RFC 7591 Dynamic Client Registration failure** — Claude tried to auto-register a client and Cloudflare refused.

### Q1 — Does Managed OAuth support DCR, and must it be enabled?

**Yes, it supports DCR — and it is NOT on by default. You enable it by populating "Allowed redirect URIs" (and, per the API, a `dynamic_client_registration.enabled` flag) in the Access application's Advanced settings.** **Confidence: verified.**

- The Managed OAuth doc exposes DCR controls under the API object `oauth_configuration.dynamic_client_registration` with fields `enabled`, `allow_any_on_localhost`, `allow_any_on_loopback`, and `allowed_uris`. In the dashboard these surface as **"Allowed redirect URIs"**, **"Allow localhost clients"**, **"Allow loopback clients."** There is **no separate control labeled "Dynamic Client Registration" / "RFC 7591"** in the UI — **populating "Allowed redirect URIs" is the act that permits DCR.** An empty allow-list (or one that doesn't match the client's requested `redirect_uri`) means Cloudflare **rejects the registration** — which is exactly this failure.
- **Exact path:** **Zero Trust → Access controls → Applications →** (select the Comlink app) **→** three-dot menu **→ Edit → Advanced settings** tab. (For an MCP *portal* the path is **Zero Trust → Access controls → AI controls →** portal **→ Edit → Advanced settings**.)
- **Source:** Managed OAuth · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/` (fetched 2026-06-29). **Confidence: verified.**

### Q2 — Known causes of a Managed-OAuth DCR failure

**Most likely (this case): "Allowed redirect URIs" is empty or doesn't include Claude's callback, so CF refuses to register the dynamic client.** **Confidence: inferred (strong) — docs confirm the mechanism; CF does not publish a failure taxonomy.**

- The CF docs **do not enumerate DCR error classes**, and the `ofid_…` reference is **not a documented error code** — it is a Cloudflare-side flow/trace identifier (a "one" / Zero-Trust flow id) meaningful to CF support, not to us. So the *specific* rejection reason is **unknown from docs** and only CF support (with that `ofid_`) or an empirical retry-after-fix can confirm. **Confidence: unknown (the code itself); inferred (it signals a CF-side registration rejection).**
- Candidate causes, ranked: (1) **`allowed_uris` empty / missing Claude's callback** — primary suspect; (2) DCR not enabled at all (`dynamic_client_registration.enabled` false) even though Managed OAuth is on; (3) redirect-URI scheme/host mismatch (CF requires HTTPS for non-localhost; Claude's `https://claude.ai/api/mcp/auth_callback` qualifies, but a trailing-slash or `/*` wildcard expectation could bite); (4) account/app still propagating after enabling Managed OAuth. The Access **policy** (email-only) is **not** a DCR-stage cause — policy is evaluated at the authorize/login step, *after* registration.

### Q3 — Manually registering an OAuth client in Cloudflare (the fallback the Claude error suggests)

**Cloudflare Managed OAuth does NOT expose manual client creation. It is DCR-only by design — the only knobs are the redirect-URI allow-list + localhost/loopback toggles. There is no dashboard place to mint a static `client_id`/`client_secret` for a Managed-OAuth app.** **Confidence: verified (by the docs' complete silence on static client creation + the API surface being DCR-only).**

- Consequence: the Claude error's suggestion to *"add an OAuth Client ID in the connector settings"* **cannot be satisfied under Managed OAuth** — there's nothing in CF to hand you a client ID. Claude's own connector does support pre-registered creds (an optional **OAuth Client Secret** field, and the `oauth_anthropic_creds` path), but **Managed OAuth gives you nothing to paste there.** Don't chase that field.
- **The real alternative if DCR can't be made to work:** switch that app to **Access for SaaS (OIDC)**, which *does* issue a static `client_id`/`client_secret` and fixed endpoints (`…cloudflareaccess.com/cdn-cgi/access/sso/oidc/<client_id>/…`). But note that is the **(C)** model from Q5 above — in SaaS-OIDC the registered client is the **MCP server**, not Claude, so Comlink would have to be its own AS to Claude (more build, more moving parts). Prefer fixing DCR first.

### Q4 — Redirect URI(s) Claude needs

**Add both: `https://claude.ai/api/mcp/auth_callback` AND `https://claude.com/api/mcp/auth_callback`.** All hosted surfaces — **claude.ai web, Desktop, and mobile (and Cowork)** — share these; there is **no separate mobile-specific callback.** (Claude Code is different — RFC 8252 loopback `http://localhost/callback` + `http://127.0.0.1/callback`, port-agnostic — which is why Claude Code connected while mobile didn't.) **Source:** Claude connector authentication docs — `https://claude.com/docs/connectors/building/authentication` (fetched 2026-06-29). **Confidence: verified.**

### Q5 — Bottom line / fix sequence for right now

**Do NOT abandon the CF path — the evidence points squarely at one missing setting, not a broken feature. DCR is opt-in via the redirect-URI allow-list, and the allow-list is almost certainly empty.**

1. **FIRST (single most-likely fix):** Zero Trust → Access controls → Applications → Comlink app → ⋯ → **Edit → Advanced settings** → in **"Allowed redirect URIs"** add **`https://claude.ai/api/mcp/auth_callback`** and **`https://claude.com/api/mcp/auth_callback`**; if there's a DCR enable toggle (`dynamic_client_registration.enabled`), turn it **on**; also enable **"Allow loopback clients"** / **"Allow localhost clients"** so Claude Code keeps working. **Save.** Then re-add the connector on the phone. **Confidence the field exists + this is the lever: verified. Confidence it's the actual cause: inferred — confirm empirically.**
2. **If still failing,** capture the exact CF-side reason: the `ofid_…` is **undocumented**, so either (a) hand it to Cloudflare support, or (b) hit the registration endpoint directly (Wrecker: `POST` an RFC 7591 body to the `registration_endpoint` from the AS metadata at `https://chaosbit.cloudflareaccess.com/.well-known/oauth-authorization-server`, with `redirect_uris:["https://claude.ai/api/mcp/auth_callback"]`) and read the literal error JSON. That settles cause #1 vs #2 vs #3 above empirically.
3. **Only if DCR genuinely can't be enabled** (CF bug, account flag), fall back to **Access for SaaS (OIDC)** — model (C) — accepting that Comlink then owns the AS-to-Claude role, **or** to model (A′) from Q5 above (RS-only + external DCR-capable AS). Both are strictly more work; treat as last resort.

**Single most-likely fix to try first:** *Zero Trust → Access controls → Applications → Comlink → ⋯ → Edit → Advanced settings → "Allowed redirect URIs" → add the two `…/api/mcp/auth_callback` URLs → Save.*

**Flagged for empirical test (Wrecker):** the `ofid_afb02aaf6d3fe0d4` reference is **not in any CF doc** — its precise meaning is **unknown**; confirm the fix by re-connecting from the phone (or the direct `POST` to `registration_endpoint`) and reading the response. Whether CF requires an exact-match URI vs. a `/*` wildcard for these callbacks is **inferred, not documented** — if exact-match fails, try `https://claude.ai/api/mcp/*`.

### DCR-blocker sources
- Managed OAuth · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/` (fetched 2026-06-29)
- Secure MCP servers · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/` (fetched 2026-06-29)
- Managed OAuth for Cloudflare Access · Changelog, 2026-03-20 (no post-March DCR updates in entry) — `https://developers.cloudflare.com/changelog/post/2026-03-20-managed-oauth/`
- Claude connector authentication (redirect URIs, pre-registered creds, DCR/CIMD requirements) — `https://claude.com/docs/connectors/building/authentication` (fetched 2026-06-29)
- Build custom connectors via remote MCP servers · Claude Help Center — `https://support.claude.com/en/articles/11503834-build-custom-connectors-via-remote-mcp-servers`

---

## Sources
- MCP Authorization spec, rev 2025-06-18 — `https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization` (via T1)
- Secure MCP servers · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/` (fetched 2026-06-28)
- Managed OAuth · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/` (fetched 2026-06-28)
- Managed OAuth for Access (blog, 2026-04-14) — `https://blog.cloudflare.com/managed-oauth-for-access/`
- Managed OAuth for Cloudflare Access (changelog, 2026-03-20) — `https://developers.cloudflare.com/changelog/post/2026-03-20-managed-oauth/`
- MCP server portals · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/`
- Authorization · Cloudflare Agents docs — `https://developers.cloudflare.com/agents/model-context-protocol/authorization/`
- Application paths · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/policies/access/app-paths/`
- Access policies · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/policies/`
- Validate JWTs · Cloudflare One docs — `https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/`
- claude.ai connector OAuth fails against CF Access Managed OAuth — GitHub issue (2026-06-07, closed "not planned") — `https://github.com/anthropics/claude-ai-mcp/issues/410`
- workers-oauth-provider (Workers-only) — `https://github.com/cloudflare/workers-oauth-provider`
- Comlink T1 intel — `docs/phase2-auth-research.md`; design doc — `docs/design-doc.md` §Epic 5
</content>
</invoke>
