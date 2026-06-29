# Cloudflare Access + Managed OAuth — mobile connect probe

**Throwaway.** Not part of Comlink production. Deletes cleanly once the question
below is answered.

## The question this answers

Does the **Claude mobile / claude.ai connector** complete **Cloudflare Access
Managed OAuth** against a self-hosted MCP origin? This is the one load-bearing
unknown for Comlink's remote deployment (GitHub issue #410 reported mobile
failing — `/mcp` 401 missing `WWW-Authenticate` — while Claude Code worked).
Resolve it before building Comlink's real transport/verifier.

- **PASS** → primary path: Cloudflare Access is the OAuth AS; build Comlink on it,
  with Comlink validating the `Cf-Access-Jwt-Assertion` (aud == the comlink AUD
  tag) as an in-server second gate.
- **FAIL at OAuth** (app errors during connect; **no request ever reaches the
  probe** — watch the logs) → #410 reproduced: pivot to the fallback — a
  DCR-capable AS (self-hosted Authentik/Keycloak on Gonk, or Stytch/Auth0/WorkOS)
  with Cloudflare Access demoted to a network-edge gate (Bypass `/.well-known/*`,
  `/mcp`, OAuth endpoints) and Comlink's own `TokenVerifier` enforcing
  `aud == https://comlink.chaosbit.dev/mcp`.

## Steps

1. **Run the probe at the comlink origin** (on Gonk, behind the existing CF route):

   ```
   PROBE_HOST=0.0.0.0 PROBE_PORT=8000 \
     PROBE_ALLOWED_HOSTS=comlink.chaosbit.dev \
     uv run python experiments/auth_probe/auth_probe.py
   ```

   Point the existing Cloudflare route for `comlink.chaosbit.dev` at this
   host:port so `https://comlink.chaosbit.dev/mcp` reaches the probe.

2. **Confirm on the comlink Access app:** Managed OAuth is enabled, GitHub IdP +
   email-only policy in place. (Cookie settings — HTTP Only, binding cookie, etc.
   — are the browser-session path; they don't affect this test.)

3. **Add the connector in the Claude *mobile* app:** add a custom connector
   pointing at `https://comlink.chaosbit.dev/mcp`. Expect a redirect into the CF
   → GitHub login, gated to your email.

4. **Observe — two places at once:**
   - **Probe logs:** does *any* request arrive after you authenticate? Look for
     `initialize`, then a `tools/list`, then `ping called:` when you invoke it.
     **No request arriving = the failure is up at CF (the #410 signature).**
   - **Mobile app:** does it finish auth, show the `ping` tool, and return
     `pong @ <timestamp> …` when you call it?

5. **Record the outcome** (pass / fail-at-oauth / partial) and any error text the
   app shows. That decides the architecture fork above.

## Repeat later for mcp-ha

Same procedure with the `mcp-ha` Access app + its own AUD tag — whichever path
passes here is the template to replicate.
