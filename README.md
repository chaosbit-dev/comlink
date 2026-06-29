# Comlink

Comlink is a **Proton Mail MCP server**. It gives Claude full mailbox capability —
read, search, triage, organize, draft, and (gated) send — by talking to **Proton Mail
Bridge's local IMAP/SMTP endpoints**. Bridge handles all encryption/decryption and
server sync; Comlink is a thin, well-typed protocol adapter with strong safety rails on
anything that leaves the machine. The server registers its tools under the `proton_`
prefix (server name `proton_mail_mcp`).

**Phase 1 (this README): local stdio.** Comlink runs as a subprocess of Claude Desktop /
Claude Code on your Mac and reaches Bridge over `127.0.0.1`. Zero networking, no inbound
ports.

**Phase 2 (deferred, design only): remote.** A `streamable-http` deployment on Gonk K3s,
exposed as a **public HTTPS endpoint behind OAuth** so the Claude mobile app / claude.ai
can reach it (a tailnet cannot). The transport and OAuth token validation are not yet
implemented. See `docs/design-doc.md` §2 and Epic 5 for the threat model.

---

## 1. Prerequisites

- macOS with [Homebrew](https://brew.sh).
- [`uv`](https://docs.astral.sh/uv/) — `brew install uv`.
- **Proton Mail Bridge, installed and logged in.** Comlink never sees your Proton account
  password; it uses the Bridge-generated *app password*. Bridge must be **running** whenever
  Comlink is used.
- Claude Desktop and/or Claude Code.

Clone and sync the project:

```bash
git clone <your-fork-or-origin> ~/dev/comlink
cd ~/dev/comlink
uv sync
```

Target: a working setup on a fresh Mac in under 15 minutes.

---

## 2. Proton Mail Bridge: install and get the app password

1. Install Bridge — `brew install --cask proton-mail-bridge` (or download from Proton) — and
   sign in with your Proton account. Leave it running.
2. In Bridge, open **Mailbox details** for your account. It shows:
   - the **IMAP** host/port (`127.0.0.1:1143`, STARTTLS),
   - the **SMTP** host/port (`127.0.0.1:1025`, STARTTLS),
   - the **username** (usually your Proton email address),
   - the **app password** — a Bridge-generated password, **not** your Proton login password.
3. Copy the app password. You'll store it in the Keychain next.

If the app password ever rotates (re-login, reconfigure), repeat the Keychain step below.

---

## 3. Store the Bridge app password (macOS Keychain)

Don't put the password in plaintext config. Store it in the Keychain once:

```bash
security add-generic-password -s proton-bridge -a "$USER" -w
# (you'll be prompted to paste the Bridge app password; -w with no value reads it interactively)
```

Comlink retrieves it at runtime via a shell command (`COMLINK_PASSWORD_COMMAND`). The exact
retrieval command — the one you put in config — is:

```bash
security find-generic-password -s proton-bridge -w
```

That prints the password to stdout; Comlink reads stdout (stripped) and never logs it.

**Vaultwarden alternative.** If you keep the Bridge password in your self-hosted Vaultwarden
via the Bitwarden CLI, use this as `COMLINK_PASSWORD_COMMAND` instead (unlock `bw` first):

```bash
bw get password proton-bridge
```

---

## 4. Configuration (`COMLINK_*` environment variables)

All configuration is environment variables with the `COMLINK_` prefix. Secrets are never
logged. Mirrors `src/comlink/config.py`.

| Variable | Default | Notes |
|---|---|---|
| `COMLINK_IMAP_HOST` | `127.0.0.1` | Bridge IMAP host |
| `COMLINK_IMAP_PORT` | `1143` | Bridge IMAP port (STARTTLS) |
| `COMLINK_SMTP_HOST` | `127.0.0.1` | Bridge SMTP host |
| `COMLINK_SMTP_PORT` | `1025` | Bridge SMTP port. |
| `COMLINK_SMTP_SECURITY` | `starttls` | `starttls` (connect plaintext, upgrade in-band — Bridge default) or `ssl` (implicit TLS on connect). Set to `ssl` if your Bridge's SMTP is configured for SSL/TLS. |
| `COMLINK_USERNAME` | `""` | Bridge username (usually your Proton address) |
| `COMLINK_PASSWORD` | _unset_ | Bridge app password (NOT the Proton account password). Prefer the command form below. |
| `COMLINK_PASSWORD_COMMAND` | _unset_ | Shell command whose stdout is the app password, e.g. `security find-generic-password -s proton-bridge -w` (Keychain) or `bw get password proton-bridge` (Vaultwarden). **Wins over `COMLINK_PASSWORD` if both are set.** |
| `COMLINK_TLS_MODE` | `verify` | `verify` or `no-verify`. `no-verify` is refused for non-localhost hosts. |
| `COMLINK_TLS_CERT_PATH` | _unset_ | Pinned Bridge certificate for `verify` mode. |
| `COMLINK_READ_ONLY` | `false` | When `true`, only the five read tools are registered (`proton_health_check`, `proton_list_folders`, `proton_list_messages`, `proton_search_messages`, `proton_get_message`). Every write/organize/compose tool — including `proton_send_message` — is **not registered** and invisible to the client. Overrides `COMLINK_ALLOW_SEND`. |
| `COMLINK_ALLOW_SEND` | `false` | Master send gate. When `false`, `proton_send_message` is **not registered** — the tool is invisible to the client, not just refusing. |
| `COMLINK_SEND_ALLOWLIST` | `""` | Comma-separated recipients. Exact address (`kendra@chaosbit.dev`) or `*@domain` wildcard (`*@chaosbit.dev`). **Empty + send enabled = any recipient** (logged loudly at startup). |
| `COMLINK_SEND_MAX_PER_HOUR` | `5` | Sliding-window send rate limit. |
| `COMLINK_AUDIT_LOG` | `~/.comlink/audit.jsonl` | Append-only JSONL of every send and delete. |
| `COMLINK_TRANSPORT` | `stdio` | `stdio` (Phase 1) or `streamable-http` (Phase 2, remote on Gonk behind Cloudflare Access). |
| `COMLINK_HTTP_HOST` | `127.0.0.1` | Bind address for `streamable-http`. Use `0.0.0.0` in a container. Ignored for `stdio`. |
| `COMLINK_HTTP_PORT` | `8000` | Bind port for `streamable-http`. Ignored for `stdio`. |
| `COMLINK_HTTP_PATH` | `/mcp` | Mount path for the `streamable-http` endpoint. Ignored for `stdio`. |
| `COMLINK_HTTP_ALLOWED_HOSTS` | `""` | Comma-separated `Host` allowlist for DNS-rebinding protection. When set, protection is **on** and only these hosts (and `https://<host>` origins) are accepted — set it to your public hostname (e.g. `comlink.chaosbit.dev`). When empty, protection is **disabled** with a logged warning: acceptable behind Cloudflare Access, never for bare-internet exposure. |
| `COMLINK_REQUIRE_ACCESS_JWT` | `false` | Defense-in-depth gate for `streamable-http`. When `true`, every HTTP request must carry a valid `Cf-Access-Jwt-Assertion` header (RS256-verified against the team JWKS, plus `aud`/`iss`/`exp`/`iat` and the optional email allowlist) or it is rejected with 401 before reaching the MCP app — so a direct in-cluster hit on the ClusterIP can't bypass Cloudflare Access. Requires `COMLINK_ACCESS_AUD` and `COMLINK_ACCESS_TEAM_DOMAIN` (startup fails fast otherwise). Ignored for `stdio`. |
| `COMLINK_ACCESS_AUD` | `""` | Cloudflare Access application **AUD** tag (an identifier, not a secret). Required when the gate is on. |
| `COMLINK_ACCESS_TEAM_DOMAIN` | `""` | Cloudflare Access team domain, e.g. `chaosbit.cloudflareaccess.com`. The issuer (`https://<team>`) and JWKS URL (`https://<team>/cdn-cgi/access/certs`) are derived from it. Required when the gate is on. |
| `COMLINK_ACCESS_ALLOWED_EMAILS` | `""` | Comma-separated allowlist of `email` claim values (e.g. `brandon@chaosbit.dev,brandon.luttrell@att.net`). Empty disables the per-email check (signature/`aud`/`iss`/time are still enforced). |

Set at least `COMLINK_USERNAME` and `COMLINK_PASSWORD_COMMAND`. Everything else has working
defaults for a local Bridge.

---

## 5. Register the server with your MCP client

Comlink installs a console entry point named **`comlink`** (`comlink = "comlink.server:main"`
in `pyproject.toml`), which `uv run` invokes.

### Claude Desktop (`claude_desktop_config.json`) / Claude Code (`.mcp.json`)

```json
{
  "mcpServers": {
    "comlink": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/brandon/dev/comlink", "comlink"],
      "env": {
        "COMLINK_USERNAME": "brandon@proton.me",
        "COMLINK_PASSWORD_COMMAND": "security find-generic-password -s proton-bridge -w",
        "COMLINK_ALLOW_SEND": "false"
      }
    }
  }
}
```

Adjust `--directory` to where you cloned the repo and `COMLINK_USERNAME` to your Bridge
username. Restart Claude Desktop (or reload the MCP config in Claude Code) to pick it up.

To run it by hand for debugging:

```bash
COMLINK_USERNAME=brandon@proton.me \
COMLINK_PASSWORD_COMMAND="security find-generic-password -s proton-bridge -w" \
uv run --directory ~/dev/comlink comlink
```

---

## 6. Smoke test (health check)

With Bridge running and the server registered, ask Claude to run the **`proton_health_check`**
tool (or invoke it from the MCP Inspector). It verifies IMAP + SMTP connectivity and reports:

- Bridge reachability,
- the account (`COMLINK_USERNAME`),
- folder count,
- send-gate status: enabled/disabled, allowlist size, max-per-hour, and remaining hourly budget.

Inspector pass over every tool:

```bash
npx @modelcontextprotocol/inspector uv run --directory ~/dev/comlink comlink
```

If health check reports the Bridge unreachable, start the Bridge app and retry. If IMAP login
is rejected, the app password likely rotated — re-run the Keychain step in §3.

---

## 7. The send gate (read before enabling send)

`proton_send_message` is the only tool that puts mail on the wire, and it is gated in **three
structural layers**:

1. **Env flag (registration).** `COMLINK_ALLOW_SEND` must be `true`. When it is `false`,
   `proton_send_message` is **not registered at all** — it is invisible to the client, not a
   tool that exists and refuses. This is the default. The draft path (`proton_save_draft`) is
   always available; prefer it.
2. **Recipient allowlist.** With send enabled, every recipient must match `COMLINK_SEND_ALLOWLIST`
   (exact address or `*@domain`). A non-matching recipient is rejected by name. An **empty**
   allowlist means any-recipient mode and is warned about loudly at startup — set the allowlist.
3. **Confirm + rate limit.** The call must assert `confirm: true` (schema-required), and sends are
   capped at `COMLINK_SEND_MAX_PER_HOUR` (default 5) on a sliding window. Every send is written to
   the audit log.

To enable send, set `COMLINK_ALLOW_SEND=true` **and** a non-empty `COMLINK_SEND_ALLOWLIST`:

```json
"env": {
  "COMLINK_USERNAME": "brandon@proton.me",
  "COMLINK_PASSWORD_COMMAND": "security find-generic-password -s proton-bridge -w",
  "COMLINK_ALLOW_SEND": "true",
  "COMLINK_SEND_ALLOWLIST": "kendra@chaosbit.dev, *@chaosbit.dev"
}
```

**Why the gate defaults off.** Email content is attacker-controlled. A hostile message read into
the model's context is a prompt-injection vector aimed at your send/move/delete tools. The gate
exists to bound the blast radius: with it off, no amount of injected text can make Comlink emit
mail, because the tool isn't there. Security posture is the feature — leave send off unless you
have a specific reason, and keep the allowlist tight when you turn it on.

---

## 8. Security note

- **Email content is untrusted input.** Message bodies and summary fields (subjects, sender and
  recipient names) are returned to the model with an untrusted-content marker. That marker is
  *advisory* — it biases the model, it is not an enforcement boundary.
- **The structural gate is the real defense.** Send is bounded by env flag → allowlist → confirm →
  rate limit. Deletes are soft: messages move to **Trash**, never EXPUNGE; deleting from Trash or
  Spam is refused (empty those from a Proton client).
- **Credentials.** Prefer `COMLINK_PASSWORD_COMMAND` (Keychain / Vaultwarden) over a static
  password. The password is never logged and is scrubbed from surfaced error text.
- **Audit trail.** Every send and delete appends a line to `COMLINK_AUDIT_LOG`
  (`~/.comlink/audit.jsonl` by default) with enough detail to reconstruct what an agent did.

---

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `BridgeUnavailable` — "Bridge not reachable on 127.0.0.1:1143" | Bridge app not running | Start Proton Mail Bridge and retry. |
| `AuthFailed` — "IMAP login rejected" | Bridge app password rotated | Re-run §3 Keychain store with the new app password from Bridge → Mailbox details. |
| `FolderNotFound` | Misspelled folder name | Use `proton_list_folders`; the error includes fuzzy suggestions. |
| `InvalidTarget` — "is a label, not a folder" | Tried to move into a label | Labels coexist with folders in Proton; move into a folder, or apply labels from a Proton client. |
| `SendBlocked` | Send gate / allowlist / rate limit | The message names which layer; adjust `COMLINK_ALLOW_SEND`, `COMLINK_SEND_ALLOWLIST`, or wait out the rate limit. |
| `UidStale` — "UIDVALIDITY changed" | Cached UIDs went stale | Re-run `proton_list_messages` / `proton_search_messages` and retry with fresh UIDs. |
| `proton_send_message` not in tool list | `COMLINK_ALLOW_SEND` is not `true` | Intentional — set it to `true` (and an allowlist) to register the tool. |

Error classes match the design doc §8 taxonomy; every message tells the agent what to do next.

---

## 10. References

- Design doc: `docs/design-doc.md` (architecture, Bridge constraints, security model, epics).
- MCP spec: https://modelcontextprotocol.io
- Proton Mail Bridge: https://proton.me/mail/bridge
