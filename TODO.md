# Comlink — TODO / remaining work

Status: **the roadmap is shipped.** Design-doc Epics 0–5 are all done and live
(Epic 5 — remote Gonk deployment — was "design-only" in the doc; it was actually
built: public HTTPS + Cloudflare Access OAuth + in-server audience-bound JWT
gate, full read/organize/compose/send, verified live from the phone). What's
below is QA closeout + optional future work — no roadmap milestones remain.

## Finish Epic 4 acceptance (QA only — no new build; the live server now exists)
- [ ] **Run the 10-question eval set** (`evals/comlink_evals.xml`) as the naive-user
      pass; record pass/fail in `evals/RUNBOOK.md`. Includes the injection-resistance
      probe (Q10 — a hostile email must not drive a tool action). "All evals pass" is
      currently unverified.
- [ ] **Full MCP Inspector pass** — exercise every tool through the Inspector;
      confirm annotations (readOnlyHint / destructiveHint) and that
      `proton_send_message` is invisible when the gate is off.

## Live-verify to fully tick Epic 2/3 acceptance (code done + unit-tested + audited; just exercise once on the real account)
- [ ] Organize tools live: `create_folder`, `move_messages`, `mark_messages`,
      `delete_messages` (→ Trash, recoverable), `save_draft`.
- [ ] Send negatives live: a non-allowlisted recipient → `SendBlocked`; the 6th
      send in an hour → rate-limited.

## Optional / future (design-doc §12 open questions — not milestones)
- [ ] **Audit → ntfy on send** (design Open Q4). Cheap given existing ntfy infra;
      a worthwhile tripwire now that send is internet-exposed (push on every send).
- [ ] **Labels (v1.1):** `proton_label_messages` / `proton_unlabel_messages`
      (first confirm Bridge represents label application as IMAP COPY into
      `Labels/<name>`).
- [ ] **Attachment fetch (v2):** `proton_get_attachment(uid, folder, index, dest_dir)`
      with a size cap and dest restricted to `~/Downloads`.
- [ ] **Dispatch convergence:** `agent@chaosbit.dev` as a second Comlink instance
      (`allow_send=true` + tight allowlist) — parked until Dispatch exists.

## Trivial deploy loose ends (in gonk-infra)
- [ ] Pin the cloudflared image off `:latest` to a current release.
- [ ] Delete the stray untracked `gonk-infra/cloudflared/config.yml` (superseded by
      the workload `ConfigMap`).
