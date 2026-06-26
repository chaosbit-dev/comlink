"""Adversarial attacks on DraftCreated.bcc_dropped semantics (§6, Epic 4).

A draft has no SMTP envelope and build_message never serializes a Bcc header, so
Bcc recipients on a draft are DROPPED and surfaced via bcc_dropped. Wrecker probes
the reporting edges: many Bcc, Bcc that overlaps To/Cc (documents the actual
no-dedup behavior — a low-severity truthfulness nit), and asserts that under every
case ZERO Bcc bytes are serialized into the appended draft.
"""

from __future__ import annotations

from email import message_from_bytes
from email.policy import default as default_policy

from comlink.server import save_draft_impl

from ..conftest import make_settings


class _CapturingDraftManager:
    def __init__(self) -> None:
        self.appended: list[tuple[bytes, str]] = []

    async def append_draft(self, raw_bytes: bytes, message_id: str) -> int:
        self.appended.append((raw_bytes, message_id))
        return 1


def _has_bcc_anywhere(raw: bytes) -> bool:
    # Parsed-header check AND a raw byte scan — a Bcc must not survive either way.
    msg = message_from_bytes(raw, policy=default_policy)
    return "Bcc" in msg or b"bcc:" in raw.lower()


class TestBccDroppedReporting:
    async def test_many_bcc_all_reported_and_no_header_serialized(self) -> None:
        bccs = [f"hidden{i}@chaosbit.dev" for i in range(8)]
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            bcc=bccs,
            subject="quiet",
            body_text="x",
        )
        assert payload["bcc_dropped"] == bccs
        raw = manager.appended[0][0]
        assert not _has_bcc_anywhere(raw)
        for addr in bccs:
            assert addr.encode() not in raw

    async def test_empty_bcc_reports_empty_list(self) -> None:
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            subject="s",
            body_text="x",
        )
        assert payload["bcc_dropped"] == []

    async def test_bcc_only_draft_drops_all_and_serializes_no_recipient_header(self) -> None:
        # A Bcc-only draft cannot carry ANY recipient (no To/Cc, no Bcc header), so
        # every address is dropped — the draft is still saved, never rejected.
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            bcc=["only@chaosbit.dev"],
            subject="blind",
            body_text="x",
        )
        assert payload["bcc_dropped"] == ["only@chaosbit.dev"]
        raw = manager.appended[0][0]
        assert not _has_bcc_anywhere(raw)
        assert b"only@chaosbit.dev" not in raw

    async def test_bcc_overlapping_to_or_cc_is_not_reported_dropped(self) -> None:
        # CORRECTED BEHAVIOR (Epic 4 finding 2): bcc_dropped excludes any Bcc that is
        # also a To/Cc recipient — that address is still delivered via its visible
        # header, so reporting it as "dropped" would over-report and could prompt an
        # unnecessary re-send. Only the genuinely-lost Bcc-only address remains.
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            cc=["cc@chaosbit.dev"],
            bcc=["kendra@chaosbit.dev", "cc@chaosbit.dev", "real-hidden@chaosbit.dev"],
            subject="s",
            body_text="x",
        )
        # Only the Bcc-only address is reported dropped; the To/Cc overlaps are not.
        assert payload["bcc_dropped"] == ["real-hidden@chaosbit.dev"]
        raw = manager.appended[0][0]
        # The To/Cc recipients remain deliverable via their headers, and no Bcc
        # header leaks the genuinely-hidden one.
        assert not _has_bcc_anywhere(raw)
        assert b"real-hidden@chaosbit.dev" not in raw
        assert b"kendra@chaosbit.dev" in raw  # present via To, so not truly "lost"

    async def test_bcc_overlap_is_case_insensitive(self) -> None:
        # The visible-recipient comparison lowercases the stripped address, matching
        # allowlist/recipient handling: a Bcc that differs only in case from a To
        # recipient is treated as already-delivered and is NOT reported dropped.
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            to=["Kendra@Chaosbit.dev"],
            bcc=["kendra@chaosbit.dev", "real-hidden@chaosbit.dev"],
            subject="s",
            body_text="x",
        )
        assert payload["bcc_dropped"] == ["real-hidden@chaosbit.dev"]

    async def test_duplicate_bcc_only_address_reported_once(self) -> None:
        # De-duplication within bcc itself: a genuinely-dropped address listed twice
        # is reported a single time, in first-seen order.
        manager = _CapturingDraftManager()
        payload = await save_draft_impl(
            make_settings(username="brandon@chaosbit.dev"),
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            bcc=["dup@chaosbit.dev", "dup@chaosbit.dev"],
            subject="s",
            body_text="x",
        )
        assert payload["bcc_dropped"] == ["dup@chaosbit.dev"]
