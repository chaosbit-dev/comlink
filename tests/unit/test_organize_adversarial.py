"""Adversarial / edge-case coverage for Epic 2 organize paths.

Wrecker's demolition pass. Tech owns the happy paths and key branches
(test_imap_manager.py, test_server_organize.py, test_guardrails.py); this file
attacks the seams those left open:

- the no-EXPUNGE invariant under *every* path including error/exception paths
- partial success/failure permutations, duplicate UIDs, boundary cap math
- label-move + protected-delete refusals producing ZERO server mutation and
  ZERO audit entries
- mark idempotency / invalid mark values
- create_folder collisions, delimiter/special-char names, namespace correctness
- audit log-and-continue, partial-failure entry shape, no-secret leakage,
  append (not truncate) semantics
- redaction paths that could leak the Bridge password

Reuses FakeIMAPClient/FakeBridgeState from test_imap_manager (its expunge()
raises AssertionError, so any expunge call anywhere blows the test up loudly).
"""

from __future__ import annotations

import imaplib
import json
from pathlib import Path
from typing import Any

import pytest

from comlink.bridge.imap import (
    DELETED_FLAG,
    SEEN_FLAG,
)
from comlink.errors import (
    ComlinkError,
    InvalidTarget,
    redact,
)
from comlink.guardrails import append_audit, delete_audit_entry
from comlink.models import BatchResult, UidResult
from comlink.server import (
    MAX_BATCH_UIDS,
    delete_messages_impl,
    mark_messages_impl,
    move_messages_impl,
)

from ..conftest import make_settings

# Reuse the behavioral fakes from the shared unit conftest. The `bridge` fixture
# lives there too and is discovered automatically — importing it here would trip
# Ruff F811 when used as a test parameter.
from .conftest import (
    FakeBridgeState,
    FakeIMAPClient,
    make_manager,
)


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _with_trash(state: FakeBridgeState) -> None:
    state.folders.append(((), "Trash"))


def _with_spam(state: FakeBridgeState) -> None:
    state.folders.append(((), "Spam"))


# ---------------------------------------------------------------------------
# No-EXPUNGE invariant — every path, including error/exception paths.
# FakeIMAPClient.expunge() raises AssertionError, so reaching it fails loudly.
# We also assert move() (RFC6851 MOVE = COPY+STORE+EXPUNGE) is never used.
# ---------------------------------------------------------------------------


class TestNoExpungeInvariant:
    async def test_move_all_copies_fail_no_expunge_no_move(self, bridge: FakeBridgeState) -> None:
        # Every UID fails the COPY; make sure we never "clean up" with expunge.
        bridge.fail_copy_uids = {10, 11, 12}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == []
        assert [item.uid for item in result.failed] == [10, 11, 12]
        assert bridge.expunges == 0
        assert bridge.moves == []
        # No \Deleted flag set when the COPY failed (no orphaned source deletes).
        assert bridge.added_flags == []

    async def test_trash_all_copies_fail_no_expunge(self, bridge: FakeBridgeState) -> None:
        _with_trash(bridge)
        bridge.fail_copy_uids = {3, 4}
        manager = make_manager()
        result = await manager.move_to_trash("INBOX", [3, 4])
        assert result.succeeded == []
        assert bridge.expunges == 0
        assert bridge.moves == []
        assert bridge.added_flags == []

    async def test_select_failure_mid_operation_never_expunges(
        self, bridge: FakeBridgeState
    ) -> None:
        # Make select_folder blow up *after* resolution, the way a UIDVALIDITY /
        # connection hiccup might. The reconnect path retries once; force both to
        # fail with a non-OSError IMAP error so it propagates without expunge.
        manager = make_manager()

        original_select = FakeIMAPClient.select_folder

        def exploding_select(self: FakeIMAPClient, name: str, readonly: bool = False) -> Any:
            if not readonly:  # only the write select used by move
                raise imaplib.IMAP4.error("SELECT failed: server angry")
            return original_select(self, name, readonly)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(FakeIMAPClient, "select_folder", exploding_select)
            with pytest.raises(imaplib.IMAP4.error):
                await manager.move_messages("INBOX", "receipts", [1])
        assert bridge.expunges == 0
        assert bridge.moves == []
        assert bridge.copies == []

    async def test_mark_never_expunges_even_when_flag_op_raises(
        self, bridge: FakeBridgeState
    ) -> None:
        manager = make_manager()

        def boom(*_a: object, **_k: object) -> None:
            raise imaplib.IMAP4.error("STORE failed")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(FakeIMAPClient, "add_flags", boom)
            result = await manager.mark_messages("INBOX", [1, 2], "read")
        assert result.succeeded == []
        assert [i.uid for i in result.failed] == [1, 2]
        assert bridge.expunges == 0


# ---------------------------------------------------------------------------
# Partial success / failure permutations, duplicate + boundary UIDs.
# ---------------------------------------------------------------------------


class TestPartialAndBoundary:
    async def test_first_uid_fails_rest_succeed(self, bridge: FakeBridgeState) -> None:
        bridge.fail_copy_uids = {10}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == [11, 12]
        assert [i.uid for i in result.failed] == [10]
        # Only the successful UIDs got COPY + \Deleted; failed one got neither.
        assert bridge.copies == [([11], "Folders/receipts"), ([12], "Folders/receipts")]
        assert bridge.added_flags == [([11], [DELETED_FLAG]), ([12], [DELETED_FLAG])]

    async def test_duplicate_uids_are_processed_per_occurrence(
        self, bridge: FakeBridgeState
    ) -> None:
        # The manager does NOT dedupe — document the actual behavior: a duplicate
        # UID is copied + \Deleted twice. Harmless (idempotent on the server) but
        # the report reflects two entries.
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [5, 5])
        assert result.succeeded == [5, 5]
        assert bridge.copies == [([5], "Folders/receipts"), ([5], "Folders/receipts")]
        assert bridge.expunges == 0

    async def test_exactly_max_batch_passes(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        payload = await move_messages_impl(
            manager,
            uids=list(range(1, MAX_BATCH_UIDS + 1)),
            source_folder="INBOX",
            destination_folder="receipts",
        )
        assert len(payload["succeeded"]) == MAX_BATCH_UIDS

    async def test_one_over_max_batch_rejected_before_any_call(
        self, bridge: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(ComlinkError, match=f"max {MAX_BATCH_UIDS}"):
            await move_messages_impl(
                manager,
                uids=list(range(1, MAX_BATCH_UIDS + 2)),
                source_folder="INBOX",
                destination_folder="receipts",
            )
        assert bridge.copies == []

    async def test_duplicate_uids_can_exceed_cap_by_count(self, bridge: FakeBridgeState) -> None:
        # The cap counts list length, not distinct UIDs. 51 copies of UID 1 is
        # still rejected — documents that the cap is positional, not set-based.
        manager = make_manager()
        with pytest.raises(ComlinkError, match=f"max {MAX_BATCH_UIDS}"):
            await move_messages_impl(
                manager,
                uids=[1] * (MAX_BATCH_UIDS + 1),
                source_folder="INBOX",
                destination_folder="receipts",
            )
        assert bridge.copies == []

    async def test_empty_uids_rejected_for_every_write_tool(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        for call in (
            lambda: move_messages_impl(
                manager, uids=[], source_folder="INBOX", destination_folder="receipts"
            ),
            lambda: mark_messages_impl(manager, uids=[], folder="INBOX", mark="read"),
            lambda: delete_messages_impl(make_settings(), manager, uids=[], folder="INBOX"),
        ):
            with pytest.raises(ComlinkError, match="at least one UID"):
                await call()
        assert bridge.copies == []


# ---------------------------------------------------------------------------
# Label-move + protected-delete refusals: ZERO mutation, ZERO audit.
# ---------------------------------------------------------------------------


class TestRefusalsAreInert:
    async def test_label_move_does_not_select_copy_or_flag(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="label, not a folder"):
            await manager.move_messages("INBOX", "news", list(range(1, 20)))
        assert bridge.copies == []
        assert bridge.added_flags == []
        assert bridge.removed_flags == []
        # Resolution LISTs but never selects a mailbox for writing.
        assert bridge.clients[0].selects == []
        assert bridge.expunges == 0

    async def test_delete_from_trash_writes_no_audit_and_no_mutation(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        _with_trash(bridge)
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="protected"):
            await delete_messages_impl(settings, manager, uids=[1, 2, 3], folder="Trash")
        assert bridge.copies == []
        assert bridge.added_flags == []
        assert bridge.expunges == 0
        assert _read_audit(tmp_path / "audit.jsonl") == []

    async def test_delete_from_spam_writes_no_audit_and_no_mutation(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        _with_spam(bridge)
        _with_trash(bridge)
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="protected"):
            await delete_messages_impl(settings, manager, uids=[9], folder="Spam")
        assert bridge.copies == []
        assert _read_audit(tmp_path / "audit.jsonl") == []

    async def test_protected_check_is_case_insensitive_source(
        self, bridge: FakeBridgeState
    ) -> None:
        # Resolution is case-insensitive; "trash" must still hit the refusal,
        # not sneak past the protection because of casing.
        _with_trash(bridge)
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="protected"):
            await manager.move_to_trash("trash", [1])
        assert bridge.copies == []


# ---------------------------------------------------------------------------
# Mark idempotency and invalid values.
# ---------------------------------------------------------------------------


class TestMarkSemantics:
    async def test_mark_read_twice_is_idempotent_at_manager(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        await manager.mark_messages("INBOX", [1], "read")
        await manager.mark_messages("INBOX", [1], "read")
        # add_flags is issued each call (silent STORE is idempotent on server).
        assert bridge.added_flags == [([1], [SEEN_FLAG]), ([1], [SEEN_FLAG])]
        assert bridge.removed_flags == []
        assert bridge.expunges == 0

    async def test_invalid_mark_value_raises_keyerror_at_manager(
        self, bridge: FakeBridgeState
    ) -> None:
        # _MARK_OPS lookup is the only validation at the manager layer; the
        # Literal type guards the tool boundary. A bad value must not silently
        # no-op or mutate anything.
        manager = make_manager()
        with pytest.raises(KeyError):
            await manager.mark_messages("INBOX", [1], "archived")  # type: ignore[arg-type]
        assert bridge.added_flags == []
        assert bridge.removed_flags == []

    async def test_mark_partial_failure_split(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        real = FakeIMAPClient.add_flags

        def flaky(
            self: FakeIMAPClient,
            uids: list[int],
            flags: list[bytes],
            silent: bool = False,
        ) -> None:
            if uids == [2]:
                raise imaplib.IMAP4.error("STORE failed on 2")
            real(self, uids, flags, silent)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(FakeIMAPClient, "add_flags", flaky)
            result = await manager.mark_messages("INBOX", [1, 2, 3], "flagged")
        assert result.succeeded == [1, 3]
        assert [i.uid for i in result.failed] == [2]


# ---------------------------------------------------------------------------
# create_folder: collisions, delimiter/special chars, namespace correctness.
# ---------------------------------------------------------------------------


class TestCreateFolderEdges:
    async def test_emoji_folder_name_round_trips_namespace(self, bridge: FakeBridgeState) -> None:
        # Kendra WILL make a balloon folder.
        manager = make_manager()
        raw, parent = await manager.create_mailbox("🎈party", "folder")
        assert raw == "Folders/🎈party"
        assert parent is None
        assert bridge.created_folders == ["Folders/🎈party"]

    async def test_name_with_spaces_and_unicode(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        raw, _ = await manager.create_mailbox("Año Nuevo plans", "folder")
        assert raw == "Folders/Año Nuevo plans"

    async def test_name_containing_delimiter_char_is_passed_through(
        self, bridge: FakeBridgeState
    ) -> None:
        # A name with the hierarchy delimiter '/' creates a literally-named raw
        # path. Documents current behavior: no validation/escaping is done, so
        # "a/b" becomes Folders/a/b (an implicit nesting the user didn't ask for).
        manager = make_manager()
        raw, _ = await manager.create_mailbox("a/b", "folder")
        assert raw == "Folders/a/b"

    async def test_duplicate_folder_name_rejected_before_create(
        self, bridge: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="already exists"):
            await manager.create_mailbox("receipts", "folder")
        assert bridge.created_folders == []

    async def test_create_folder_named_like_system_mailbox_is_distinct(
        self, bridge: FakeBridgeState
    ) -> None:
        # Documents ACTUAL behavior: a folder named "INBOX" targets the distinct
        # raw "Folders/INBOX" and is created. The local dup set unions raw names
        # with clean names, but for namespaced creates the clean-name half is
        # effectively dead (a folder raw never equals a bare clean name), so the
        # system "INBOX" does NOT block it. This is benign (distinct mailbox) but
        # means the only real local dup guard is on the exact raw path; the rest
        # is delegated to the server's ALREADYEXISTS handling. Flagged in report.
        manager = make_manager()
        raw, _ = await manager.create_mailbox("INBOX", "folder")
        assert raw == "Folders/INBOX"
        assert bridge.created_folders == ["Folders/INBOX"]

    async def test_nested_folder_duplicate_detected(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        # Pre-create the nested raw so the second attempt collides.
        bridge.folders.append(((), "Folders/receipts/hera"))
        with pytest.raises(InvalidTarget, match="already exists"):
            await manager.create_mailbox("hera", "folder", parent="receipts")
        assert bridge.created_folders == []

    async def test_label_and_folder_same_name_should_coexist(self, bridge: FakeBridgeState) -> None:
        # SPEC §3.1: labels coexist with folders in Proton. A folder 'receipts'
        # already exists (DEFAULT_FOLDERS). Creating a *label* 'receipts' targets
        # the distinct raw 'Labels/receipts' and must be allowed.
        #
        # Verified correct: the local dup set keys on the raw path, and
        # 'Labels/receipts' is distinct from the folder's 'Folders/receipts', so
        # the label is created. (The clean-name half of the dup set never fires
        # for namespaced creates — see test_create_folder_named_like_system_*.)
        manager = make_manager()
        raw, _parent = await manager.create_mailbox("receipts", "label")
        assert raw == "Labels/receipts"
        assert "Labels/receipts" in bridge.created_folders


# ---------------------------------------------------------------------------
# Audit log: log-and-continue, partial-failure shape, no secrets, append.
# ---------------------------------------------------------------------------


class TestAuditAdversarial:
    async def test_delete_succeeds_when_audit_append_raises_oserror(
        self, bridge: FakeBridgeState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _with_trash(bridge)
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()

        def boom(*_a: object, **_k: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(Path, "open", boom)
        # The delete itself must still succeed end-to-end.
        payload = await delete_messages_impl(settings, manager, uids=[3], folder="INBOX")
        assert payload["destination"] == "Trash"
        assert payload["succeeded"] == [3]
        assert bridge.copies == [([3], "Trash")]
        assert bridge.expunges == 0

    async def test_audit_entry_shape_on_partial_failure(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        _with_trash(bridge)
        bridge.fail_copy_uids = {2}
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        await delete_messages_impl(settings, manager, uids=[1, 2, 3], folder="INBOX")
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        e = entries[0]
        assert e["action"] == "delete"
        assert e["folder"] == "INBOX"
        assert e["succeeded"] == [1, 3]
        assert e["failed"] == [2]
        assert e["uids"] == [1, 3, 2]  # succeeded + failed

    async def test_audit_appends_not_truncates_across_deletes(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        _with_trash(bridge)
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        await delete_messages_impl(settings, manager, uids=[1], folder="INBOX")
        await delete_messages_impl(settings, manager, uids=[2], folder="INBOX")
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert [e["succeeded"] for e in entries] == [[1], [2]]

    async def test_audit_entry_carries_no_password_even_on_unicode_folder(
        self, tmp_path: Path
    ) -> None:
        # Folder names are agent-supplied; ensure nothing in the entry path can
        # smuggle a secret, and the line is valid JSONL.
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        entry = delete_audit_entry("🎈/secret-folder", [1], [2])
        assert append_audit(settings, entry)
        line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
        parsed = json.loads(line)
        assert parsed["folder"] == "🎈/secret-folder"
        assert "bridge-app-password" not in line

    async def test_all_failed_delete_still_writes_single_entry(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        # Documents behavior: even when every UID fails the COPY, the call is
        # recorded (succeeded=[]). One entry, action=delete, no exception.
        _with_trash(bridge)
        bridge.fail_copy_uids = {1, 2}
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        await delete_messages_impl(settings, manager, uids=[1, 2], folder="INBOX")
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["succeeded"] == []
        assert entries[0]["failed"] == [1, 2]


# ---------------------------------------------------------------------------
# Redaction: the password must never survive into an error message.
# create_mailbox is the one organize path that surfaces raw IMAP error text.
# ---------------------------------------------------------------------------


class TestRedactionInOrganize:
    async def test_create_error_text_is_redacted(self, bridge: FakeBridgeState) -> None:
        # Force the server to echo the password back inside an IMAP error string
        # (a hostile/buggy Bridge). The surfaced ComlinkError must not contain it.
        pw = "bridge-app-password"
        bridge.create_error = f"BAD bad name (creds were {pw})"
        manager = make_manager()
        with pytest.raises(ComlinkError) as excinfo:
            await manager.create_mailbox("brandnew", "folder")
        assert pw not in str(excinfo.value)
        assert "[REDACTED]" in str(excinfo.value)

    def test_redact_handles_empty_and_none_secrets(self) -> None:
        # redact must never blank-replace on a falsy secret (would corrupt text).
        assert redact("hello world", [None, "", "world"]) == "hello [REDACTED]"
        assert redact("untouched", [None, ""]) == "untouched"

    async def test_failed_copy_error_text_is_redacted(self, bridge: FakeBridgeState) -> None:
        # FINDING 1: a hostile/buggy Bridge echoing the password into a COPY
        # error response must not leak it into the failed[] UidResult.error.
        pw = "bridge-app-password"
        bridge.copy_error_text = {7: f"NO COPY rejected (creds were {pw})"}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [7])
        assert result.succeeded == []
        assert len(result.failed) == 1
        err = result.failed[0].error or ""
        assert pw not in err
        assert "[REDACTED]" in err

    async def test_failed_store_error_text_is_redacted(self, bridge: FakeBridgeState) -> None:
        # FINDING 1: the \Deleted STORE (mark_messages and the COPY-ok/STORE-fail
        # path) must also redact server error text. Here via mark_messages, whose
        # failure text used to be raw str(exc).
        pw = "bridge-app-password"
        manager = make_manager()

        def leaky(*_a: object, **_k: object) -> None:
            raise imaplib.IMAP4.error(f"STORE rejected (password={pw})")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(FakeIMAPClient, "add_flags", leaky)
            result = await manager.mark_messages("INBOX", [1], "read")
        assert result.succeeded == []
        assert len(result.failed) == 1
        err = result.failed[0].error or ""
        assert pw not in err
        assert "[REDACTED]" in err

    async def test_copy_ok_store_fail_warning_text_is_redacted(
        self, bridge: FakeBridgeState
    ) -> None:
        # FINDING 1 + 3: COPY succeeds, the source \Deleted STORE fails echoing the
        # password. The UID is ok=True with a warning, and the warning must not
        # carry the secret.
        pw = "bridge-app-password"
        bridge.store_error_text = {4: f"NO STORE denied (creds {pw})"}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [4])
        assert result.succeeded == [4]
        assert len(result.warnings) == 1
        warn = result.warnings[0].warning or ""
        assert pw not in warn
        assert "[REDACTED]" in warn


# ---------------------------------------------------------------------------
# FINDING 2 — a mid-COPY-loop connection drop must NOT replay (no duplicate
# COPY); the dropped UID is reported failed. The reconnect-replay in _call_sync
# is for idempotent reads, not partial mutations (§3.5).
# ---------------------------------------------------------------------------


class TestMidLoopDropNoDuplicateCopy:
    async def test_drop_mid_copy_loop_reports_failed_no_duplicate(
        self, bridge: FakeBridgeState
    ) -> None:
        # UID 11 drops the connection on COPY; 10 already moved, 12 still moves.
        # The dropped UID is failed; 10 is NOT copied a second time (no replay).
        bridge.drop_on_copy_uids = {11}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == [10, 12]
        assert [i.uid for i in result.failed] == [11]
        # UID 10 appears exactly once — the whole op was not replayed.
        assert bridge.copies == [([10], "Folders/receipts"), ([12], "Folders/receipts")]
        assert bridge.copies.count(([10], "Folders/receipts")) == 1
        assert bridge.expunges == 0
        assert bridge.moves == []

    async def test_drop_on_first_copy_does_not_replay_whole_op(
        self, bridge: FakeBridgeState
    ) -> None:
        # A drop on the very first UID's COPY is recorded as that UID failing,
        # not a reconnect-and-replay that would re-run resolution + COPY.
        bridge.drop_on_copy_uids = {1}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [1, 2])
        assert result.succeeded == [2]
        assert [i.uid for i in result.failed] == [1]
        assert bridge.copies == [([2], "Folders/receipts")]
        # Exactly one client was ever created — no reconnect occurred for the op.
        assert len(bridge.clients) == 1


# ---------------------------------------------------------------------------
# FINDING 3 — COPY-ok then STORE-fail is a WARNING on an ok=True UID, never a
# failure. Reporting it failed would invite a duplicate-creating retry. A failed
# COPY remains a true failure and leaves no \Deleted on the source.
# ---------------------------------------------------------------------------


class TestCopyOkStoreFail:
    async def test_copy_ok_store_fail_reports_ok_with_warning_no_deleted_flag(
        self, bridge: FakeBridgeState
    ) -> None:
        bridge.store_error_text = {4: "NO STORE denied"}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [4])
        # The move happened: UID is ok (in succeeded), NOT failed.
        assert result.succeeded == [4]
        assert result.failed == []
        # COPY happened exactly once.
        assert bridge.copies == [([4], "Folders/receipts")]
        # The source got NO \Deleted flag (the STORE failed) — and we never
        # retried or expunged to "fix" it.
        assert bridge.added_flags == []
        assert bridge.expunges == 0
        # The truthful warning is carried on an ok=True entry.
        assert len(result.warnings) == 1
        assert result.warnings[0].uid == 4
        assert result.warnings[0].ok is True
        assert "Do NOT retry" in (result.warnings[0].warning or "")

    async def test_delete_copy_ok_store_fail_audited_as_succeeded(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        # Through the delete path: the warned UID is reported succeeded and the
        # audit entry reflects it truthfully (succeeded, not failed).
        _with_trash(bridge)
        bridge.store_error_text = {5: "NO STORE denied"}
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        payload = await delete_messages_impl(settings, manager, uids=[5], folder="INBOX")
        assert payload["succeeded"] == [5]
        assert payload["failed"] == []
        assert payload["warnings"][0]["uid"] == 5
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["succeeded"] == [5]
        assert entries[0]["failed"] == []

    async def test_failed_copy_remains_failure_with_no_deleted_flag(
        self, bridge: FakeBridgeState
    ) -> None:
        # Preserve the correct behavior: a FAILED COPY is a true failure and the
        # source gets no \Deleted (no orphaned delete). Distinct from STORE-fail.
        bridge.fail_copy_uids = {6}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [6])
        assert result.succeeded == []
        assert [i.uid for i in result.failed] == [6]
        assert result.warnings == []
        assert bridge.added_flags == []
        assert bridge.copies == []
        assert bridge.expunges == 0


# ---------------------------------------------------------------------------
# Model-level: BatchResult never collapses partial success to a bool.
# ---------------------------------------------------------------------------


class TestBatchResultModel:
    def test_partial_success_keeps_both_lists(self) -> None:
        result = BatchResult(
            folder="INBOX",
            succeeded=[1, 3],
            failed=[UidResult(uid=2, ok=False, error="boom")],
        )
        dumped = result.model_dump()
        assert dumped["succeeded"] == [1, 3]
        assert dumped["failed"][0]["uid"] == 2
        assert dumped["failed"][0]["ok"] is False
