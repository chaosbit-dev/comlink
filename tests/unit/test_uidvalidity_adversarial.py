"""Adversarial attacks on UIDVALIDITY staleness handling (§3.5, §8, Epic 4).

Tech covers single-absent and one-absent-in-a-batch. Wrecker attacks the seams:
- a batch where EVERY UID is absent (all stale) — clean per-UID UidStale, zero
  mutation, zero EXPUNGE, and (through delete) a truthful all-failed audit entry;
- a three-way partition in ONE batch: present + absent(stale) + COPY-fail, each
  landing in the right bucket;
- mark with an absent UID in the MIDDLE of a batch;
- a connection drop on the _present_uids presence FETCH (before any mutation):
  the reconnect-replay must re-run the op WITHOUT double-mutating.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from comlink.bridge.imap import DELETED_FLAG, FLAGGED_FLAG, SEEN_FLAG
from comlink.errors import UidStale
from comlink.server import delete_messages_impl

from ..conftest import make_settings
from .conftest import FakeBridgeState, make_manager


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class TestAllUidsStale:
    async def test_move_all_absent_mutates_nothing(self, bridge: FakeBridgeState) -> None:
        bridge.absent_uids = {10, 11, 12}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == []
        assert [item.uid for item in result.failed] == [10, 11, 12]
        for item in result.failed:
            assert "UIDVALIDITY changed" in (item.error or "")
        assert bridge.copies == []
        assert bridge.added_flags == []
        assert bridge.moves == []
        assert bridge.expunges == 0

    async def test_mark_all_absent_mutates_nothing(self, bridge: FakeBridgeState) -> None:
        bridge.absent_uids = {1, 2, 3}
        manager = make_manager()
        result = await manager.mark_messages("INBOX", [1, 2, 3], "read")
        assert result.succeeded == []
        assert [item.uid for item in result.failed] == [1, 2, 3]
        assert bridge.added_flags == []
        assert bridge.removed_flags == []
        assert bridge.expunges == 0

    async def test_delete_all_absent_writes_single_all_failed_audit(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        bridge.folders.append(((), "Trash"))
        bridge.absent_uids = {4, 5}
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = make_manager()
        payload = await delete_messages_impl(settings, manager, uids=[4, 5], folder="INBOX")
        assert payload["succeeded"] == []
        assert [item["uid"] for item in payload["failed"]] == [4, 5]
        assert bridge.copies == []
        assert bridge.expunges == 0
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["succeeded"] == []
        assert entries[0]["failed"] == [4, 5]


class TestThreeWayPartition:
    async def test_present_absent_and_copyfail_each_land_in_right_bucket(
        self, bridge: FakeBridgeState
    ) -> None:
        # 10 present -> succeeds; 11 absent -> stale failure; 12 present but COPY
        # rejected -> copy failure. All three outcomes in one batch.
        bridge.absent_uids = {11}
        bridge.fail_copy_uids = {12}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == [10]
        failed = {item.uid: (item.error or "") for item in result.failed}
        assert set(failed) == {11, 12}
        assert "UIDVALIDITY changed" in failed[11]
        assert "UIDVALIDITY" not in failed[12]  # a real COPY rejection, not staleness
        # Only the present, copyable UID moved.
        assert bridge.copies == [([10], "Folders/receipts")]
        assert bridge.added_flags == [([10], [DELETED_FLAG])]
        assert bridge.expunges == 0

    async def test_mark_absent_in_the_middle_of_batch(self, bridge: FakeBridgeState) -> None:
        bridge.absent_uids = {2}
        manager = make_manager()
        result = await manager.mark_messages("INBOX", [1, 2, 3], "flagged")
        assert result.succeeded == [1, 3]
        assert [item.uid for item in result.failed] == [2]
        assert "not present" in (result.failed[0].error or "")
        assert bridge.added_flags == [([1], [FLAGGED_FLAG]), ([3], [FLAGGED_FLAG])]
        assert bridge.expunges == 0


class TestPresenceFetchDropReplaysSafely:
    async def test_move_drop_on_presence_fetch_replays_without_double_copy(
        self, bridge: FakeBridgeState
    ) -> None:
        # The _present_uids FETCH drops the connection ONCE, before any COPY. The
        # reconnect-replay in _call_sync re-runs the whole op; because no mutation
        # had occurred, the COPY must happen EXACTLY once (no duplicate).
        bridge.present_fetch_drops = 1
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11])
        assert result.succeeded == [10, 11]
        assert result.failed == []
        # COPY ran once per UID despite the replay — never twice.
        assert bridge.copies == [([10], "Folders/receipts"), ([11], "Folders/receipts")]
        assert bridge.copies.count(([10], "Folders/receipts")) == 1
        assert bridge.expunges == 0
        # A reconnect happened (second client created), proving the drop fired.
        assert len(bridge.clients) == 2

    async def test_mark_drop_on_presence_fetch_replays_without_double_store(
        self, bridge: FakeBridgeState
    ) -> None:
        bridge.present_fetch_drops = 1
        manager = make_manager()
        result = await manager.mark_messages("INBOX", [5, 6], "read")
        assert result.succeeded == [5, 6]
        assert bridge.added_flags == [([5], [SEEN_FLAG]), ([6], [SEEN_FLAG])]
        assert bridge.added_flags.count(([5], [SEEN_FLAG])) == 1
        assert bridge.expunges == 0
        assert len(bridge.clients) == 2


def test_uid_stale_for_uid_message_is_actionable() -> None:
    # The per-UID variant names the UID + folder and points at the recovery tool.
    err = UidStale.for_uid(42, "receipts")
    msg = str(err)
    assert "42" in msg
    assert "receipts" in msg
    assert "proton_list_messages" in msg or "proton_search_messages" in msg
