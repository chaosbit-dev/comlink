"""append_draft UID-recovery edge cases (§6 Compose, Epic 3 Task 3).

Tech covered the happy max() case and the zero-match raise. Wrecker adds:
Message-ID collisions (multiple matches), a single match, and a search that
returns extra/stale UIDs alongside the real one — recovery must pick the
highest matching UID and never silently return a wrong one.
"""

from __future__ import annotations

import pytest

from comlink.errors import ComlinkError

from .conftest import FakeBridgeState, make_manager


@pytest.fixture
def bridge_with_drafts(bridge: FakeBridgeState) -> FakeBridgeState:
    bridge.folders.append(((), "Drafts"))
    return bridge


class TestAppendDraftUidRecovery:
    async def test_single_match_returns_that_uid(self, bridge_with_drafts: FakeBridgeState) -> None:
        msg_id = "<solo@chaosbit.dev>"
        bridge_with_drafts.message_id_uids[msg_id] = [12]
        manager = make_manager()
        assert await manager.append_draft(b"raw", msg_id) == 12

    async def test_collision_returns_highest_uid(self, bridge_with_drafts: FakeBridgeState) -> None:
        # Two drafts share a Message-ID (collision / double-append). Recovery
        # must deterministically return the newest (max) UID, not an arbitrary
        # one — the just-appended copy is the highest UID in the mailbox.
        msg_id = "<dup@chaosbit.dev>"
        bridge_with_drafts.message_id_uids[msg_id] = [4, 17, 9]
        manager = make_manager()
        assert await manager.append_draft(b"raw", msg_id) == 17

    async def test_extra_unsorted_uids_still_pick_max(
        self, bridge_with_drafts: FakeBridgeState
    ) -> None:
        msg_id = "<m@chaosbit.dev>"
        bridge_with_drafts.message_id_uids[msg_id] = [100, 2, 50, 3]
        manager = make_manager()
        assert await manager.append_draft(b"raw", msg_id) == 100

    async def test_zero_matches_raises_actionable_error_no_wrong_uid(
        self, bridge_with_drafts: FakeBridgeState
    ) -> None:
        # No silent wrong-UID: when the HEADER search finds nothing, raise.
        manager = make_manager()
        with pytest.raises(ComlinkError, match="could not be located"):
            await manager.append_draft(b"raw", "<ghost@chaosbit.dev>")
