"""append_draft UID recovery via HEADER Message-ID search (Epic 3, Task 3).

The Bridge APPENDUID response is not relied upon; the draft carries a unique
Message-ID and we recover its UID with a HEADER Message-ID search in the same
locked op.
"""

from __future__ import annotations

import pytest

from comlink.bridge.imap import DRAFT_FLAG
from comlink.errors import ComlinkError

from .conftest import FakeBridgeState, make_manager


@pytest.fixture
def bridge_with_drafts(bridge: FakeBridgeState) -> FakeBridgeState:
    bridge.folders.append(((), "Drafts"))
    return bridge


class TestAppendDraft:
    async def test_appends_with_draft_flag_and_recovers_uid_by_message_id(
        self, bridge_with_drafts: FakeBridgeState
    ) -> None:
        msg_id = "<abc@chaosbit.dev>"
        # The HEADER Message-ID search returns matching UIDs; max() is taken.
        bridge_with_drafts.message_id_uids[msg_id] = [3, 9, 5]
        manager = make_manager()
        uid = await manager.append_draft(b"raw message bytes", msg_id)
        assert uid == 9
        # APPEND went to the resolved Drafts mailbox with the \Draft flag.
        assert len(bridge_with_drafts.appended) == 1
        mailbox, raw, flags = bridge_with_drafts.appended[0]
        assert mailbox == "Drafts"
        assert raw == b"raw message bytes"
        assert flags == [DRAFT_FLAG]

    async def test_missing_message_id_after_append_raises(
        self, bridge_with_drafts: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(ComlinkError, match="could not be located"):
            await manager.append_draft(b"raw", "<nope@chaosbit.dev>")
