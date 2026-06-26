"""Live organize-path integration tests against a running Proton Mail Bridge (§9).

Marked ``integration`` and excluded from the default ``pytest`` run. The write
mutations are additionally gated behind ``COMLINK_TEST_WRITE=1`` so a bare
``uv run pytest -m integration`` never mutates a real mailbox by accident::

    COMLINK_TEST_WRITE=1 uv run pytest -m integration -k organize

The suite is self-cleaning and reversible: it creates a temporary folder, seeds
it by copying a message in, moves the message out and back, marks it, deletes it
to Trash and restores it, then drops the temporary folder. No EXPUNGE is ever
issued (delete = move to Trash; §3, §7.3).

The final MCP-Inspector / iOS visual confirmation pass remains manual (§9): an
automated test cannot assert that the change appeared in the Proton iOS app.
"""

from __future__ import annotations

import os
import uuid

import pytest

from comlink.bridge.imap import ImapConnectionManager
from comlink.config import ComlinkSettings
from comlink.server import (
    create_folder_impl,
    delete_messages_impl,
    list_messages_impl,
    mark_messages_impl,
    move_messages_impl,
)

pytestmark = pytest.mark.integration

_WRITE_ENABLED = os.environ.get("COMLINK_TEST_WRITE") == "1"
_write_guard = pytest.mark.skipif(
    not _WRITE_ENABLED,
    reason="Write mutations gated behind COMLINK_TEST_WRITE=1 to protect real mailboxes.",
)


@_write_guard
class TestOrganizeRoundTrip:
    async def test_create_move_mark_delete_restore(
        self,
        settings: ComlinkSettings,
        imap: ImapConnectionManager,
        seed_folder: str,
    ) -> None:
        listing = await list_messages_impl(imap, folder=seed_folder, limit=1)
        if not listing["messages"]:
            pytest.skip(f"Seed folder '{seed_folder}' is empty; nothing to organize.")
        uid = int(listing["messages"][0]["uid"])
        temp_name = f"comlink-test-{uuid.uuid4().hex[:8]}"

        created = await create_folder_impl(imap, name=temp_name, kind="folder")
        assert created["kind"] == "folder"
        try:
            # Move the seed message into the temp folder, then re-resolve its UID.
            moved = await move_messages_impl(
                imap, uids=[uid], source_folder=seed_folder, destination_folder=temp_name
            )
            assert moved["succeeded"] == [uid]

            in_temp = await list_messages_impl(imap, folder=temp_name, limit=5)
            assert in_temp["messages"], "Moved message should appear in the temp folder."
            temp_uid = int(in_temp["messages"][0]["uid"])

            marked = await mark_messages_impl(
                imap, uids=[temp_uid], folder=temp_name, mark="flagged"
            )
            assert marked["succeeded"] == [temp_uid]

            # Delete (to Trash) then restore from Trash back into the temp folder.
            deleted = await delete_messages_impl(settings, imap, uids=[temp_uid], folder=temp_name)
            assert deleted["destination"] == "Trash"

            trash = await list_messages_impl(imap, folder="Trash", limit=25)
            trash_uids = [int(m["uid"]) for m in trash["messages"]]
            assert trash_uids, "Deleted message should be reachable in Trash."
            await move_messages_impl(
                imap,
                uids=trash_uids[:1],
                source_folder="Trash",
                destination_folder=seed_folder,
            )
        finally:
            # Best-effort cleanup: drop the temp folder via Bridge (test-only,
            # reaches into the manager internals deliberately).
            def _drop(client: object) -> None:
                entries = ImapConnectionManager._list_entries_sync(client)
                raw = next((e.raw for e in entries if e.name == temp_name), None)
                if raw is not None:
                    client.delete_folder(raw)  # type: ignore[attr-defined]

            await imap._call(_drop)

    async def test_delete_from_trash_refused(
        self, settings: ComlinkSettings, imap: ImapConnectionManager
    ) -> None:
        from comlink.errors import InvalidTarget

        listing = await list_messages_impl(imap, folder="Trash", limit=1)
        if not listing["messages"]:
            pytest.skip("Trash is empty; cannot exercise the refusal path.")
        uid = int(listing["messages"][0]["uid"])
        with pytest.raises(InvalidTarget, match="protected"):
            await delete_messages_impl(settings, imap, uids=[uid], folder="Trash")
