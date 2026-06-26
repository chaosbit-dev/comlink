"""Task 5 verification: fuzzy folder suggestions on EVERY resolve path (§8).

The design-doc §8 example is verbatim: a target "recipts" must suggest
"receipts" (and "recipes" when present). The real risk is a folder-resolving code
path that raises a BARE error instead of FolderNotFound.for_name — so this module
drives a typo'd folder name through every user-facing resolve path (list, search,
get, reply-parent, move source, move destination, mark, delete, create parent)
and asserts each one produces the fuzzy suggestion. If any path bypasses it, the
parametrized case for that path fails loudly.
"""

from __future__ import annotations

import pytest

from comlink.errors import FolderNotFound
from comlink.server import (
    create_folder_impl,
    delete_messages_impl,
    get_message_impl,
    list_messages_impl,
    mark_messages_impl,
    move_messages_impl,
    save_draft_impl,
    search_messages_impl,
)

from ..conftest import make_settings
from .conftest import FakeBridgeState, make_manager


@pytest.fixture
def bridge_with_receipts_and_recipes(bridge: FakeBridgeState) -> FakeBridgeState:
    # DEFAULT_FOLDERS already has Folders/receipts; add Folders/recipes and Trash so
    # the §8 example ("receipts" AND "recipes") and the delete path both work.
    bridge.folders.append(((), "Folders/recipes"))
    bridge.folders.append(((), "Trash"))
    return bridge


class TestSection8VerbatimExample:
    async def test_recipts_suggests_receipts_and_recipes(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        # The §8 row, end to end through a real resolve path (list).
        manager = make_manager()
        with pytest.raises(FolderNotFound) as excinfo:
            await list_messages_impl(manager, folder="recipts")
        message = str(excinfo.value)
        assert "'recipts' not found" in message
        assert "receipts" in message
        assert "recipes" in message
        assert "proton_list_folders" in message

    def test_for_name_orders_closest_first(self) -> None:
        # difflib ranks the nearer typo-neighbor first; "receipts" should precede
        # "recipes" for the input "recipts".
        message = str(FolderNotFound.for_name("recipts", ["receipts", "recipes", "INBOX"]))
        assert message.index("receipts") < message.index("recipes")


class TestEveryResolvePathIsFuzzy:
    """Each user-facing folder-resolve path must route through fuzzy suggestions."""

    async def test_list_folder(self, bridge_with_receipts_and_recipes: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await list_messages_impl(manager, folder="recipts")

    async def test_search_explicit_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await search_messages_impl(manager, query="x", folder="recipts")

    async def test_get_message_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await get_message_impl(manager, uid=1, folder="recipts")

    async def test_reply_parent_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        # The reply path resolves in_reply_to_folder via fetch_raw_message.
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await save_draft_impl(
                settings,
                manager,
                to=["k@chaosbit.dev"],
                body_text="x",
                in_reply_to_uid=1,
                in_reply_to_folder="recipts",
            )

    async def test_move_source_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await move_messages_impl(
                manager, uids=[1], source_folder="recipts", destination_folder="INBOX"
            )

    async def test_move_destination_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        # Source resolves fine (INBOX); the typo'd DESTINATION must still be fuzzy.
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await move_messages_impl(
                manager, uids=[1], source_folder="INBOX", destination_folder="recipts"
            )

    async def test_mark_folder(self, bridge_with_receipts_and_recipes: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await mark_messages_impl(manager, uids=[1], folder="recipts", mark="read")

    async def test_delete_folder(self, bridge_with_receipts_and_recipes: FakeBridgeState) -> None:
        settings = make_settings()
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await delete_messages_impl(settings, manager, uids=[1], folder="recipts")

    async def test_create_parent_folder(
        self, bridge_with_receipts_and_recipes: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await create_folder_impl(manager, name="new", kind="folder", parent="recipts")
