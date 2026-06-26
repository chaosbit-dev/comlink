"""IMAP connection manager: lazy connect, reconnect-on-drop, error mapping,
mailbox resolution, pagination, All Mail exclusion (§3, §9)."""

from __future__ import annotations

import pytest

from comlink.bridge.imap import (
    DELETED_FLAG,
    FLAGGED_FLAG,
    SEEN_FLAG,
    ImapConnectionManager,
    build_search_criteria,
)
from comlink.errors import (
    AuthFailed,
    BridgeUnavailable,
    ComlinkError,
    ConfigError,
    FolderNotFound,
    InvalidTarget,
)

from ..conftest import make_settings
from .conftest import (
    DEFAULT_FOLDERS,
    FakeBridgeState,
    FakeIMAPClient,
    make_manager,
)

__all__ = ["DEFAULT_FOLDERS", "FakeBridgeState", "FakeIMAPClient", "make_manager"]


class TestConnectionLifecycle:
    async def test_lazy_connect(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        assert bridge.clients == []
        count = await manager.verify_connectivity()
        assert count == 5  # \Noselect entry skipped
        assert len(bridge.clients) == 1
        assert bridge.clients[0].starttls_called
        assert bridge.clients[0].logged_in

    async def test_connection_reused_across_calls(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        await manager.verify_connectivity()
        await manager.verify_connectivity()
        assert len(bridge.clients) == 1

    async def test_reconnect_on_drop(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        await manager.verify_connectivity()
        bridge.drop_ops = 1
        count = await manager.verify_connectivity()
        assert count == 5
        assert len(bridge.clients) == 2
        assert bridge.clients[0].shutdown_called

    async def test_connection_refused_maps_to_bridge_unavailable(
        self, bridge: FakeBridgeState
    ) -> None:
        bridge.refuse_connection = True
        manager = make_manager()
        with pytest.raises(BridgeUnavailable, match=r"127\.0\.0\.1:1143"):
            await manager.verify_connectivity()

    async def test_login_failure_maps_to_auth_failed(self, bridge: FakeBridgeState) -> None:
        bridge.fail_login = True
        manager = make_manager()
        with pytest.raises(AuthFailed, match="COMLINK_PASSWORD"):
            await manager.verify_connectivity()
        assert bridge.clients[0].shutdown_called

    async def test_missing_username_is_config_error(self, bridge: FakeBridgeState) -> None:
        manager = ImapConnectionManager(make_settings(username=""))
        with pytest.raises(ConfigError, match="COMLINK_USERNAME"):
            await manager.verify_connectivity()

    async def test_aclose_drops_connection(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        await manager.verify_connectivity()
        await manager.aclose()
        assert bridge.clients[0].shutdown_called
        await manager.verify_connectivity()
        assert len(bridge.clients) == 2


class TestMailboxes:
    async def test_list_mailboxes_clean_names_kinds_counts(self, bridge: FakeBridgeState) -> None:
        bridge.counts["INBOX"] = (12, 3)
        bridge.counts["Folders/receipts"] = (7, 0)
        manager = make_manager()
        statuses = await manager.list_mailboxes()
        by_name = {status.name: status for status in statuses}
        assert set(by_name) == {"INBOX", "Sent", "All Mail", "receipts", "news"}
        assert by_name["INBOX"].kind == "system"
        assert by_name["INBOX"].message_count == 12
        assert by_name["INBOX"].unread_count == 3
        assert by_name["receipts"].kind == "folder"
        assert by_name["receipts"].raw == "Folders/receipts"
        assert by_name["news"].kind == "label"

    async def test_resolve_clean_name_selects_raw(self, bridge: FakeBridgeState) -> None:
        bridge.search_uids["Folders/receipts"] = [1]
        manager = make_manager()
        clean, total, _page = await manager.fetch_summary_page(
            "receipts", ["ALL"], limit=25, offset=0
        )
        assert clean == "receipts"
        assert total == 1
        assert bridge.clients[0].selects == [("Folders/receipts", True)]

    async def test_resolve_is_case_insensitive(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        clean, _total, _page = await manager.fetch_summary_page(
            "inbox", ["ALL"], limit=25, offset=0
        )
        assert clean == "INBOX"

    async def test_unknown_folder_raises_with_suggestion(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(FolderNotFound, match="receipts"):
            await manager.fetch_summary_page("recipts", ["ALL"], limit=25, offset=0)


class TestSummaryPage:
    async def test_newest_first_pagination(self, bridge: FakeBridgeState) -> None:
        bridge.search_uids["INBOX"] = [3, 1, 10, 7, 5, 2, 9, 4, 8, 6]
        manager = make_manager()
        _clean, total, page = await manager.fetch_summary_page("INBOX", ["ALL"], limit=3, offset=0)
        assert total == 10
        assert [uid for uid, _ in page] == [10, 9, 8]
        _clean, _total, page = await manager.fetch_summary_page("INBOX", ["ALL"], limit=3, offset=8)
        assert [uid for uid, _ in page] == [2, 1]

    async def test_mailbox_reselected_every_call(self, bridge: FakeBridgeState) -> None:
        # §3.5 — UIDVALIDITY can change; never reuse a selection across calls.
        bridge.search_uids["INBOX"] = [1, 2]
        manager = make_manager()
        await manager.fetch_summary_page("INBOX", ["ALL"], limit=5, offset=0)
        await manager.fetch_summary_page("INBOX", ["ALL"], limit=5, offset=0)
        assert bridge.clients[0].selects == [("INBOX", True), ("INBOX", True)]

    async def test_empty_page_does_not_fetch(self, bridge: FakeBridgeState) -> None:
        bridge.search_uids["INBOX"] = [1]
        manager = make_manager()
        _clean, total, page = await manager.fetch_summary_page(
            "INBOX", ["ALL"], limit=25, offset=10
        )
        assert total == 1
        assert page == []


class TestSearchMailboxes:
    async def test_default_scope_excludes_all_mail_and_labels(
        self, bridge: FakeBridgeState
    ) -> None:
        for raw in ("INBOX", "Sent", "All Mail", "Folders/receipts", "Labels/news"):
            bridge.search_uids[raw] = [1]
        manager = make_manager()
        hits = await manager.search_mailboxes(["TEXT", "x"], folder=None, cap=100)
        folders_hit = {name for name, _uid, _data in hits}
        assert folders_hit == {"INBOX", "Sent", "receipts"}

    async def test_all_mail_searched_when_explicitly_requested(
        self, bridge: FakeBridgeState
    ) -> None:
        bridge.search_uids["All Mail"] = [5, 6]
        manager = make_manager()
        hits = await manager.search_mailboxes(["TEXT", "x"], folder="All Mail", cap=100)
        assert {name for name, _uid, _data in hits} == {"All Mail"}
        assert sorted(uid for _name, uid, _data in hits) == [5, 6]

    async def test_cap_limits_total_results(self, bridge: FakeBridgeState) -> None:
        bridge.search_uids["INBOX"] = [1, 2, 3, 4, 5]
        bridge.search_uids["Sent"] = [1, 2, 3]
        manager = make_manager()
        hits = await manager.search_mailboxes(["TEXT", "x"], folder=None, cap=4)
        assert len(hits) == 4


class TestFetchRawMessage:
    async def test_returns_body_and_flags(self, bridge: FakeBridgeState) -> None:
        bridge.raw_messages[("INBOX", 42)] = b"From: a@b.c\r\n\r\nhello"
        manager = make_manager()
        clean, raw, flags = await manager.fetch_raw_message("INBOX", 42)
        assert clean == "INBOX"
        assert raw == b"From: a@b.c\r\n\r\nhello"
        assert flags == (b"\\Seen",)

    async def test_missing_uid_is_actionable(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(ComlinkError, match="proton_list_messages"):
            await manager.fetch_raw_message("INBOX", 999)


class TestSearchCriteria:
    def test_default_is_all(self) -> None:
        assert build_search_criteria() == ["ALL"]

    def test_filters_compose(self) -> None:
        criteria = build_search_criteria(
            query="hera",
            from_="breeder@nobleheim.example",
            unread_only=True,
            since="2026-06-01",
        )
        assert criteria[0] == "UNSEEN"
        assert criteria[1:3] == ["TEXT", "hera"]
        assert criteria[3:5] == ["FROM", "breeder@nobleheim.example"]
        assert criteria[5] == "SINCE"
        assert str(criteria[6]) == "2026-06-01"

    def test_invalid_date_is_actionable(self) -> None:
        with pytest.raises(ComlinkError, match="ISO date"):
            build_search_criteria(since="June 1st")


class TestMoveMessages:
    async def test_copy_then_mark_deleted_no_expunge(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11])
        assert result.succeeded == [10, 11]
        assert result.failed == []
        # Source selected non-readonly (first non-readonly select in the codebase).
        assert bridge.clients[0].selects == [("INBOX", False)]
        # COPY into the resolved raw destination, never move()/expunge().
        assert bridge.copies == [([10], "Folders/receipts"), ([11], "Folders/receipts")]
        assert bridge.added_flags == [([10], [DELETED_FLAG]), ([11], [DELETED_FLAG])]
        assert bridge.moves == []
        assert bridge.expunges == 0

    async def test_label_destination_rejected_with_zero_mutations(
        self, bridge: FakeBridgeState
    ) -> None:
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="label, not a folder"):
            await manager.move_messages("INBOX", "news", [1, 2])
        # No server-side mutation occurred — rejection happens before any COPY/select.
        assert bridge.copies == []
        assert bridge.added_flags == []
        assert bridge.clients[0].selects == []

    async def test_partial_success_reported(self, bridge: FakeBridgeState) -> None:
        bridge.fail_copy_uids = {11}
        manager = make_manager()
        result = await manager.move_messages("INBOX", "receipts", [10, 11, 12])
        assert result.succeeded == [10, 12]
        assert [item.uid for item in result.failed] == [11]
        assert result.failed[0].ok is False
        assert result.failed[0].error


class TestMarkMessages:
    @pytest.mark.parametrize(
        ("mark", "flag", "added"),
        [
            ("read", SEEN_FLAG, True),
            ("unread", SEEN_FLAG, False),
            ("flagged", FLAGGED_FLAG, True),
            ("unflagged", FLAGGED_FLAG, False),
        ],
    )
    async def test_flag_mapping(
        self, bridge: FakeBridgeState, mark: str, flag: bytes, added: bool
    ) -> None:
        bridge.search_uids["INBOX"] = []
        manager = make_manager()
        result = await manager.mark_messages("INBOX", [7], mark)  # type: ignore[arg-type]
        assert result.succeeded == [7]
        assert bridge.clients[0].selects == [("INBOX", False)]
        if added:
            assert bridge.added_flags == [([7], [flag])]
            assert bridge.removed_flags == []
        else:
            assert bridge.removed_flags == [([7], [flag])]
            assert bridge.added_flags == []


class TestMoveToTrash:
    async def test_moves_to_trash_via_copy(self, bridge: FakeBridgeState) -> None:
        bridge.folders.append(((), "Trash"))
        manager = make_manager()
        result = await manager.move_to_trash("INBOX", [3])
        assert result.succeeded == [3]
        assert bridge.copies == [([3], "Trash")]
        assert bridge.added_flags == [([3], [DELETED_FLAG])]
        assert bridge.expunges == 0

    async def test_delete_from_trash_refused(self, bridge: FakeBridgeState) -> None:
        bridge.folders.append(((), "Trash"))
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="protected"):
            await manager.move_to_trash("Trash", [3])
        assert bridge.copies == []
        assert bridge.added_flags == []

    async def test_delete_from_spam_refused(self, bridge: FakeBridgeState) -> None:
        bridge.folders.append(((), "Spam"))
        bridge.folders.append(((), "Trash"))
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="protected"):
            await manager.move_to_trash("Spam", [3])
        assert bridge.copies == []


class TestCreateMailbox:
    async def test_create_folder_namespace(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        raw, parent = await manager.create_mailbox("puppy", "folder")
        assert raw == "Folders/puppy"
        assert parent is None
        assert bridge.created_folders == ["Folders/puppy"]

    async def test_create_label_namespace(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        raw, parent = await manager.create_mailbox("vip", "label")
        assert raw == "Labels/vip"
        assert parent is None
        assert bridge.created_folders == ["Labels/vip"]

    async def test_create_nested_folder_uses_delimiter(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        raw, parent = await manager.create_mailbox("hera", "folder", parent="receipts")
        assert raw == "Folders/receipts/hera"
        assert parent == "receipts"

    async def test_nesting_under_label_rejected(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="not a folder"):
            await manager.create_mailbox("x", "folder", parent="news")
        assert bridge.created_folders == []

    async def test_already_exists_locally_is_actionable(self, bridge: FakeBridgeState) -> None:
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="already exists"):
            await manager.create_mailbox("receipts", "folder")
        assert bridge.created_folders == []

    async def test_server_already_exists_mapped(self, bridge: FakeBridgeState) -> None:
        bridge.create_error = "ALREADYEXISTS mailbox already exists"
        manager = make_manager()
        with pytest.raises(InvalidTarget, match="already exists"):
            await manager.create_mailbox("brandnew", "folder")

    async def test_other_create_error_is_comlink_error(self, bridge: FakeBridgeState) -> None:
        bridge.create_error = "BAD invalid mailbox name"
        manager = make_manager()
        with pytest.raises(ComlinkError, match="valid Proton mailbox names"):
            await manager.create_mailbox("brandnew", "folder")
