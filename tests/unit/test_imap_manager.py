"""IMAP connection manager: lazy connect, reconnect-on-drop, error mapping,
mailbox resolution, pagination, All Mail exclusion (§3, §9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from imapclient.exceptions import LoginError

import comlink.bridge.imap as imap_module
from comlink.bridge.imap import ImapConnectionManager, build_search_criteria
from comlink.errors import AuthFailed, BridgeUnavailable, ComlinkError, ConfigError, FolderNotFound

from ..conftest import make_settings

DEFAULT_FOLDERS: list[tuple[tuple[bytes, ...], str]] = [
    ((), "INBOX"),
    ((), "Sent"),
    ((), "All Mail"),
    ((), "Folders/receipts"),
    ((), "Labels/news"),
    ((b"\\Noselect",), "Folders"),
]


@dataclass
class FakeBridgeState:
    folders: list[tuple[tuple[bytes, ...], str]] = field(
        default_factory=lambda: list(DEFAULT_FOLDERS)
    )
    counts: dict[str, tuple[int, int]] = field(default_factory=dict)
    search_uids: dict[str, list[int]] = field(default_factory=dict)
    raw_messages: dict[tuple[str, int], bytes] = field(default_factory=dict)
    refuse_connection: bool = False
    fail_login: bool = False
    drop_ops: int = 0  # raise OSError on this many subsequent operations
    clients: list[FakeIMAPClient] = field(default_factory=list)


class FakeIMAPClient:
    def __init__(self, state: FakeBridgeState) -> None:
        self.state = state
        self.selected: str | None = None
        self.selects: list[tuple[str, bool]] = []
        self.starttls_called = False
        self.logged_in = False
        self.shutdown_called = False

    def _maybe_drop(self) -> None:
        if self.state.drop_ops > 0:
            self.state.drop_ops -= 1
            raise OSError("connection dropped")

    def starttls(self, ssl_context: object) -> None:
        self.starttls_called = True

    def login(self, username: str, password: str) -> None:
        if self.state.fail_login:
            raise LoginError("LOGIN command error: BAD credentials")
        self.logged_in = True

    def list_folders(self) -> list[tuple[tuple[bytes, ...], bytes, str]]:
        self._maybe_drop()
        return [(flags, b"/", name) for flags, name in self.state.folders]

    def folder_status(self, name: str, what: list[bytes]) -> dict[bytes, int]:
        messages, unseen = self.state.counts.get(name, (0, 0))
        return {b"MESSAGES": messages, b"UNSEEN": unseen}

    def select_folder(self, name: str, readonly: bool = False) -> dict[bytes, Any]:
        self._maybe_drop()
        self.selected = name
        self.selects.append((name, readonly))
        return {}

    def search(self, criteria: list[Any]) -> list[int]:
        assert self.selected is not None
        return list(self.state.search_uids.get(self.selected, []))

    def fetch(self, uids: list[int], keys: list[bytes]) -> dict[int, dict[bytes, Any]]:
        assert self.selected is not None
        result: dict[int, dict[bytes, Any]] = {}
        for uid in uids:
            if b"BODY.PEEK[]" in keys:
                raw = self.state.raw_messages.get((self.selected, uid))
                if raw is not None:
                    result[uid] = {b"BODY[]": raw, b"FLAGS": (b"\\Seen",)}
            else:
                result[uid] = {b"FLAGS": (), b"RFC822.SIZE": 100 + uid}
        return result

    def shutdown(self) -> None:
        self.shutdown_called = True

    def logout(self) -> None:
        self.shutdown_called = True


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch) -> FakeBridgeState:
    state = FakeBridgeState()

    def factory(host: str, port: int = 143, ssl: bool = True, timeout: int | None = None) -> Any:
        if state.refuse_connection:
            raise ConnectionRefusedError("connection refused")
        client = FakeIMAPClient(state)
        state.clients.append(client)
        return client

    monkeypatch.setattr(imap_module, "IMAPClient", factory)
    return state


def make_manager() -> ImapConnectionManager:
    return ImapConnectionManager(make_settings())


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
