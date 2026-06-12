"""Live read-path integration tests against a running Proton Mail Bridge (§9).

Marked ``integration`` and excluded from the default ``pytest`` run. Run with::

    uv run pytest -m integration

Covers Epic 0 (health check, connectivity) and Epic 1 (list folders, list/search
messages, get message). No writes, no sends — entirely read-only.
"""

from __future__ import annotations

import json

import pytest

from comlink.bridge.imap import ImapConnectionManager
from comlink.bridge.parsing import UNTRUSTED_CONTENT_MARKER
from comlink.config import ComlinkSettings
from comlink.server import (
    get_message_impl,
    health_check_impl,
    list_folders_impl,
    list_messages_impl,
    search_messages_impl,
)

pytestmark = pytest.mark.integration


class TestHealthCheck:
    async def test_health_check_reports_bridge_status(
        self, settings: ComlinkSettings, imap: ImapConnectionManager
    ) -> None:
        report = await health_check_impl(settings, imap)
        assert report["imap"]["ok"] is True, report["imap"].get("error")
        assert report["smtp"]["ok"] is True, report["smtp"].get("error")
        assert report["bridge_reachable"] is True
        assert isinstance(report["folder_count"], int)
        assert report["folder_count"] >= 1
        assert report["send_gate"]["enabled"] == settings.allow_send


class TestListFolders:
    async def test_lists_system_mailboxes_with_clean_names(
        self, imap: ImapConnectionManager
    ) -> None:
        result = await list_folders_impl(imap)
        names = {f["name"] for f in result["folders"]}
        # System mailboxes should be present and surfaced under clean names.
        assert "INBOX" in names
        kinds = {f["kind"] for f in result["folders"]}
        assert kinds <= {"folder", "label", "system"}
        # No raw Bridge prefixes leak through to the model.
        assert not any(f["name"].startswith(("Folders/", "Labels/")) for f in result["folders"])


class TestListMessages:
    async def test_list_inbox_newest_first(
        self, imap: ImapConnectionManager, seed_folder: str
    ) -> None:
        result = await list_messages_impl(imap, folder=seed_folder, limit=5)
        assert result["folder"] == seed_folder or result["folder"].lower() == seed_folder.lower()
        assert result["limit"] == 5
        dates = [m["date"] for m in result["messages"] if m["date"]]
        # Newest-first ordering: dates are non-increasing where present.
        assert dates == sorted(dates, reverse=True)

    async def test_pagination_offset(self, imap: ImapConnectionManager, seed_folder: str) -> None:
        page1 = await list_messages_impl(imap, folder=seed_folder, limit=2, offset=0)
        if page1["total"] < 3:
            pytest.skip("Seed folder has too few messages for pagination assertions.")
        page2 = await list_messages_impl(imap, folder=seed_folder, limit=2, offset=2)
        uids1 = {m["uid"] for m in page1["messages"]}
        uids2 = {m["uid"] for m in page2["messages"]}
        assert uids1.isdisjoint(uids2)


class TestSearchMessages:
    async def test_search_excludes_all_mail_by_default(self, imap: ImapConnectionManager) -> None:
        # A broad query: results should never be tagged with the All Mail virtual
        # view when scope is the default (§3.2).
        result = await search_messages_impl(imap, query="the", limit=20)
        folders = {m["folder"] for m in result["messages"]}
        assert "All Mail" not in folders
        assert "All Mail excluded" in result["scope"]


class TestGetMessage:
    async def test_get_first_inbox_message_has_untrusted_marker(
        self, imap: ImapConnectionManager, seed_folder: str
    ) -> None:
        listing = await list_messages_impl(imap, folder=seed_folder, limit=1)
        if not listing["messages"]:
            pytest.skip("Seed folder is empty; cannot fetch a message.")
        first = listing["messages"][0]
        detail = await get_message_impl(imap, uid=first["uid"], folder=seed_folder)
        assert detail["body"].startswith(UNTRUSTED_CONTENT_MARKER)
        assert detail["uid"] == first["uid"]
        # JSON-serializable end to end (mirrors the tool's _dump wrapper).
        json.dumps(detail)
