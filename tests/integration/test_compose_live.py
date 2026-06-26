"""Live compose-path integration tests against a running Proton Mail Bridge (§9).

Marked ``integration`` and excluded from the default ``pytest`` run.

- The draft round-trip (append → fetch → delete) is gated behind
  ``COMLINK_TEST_WRITE=1`` like the organize suite; it is self-cleaning.
- The send test is gated behind an ADDITIONAL ``COMLINK_TEST_SEND=1`` and only
  ever sends to the configured user's OWN address (§9: no send tests against
  real third parties)::

      COMLINK_TEST_WRITE=1 COMLINK_TEST_SEND=1 COMLINK_ALLOW_SEND=true \
        COMLINK_SEND_ALLOWLIST="<your-own-address>" uv run pytest -m integration -k compose
"""

from __future__ import annotations

import os
import uuid

import pytest

from comlink.bridge.imap import ImapConnectionManager
from comlink.config import ComlinkSettings
from comlink.guardrails import RateLimiter
from comlink.server import (
    delete_messages_impl,
    list_messages_impl,
    save_draft_impl,
    send_message_impl,
)

pytestmark = pytest.mark.integration

_WRITE_ENABLED = os.environ.get("COMLINK_TEST_WRITE") == "1"
_SEND_ENABLED = os.environ.get("COMLINK_TEST_SEND") == "1"

_write_guard = pytest.mark.skipif(
    not _WRITE_ENABLED,
    reason="Write mutations gated behind COMLINK_TEST_WRITE=1 to protect real mailboxes.",
)
_send_guard = pytest.mark.skipif(
    not _SEND_ENABLED,
    reason="Live send gated behind COMLINK_TEST_SEND=1 (sends only to the user's own address).",
)


@_write_guard
class TestDraftRoundTrip:
    async def test_append_fetch_delete(
        self, settings: ComlinkSettings, imap: ImapConnectionManager
    ) -> None:
        marker = uuid.uuid4().hex
        subject = f"comlink-draft-{marker}"
        created = await save_draft_impl(
            settings,
            imap,
            to=[settings.username],
            subject=subject,
            body_text=f"Test draft {marker}",
        )
        assert created["folder"] == "Drafts"
        uid = int(created["uid"])
        try:
            listing = await list_messages_impl(imap, folder="Drafts", limit=50)
            subjects = {m["subject"] for m in listing["messages"]}
            assert subject in subjects, "New draft should be visible in Drafts."
        finally:
            # Clean up: move the draft to Trash (no EXPUNGE).
            await delete_messages_impl(settings, imap, uids=[uid], folder="Drafts")


@_write_guard
@_send_guard
class TestSendToSelf:
    async def test_send_to_own_address(
        self, settings: ComlinkSettings, imap: ImapConnectionManager
    ) -> None:
        if not settings.allow_send:
            pytest.skip("COMLINK_ALLOW_SEND must be true for the live send test.")
        own = settings.username
        marker = uuid.uuid4().hex
        result = await send_message_impl(
            settings,
            imap,
            RateLimiter(),
            to=[own],
            subject=f"comlink-send-{marker}",
            body_text=f"Self send {marker}",
            confirm=True,
        )
        assert result["recipients"] == [own]
        assert result["message_id"]
