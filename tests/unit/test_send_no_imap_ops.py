"""The send path must issue ZERO IMAP operations (§3.6).

Sending via Bridge SMTP makes Proton save the Sent copy server-side; an APPEND
to Sent (or any IMAP write) would create a duplicate. A non-reply send must not
touch IMAP at all. The static no-EXPUNGE guard already covers the whole tree;
here we prove the send pipeline never calls into the IMAP manager.
"""

from __future__ import annotations

from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.guardrails import RateLimiter
from comlink.server import send_message_impl

from ..conftest import make_settings


class _ExplodingIMAP:
    """Any IMAP method call detonates — proves the send path never uses IMAP."""

    def __getattr__(self, name: str) -> Any:
        def _boom(*a: Any, **k: Any) -> Any:
            raise AssertionError(f"send path must not call IMAP.{name} (§3.6)")

        return _boom


@pytest.fixture
def captured_send(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake_send(
        settings: ComlinkSettings,
        password: str,
        message: Any,
        *,
        envelope_recipients: list[str],
    ) -> str:
        calls.append({"recipients": envelope_recipients})
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return calls


async def test_non_reply_send_issues_no_imap_ops(
    tmp_path: Any, captured_send: list[dict[str, Any]]
) -> None:
    settings = make_settings(
        username="brandon@chaosbit.dev",
        send_allowlist="*@chaosbit.dev",
        audit_log=tmp_path / "audit.jsonl",
    )
    # If the pipeline touches IMAP for a non-reply send, _ExplodingIMAP raises.
    await send_message_impl(
        settings,
        _ExplodingIMAP(),  # type: ignore[arg-type]
        RateLimiter(),
        to=["kendra@chaosbit.dev"],
        subject="no imap please",
        body_text="x",
        confirm=True,
    )
    assert len(captured_send) == 1


async def test_reply_send_only_reads_parent_never_appends(
    tmp_path: Any, captured_send: list[dict[str, Any]]
) -> None:
    # A reply must fetch the parent (one read) but still never APPEND anywhere.
    appended: list[Any] = []

    class _ReadOnlyIMAP:
        async def fetch_raw_message(self, folder: str, uid: int) -> tuple[str, bytes, Any]:
            return (
                folder,
                b"From: x@example.com\r\nSubject: Hi\r\nMessage-ID: <p@example.com>\r\n\r\nb\r\n",
                (),
            )

        async def append_draft(self, *a: Any, **k: Any) -> int:
            appended.append((a, k))
            raise AssertionError("send path must never APPEND (§3.6)")

    settings = make_settings(
        username="brandon@chaosbit.dev",
        send_allowlist="*@chaosbit.dev",
        audit_log=tmp_path / "audit.jsonl",
    )
    await send_message_impl(
        settings,
        _ReadOnlyIMAP(),  # type: ignore[arg-type]
        RateLimiter(),
        to=["kendra@chaosbit.dev"],
        body_text="x",
        confirm=True,
        in_reply_to_uid=5,
        in_reply_to_folder="INBOX",
    )
    assert appended == []
    assert len(captured_send) == 1
