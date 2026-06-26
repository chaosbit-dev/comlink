"""Server-level compose impls + gated registration (Epic 3, §6, §7).

Covers save_draft_impl, send_message_impl (SMTP mocked), the confirm guard,
allowlist/rate-limit wiring, audit-on-send, no Sent APPEND, and the
gate-on/gate-off registration of proton_send_message.
"""

from __future__ import annotations

import json
import logging
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.bridge.parsing import build_message
from comlink.config import ComlinkSettings
from comlink.errors import ComlinkError, SendBlocked
from comlink.guardrails import RateLimiter
from comlink.server import (
    create_server,
    save_draft_impl,
    send_message_impl,
)

from ..conftest import make_settings


class FakeComposeManager:
    """Impl-layer stand-in for ImapConnectionManager (draft + reply fetch)."""

    def __init__(self, parent_raw: bytes | None = None) -> None:
        self.appended: list[tuple[bytes, str]] = []
        self.fetch_calls: list[tuple[str, int]] = []
        self._parent_raw = parent_raw
        self._next_uid = 42

    async def append_draft(self, raw_bytes: bytes, message_id: str) -> int:
        self.appended.append((raw_bytes, message_id))
        return self._next_uid

    async def fetch_raw_message(self, folder: str, uid: int) -> tuple[str, bytes, Any]:
        self.fetch_calls.append((folder, uid))
        assert self._parent_raw is not None
        return folder, self._parent_raw, ()


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


# ---------------------------------------------------------------------------
# proton_save_draft
# ---------------------------------------------------------------------------


class TestSaveDraft:
    async def test_happy_path_appends_and_returns_uid(self) -> None:
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = FakeComposeManager()
        payload = await save_draft_impl(
            settings,
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            subject="Dinner",
            body_text="What's the plan?",
        )
        assert payload["uid"] == 42
        assert payload["folder"] == "Drafts"
        assert payload["subject"] == "Dinner"
        assert payload["message_id"].endswith("@chaosbit.dev>")
        assert len(manager.appended) == 1
        raw, msg_id = manager.appended[0]
        assert b"Bcc" not in raw
        assert msg_id == payload["message_id"]

    async def test_reply_derives_headers(self) -> None:
        parent = (
            b"From: someone@example.com\r\n"
            b"Subject: Pickup\r\n"
            b"Message-ID: <parent@example.com>\r\n"
            b"References: <root@example.com>\r\n\r\nbody\r\n"
        )
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = FakeComposeManager(parent_raw=parent)
        payload = await save_draft_impl(
            settings,
            manager,  # type: ignore[arg-type]
            to=["someone@example.com"],
            body_text="Sounds good",
            in_reply_to_uid=7,
            in_reply_to_folder="INBOX",
        )
        assert manager.fetch_calls == [("INBOX", 7)]
        assert payload["subject"] == "Re: Pickup"
        raw = manager.appended[0][0]
        assert b"In-Reply-To: <parent@example.com>" in raw
        assert b"<root@example.com> <parent@example.com>" in raw

    async def test_reply_params_both_or_neither(self) -> None:
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = FakeComposeManager()
        with pytest.raises(ComlinkError, match="both or"):
            await save_draft_impl(
                settings,
                manager,  # type: ignore[arg-type]
                to=["a@b.com"],
                body_text="x",
                in_reply_to_uid=5,
            )

    async def test_requires_a_recipient(self) -> None:
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = FakeComposeManager()
        with pytest.raises(ComlinkError, match="recipient"):
            await save_draft_impl(settings, manager, subject="x", body_text="y")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# proton_send_message
# ---------------------------------------------------------------------------


@pytest.fixture
def captured_send(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Stub bridge.smtp.send_message; record args, never touch the network."""
    calls: list[dict[str, Any]] = []

    async def fake_send(
        settings: ComlinkSettings,
        password: str,
        message: EmailMessage,
        *,
        envelope_recipients: list[str],
    ) -> str:
        calls.append(
            {
                "message": message,
                "envelope_recipients": envelope_recipients,
                "password": password,
            }
        )
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return calls


class TestSendMessage:
    async def test_happy_path(self, tmp_path: Path, captured_send: list[dict[str, Any]]) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        payload = await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]  # imap unused (no reply)
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            subject="Hi",
            body_text="body",
            confirm=True,
        )
        assert payload["recipients"] == ["kendra@chaosbit.dev"]
        assert payload["message_id"].endswith("@chaosbit.dev>")
        assert len(captured_send) == 1
        assert captured_send[0]["envelope_recipients"] == ["kendra@chaosbit.dev"]

    async def test_confirm_omitted_or_false_blocks(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked, match="confirm"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["kendra@chaosbit.dev"],
                body_text="b",
                confirm=False,
            )
        assert captured_send == []

    async def test_envelope_includes_bcc_and_dedupes(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            to=["a@chaosbit.dev"],
            cc=["a@chaosbit.dev"],  # duplicate of to
            bcc=["b@chaosbit.dev"],
            subject="x",
            body_text="y",
            confirm=True,
        )
        assert captured_send[0]["envelope_recipients"] == [
            "a@chaosbit.dev",
            "b@chaosbit.dev",
        ]
        # Bcc never serialized into the message itself.
        assert b"Bcc" not in captured_send[0]["message"].as_bytes()

    async def test_allowlist_blocks_before_send(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked, match=r"stranger@example\.com"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["stranger@example.com"],
                body_text="b",
                confirm=True,
            )
        assert captured_send == []
        assert _read_audit(tmp_path / "audit.jsonl") == []

    async def test_writes_exactly_one_send_audit_line_and_no_sent_append(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        # A manager that records any APPEND so we can prove Sent is never touched.
        manager = FakeComposeManager()
        await send_message_impl(
            settings,
            manager,  # type: ignore[arg-type]
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            subject="Hi",
            body_text="body",
            confirm=True,
        )
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["action"] == "send"
        assert entries[0]["recipients"] == ["kendra@chaosbit.dev"]
        # Send path must never APPEND (to Sent or anywhere) — §3.6.
        assert manager.appended == []

    async def test_rate_limit_blocks_n_plus_one(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=1,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            limiter,
            to=["kendra@chaosbit.dev"],
            body_text="b",
            confirm=True,
        )
        with pytest.raises(SendBlocked, match="rate limit"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                limiter,
                to=["kendra@chaosbit.dev"],
                body_text="b",
                confirm=True,
            )
        # Exactly one send went through.
        assert len(captured_send) == 1
        assert len(_read_audit(tmp_path / "audit.jsonl")) == 1


# ---------------------------------------------------------------------------
# Conditional registration (§7.1) + startup warning
# ---------------------------------------------------------------------------


async def _tool_names(settings: ComlinkSettings) -> set[str]:
    server = create_server(settings)
    return {t.name for t in await server.list_tools()}


class TestGateRegistration:
    async def test_send_absent_when_gate_off(self) -> None:
        names = await _tool_names(make_settings(allow_send=False))
        assert "proton_send_message" not in names
        # Draft is always present regardless of the gate.
        assert "proton_save_draft" in names

    async def test_send_present_when_gate_on(self) -> None:
        names = await _tool_names(make_settings(allow_send=True, send_allowlist="*@chaosbit.dev"))
        assert "proton_send_message" in names

    def test_startup_warning_on_empty_allowlist(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="comlink.server"):
            create_server(make_settings(allow_send=True, send_allowlist=""))
        assert any("any recipient" in rec.message.lower() for rec in caplog.records)

    def test_no_warning_when_allowlist_present(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="comlink.server"):
            create_server(make_settings(allow_send=True, send_allowlist="*@chaosbit.dev"))
        assert not any("any recipient" in rec.message.lower() for rec in caplog.records)


class TestSendResultShape:
    async def test_send_result_fields(
        self, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        payload = await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            cc=["mom@chaosbit.dev"],
            subject="x",
            body_text="y",
            confirm=True,
        )
        assert set(payload) == {"message_id", "recipients"}
        assert payload["recipients"] == ["kendra@chaosbit.dev", "mom@chaosbit.dev"]


def test_build_message_used_by_compose() -> None:
    # Sanity that the builder the impls call is importable and pure.
    msg = build_message(from_addr="a@b.com", to=["c@d.com"], subject="s", body_text="b")
    assert msg["Message-ID"] is not None
