"""Bcc-leakage attacks (§6).

Bcc recipients must receive the message (present in the SMTP envelope) but the
serialized message MUST NOT carry a Bcc header on EITHER path (draft APPEND or
send). A hostile compose must not surface Bcc to To/Cc recipients.
"""

from __future__ import annotations

from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.guardrails import RateLimiter
from comlink.server import save_draft_impl, send_message_impl

from ..conftest import make_settings


class _FakeDraftManager:
    def __init__(self) -> None:
        self.appended: list[tuple[bytes, str]] = []

    async def append_draft(self, raw_bytes: bytes, message_id: str) -> int:
        self.appended.append((raw_bytes, message_id))
        return 7


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
        calls.append({"recipients": envelope_recipients, "raw": message.as_bytes()})
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return calls


_SECRET_BCC = "whistleblower@chaosbit.dev"


class TestBccLeakage:
    async def test_draft_bytes_have_no_bcc_header(self) -> None:
        settings = make_settings(username="brandon@chaosbit.dev")
        manager = _FakeDraftManager()
        await save_draft_impl(
            settings,
            manager,  # type: ignore[arg-type]
            to=["kendra@chaosbit.dev"],
            bcc=[_SECRET_BCC],
            subject="quiet",
            body_text="x",
        )
        raw = manager.appended[0][0]
        lowered = raw.lower()
        assert b"bcc:" not in lowered
        assert _SECRET_BCC.encode() not in raw

    async def test_send_message_bytes_have_no_bcc_header(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
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
            to=["kendra@chaosbit.dev"],
            bcc=[_SECRET_BCC],
            subject="quiet",
            body_text="x",
            confirm=True,
        )
        raw = captured_send[0]["raw"]
        # No Bcc header anywhere in the wire bytes...
        assert b"bcc:" not in raw.lower()
        assert _SECRET_BCC.encode() not in raw
        # ...but the Bcc recipient IS in the SMTP envelope (so they get the mail).
        assert _SECRET_BCC in captured_send[0]["recipients"]

    async def test_bcc_only_send_still_delivers_via_envelope(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        # A Bcc-only message has no To/Cc headers but must still RCPT the Bcc.
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            bcc=[_SECRET_BCC],
            subject="blind",
            body_text="x",
            confirm=True,
        )
        raw = captured_send[0]["raw"]
        assert b"bcc:" not in raw.lower()
        assert captured_send[0]["recipients"] == [_SECRET_BCC]

    async def test_bcc_header_injection_via_subject_does_not_smuggle(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        # Attempt CRLF header injection through the subject to forge a Bcc header.
        # stdlib EmailMessage must refuse/encode the newline rather than emit a
        # real second header line that leaks a hidden recipient.
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        injected = "Hello\r\nBcc: smuggled@evil.com"
        try:
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["kendra@chaosbit.dev"],
                subject=injected,
                body_text="x",
                confirm=True,
            )
        except ValueError:
            # stdlib raised on the embedded newline — injection refused outright.
            return
        # If it serialized, the smuggled address must NOT appear as a live header
        # recipient nor in the envelope.
        raw = captured_send[0]["raw"]
        assert b"smuggled@evil.com" not in raw
        assert "smuggled@evil.com" not in captured_send[0]["recipients"]
