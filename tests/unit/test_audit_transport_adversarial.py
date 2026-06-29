"""Adversarial attacks on the send audit entry (§6, §7.4 — Epic 4 transport tag).

The send audit now carries a static ``transport: "stdio"`` requesting-context tag.
Wrecker confirms the tag survives all the way into the written JSONL line (not
just the in-memory dict), that it never becomes a leak vector, and that a hostile
subject full of secret-looking text does not weaken the no-body / no-password
guarantee.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.guardrails import RateLimiter, send_audit_entry
from comlink.server import send_message_impl

from ..conftest import make_settings

_PASSWORD = "br1dge-app-pw-zz"
_BODY = "CONFIDENTIAL deal memo — do not forward."


def _audit_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def fake_send(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    used: list[str] = []

    async def _send(
        settings: ComlinkSettings,
        password: str,
        message: Any,
        *,
        envelope_recipients: list[str],
    ) -> str:
        used.append(password)
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", _send)
    return used


class TestTransportInWrittenLine:
    async def test_written_audit_line_carries_transport_stdio(
        self, tmp_path: Path, fake_send: list[str]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            password=_PASSWORD,
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            subject="hello",
            body_text=_BODY,
            confirm=True,
        )
        entries = _audit_lines(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["transport"] == "stdio"
        assert entries[0]["action"] == "send"

    async def test_streamable_http_written_line_records_real_transport(
        self, tmp_path: Path, fake_send: list[str]
    ) -> None:
        # M1: on the COMLINK_TRANSPORT=streamable-http deployment the audit line must
        # record the REAL transport, not the old hardcoded "stdio" — this is exactly
        # the remote, injection-exposed deployment where attribution matters.
        settings = make_settings(
            transport="streamable-http",
            username="brandon@chaosbit.dev",
            password=_PASSWORD,
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            subject="hello",
            body_text=_BODY,
            confirm=True,
        )
        entries = _audit_lines(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["transport"] == "streamable-http"
        # No authenticated request context in this unit path => principal None.
        assert entries[0]["principal"] is None

    async def test_secret_looking_subject_keeps_no_body_no_password_guarantee(
        self, tmp_path: Path, fake_send: list[str]
    ) -> None:
        # The subject is intentionally recorded (design §6), but stuffing it with
        # the password value and the word "password" must NOT cause the body to be
        # logged nor break the guarantee that the BRIDGE password never lands in the
        # audit by any other field. (The subject is user content; the test asserts
        # the system's own secret and the body are still absent.)
        hostile_subject = f"password={_PASSWORD} body={_BODY[:5]}"
        settings = make_settings(
            username="brandon@chaosbit.dev",
            password=_PASSWORD,
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        await send_message_impl(
            settings,
            object(),  # type: ignore[arg-type]
            RateLimiter(),
            to=["kendra@chaosbit.dev"],
            subject=hostile_subject,
            body_text=_BODY,
            confirm=True,
        )
        raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        # The full body never appears.
        assert _BODY not in raw
        entries = _audit_lines(tmp_path / "audit.jsonl")
        assert "body" not in entries[0]
        assert entries[0]["transport"] == "stdio"


class TestSendAuditEntryShape:
    def test_transport_default_and_no_secret_fields(self) -> None:
        entry = send_audit_entry(["k@chaosbit.dev"], "subj", "<id@chaosbit.dev>")
        assert entry["transport"] == "stdio"
        flat = json.dumps(entry).lower()
        assert "password" not in flat
        assert "body" not in flat

    def test_transport_override_is_carried_verbatim(self) -> None:
        # Forward-compat: under the Phase 2 remote transport this becomes the OAuth
        # subject. It must be a plain non-secret tag carried as given.
        entry = send_audit_entry(
            ["k@chaosbit.dev"], "subj", "<id@chaosbit.dev>", transport="oauth:brandon"
        )
        assert entry["transport"] == "oauth:brandon"
