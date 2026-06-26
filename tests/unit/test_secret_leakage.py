"""Secret / body leakage attacks (§7.4).

The Bridge app password and the message BODY must never surface in an audit
entry, an error string, or anything that leaves the server. We plant the
password inside an SMTP error and assert it is scrubbed; we assert the send
audit entry carries recipients/subject/message-id but never the body or any
secret.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosmtplib
import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.errors import ComlinkError, redact, redacted_message
from comlink.guardrails import RateLimiter, send_audit_entry
from comlink.server import _raw_secrets, send_message_impl

from ..conftest import make_settings

_PASSWORD = "sup3r-s3cret-bridge-pw"
_BODY = "MEETING NOTES: the merger closes Friday, do not forward."


def _audit_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestPasswordRedaction:
    def test_redact_scrubs_password_substring(self) -> None:
        text = f"auth failed for user with password {_PASSWORD} oops"
        assert _PASSWORD not in redact(text, [_PASSWORD])
        assert "[REDACTED]" in redact(text, [_PASSWORD])

    def test_redacted_message_scrubs_exception(self) -> None:
        exc = RuntimeError(f"login rejected: {_PASSWORD}")
        out = redacted_message(exc, [_PASSWORD])
        assert _PASSWORD not in out

    def test_redact_ignores_empty_or_none_secrets(self) -> None:
        # An empty/None secret must never turn into a replace("") catastrophe.
        text = "nothing secret here"
        assert redact(text, [None, ""]) == text

    async def test_smtp_error_carrying_password_is_redacted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The Bridge can echo the credential in an SMTP error; the send path must
        # scrub it before the ComlinkError leaves the server.
        class _LeakySMTP:
            def __init__(self, **kwargs: Any) -> None:
                pass

            async def connect(self) -> None: ...
            async def starttls(self, tls_context: Any = None) -> None: ...
            async def login(self, username: str, password: str) -> None: ...
            async def send_message(self, *a: Any, **k: Any) -> None:
                raise aiosmtplib.SMTPException(f"server said: bad creds {_PASSWORD}")

            async def quit(self) -> None: ...

        monkeypatch.setattr(aiosmtplib, "SMTP", lambda **k: _LeakySMTP(**k))
        settings = make_settings(username="brandon@chaosbit.dev")
        with pytest.raises(ComlinkError) as excinfo:
            await smtp_module.send_message(
                settings, _PASSWORD, _msg(), envelope_recipients=["k@chaosbit.dev"]
            )
        rendered = str(excinfo.value)
        assert _PASSWORD not in rendered
        assert "[REDACTED]" in rendered

    def test_raw_secrets_pulls_the_configured_password(self) -> None:
        settings = make_settings(username="x@y.com", password=_PASSWORD)
        assert _PASSWORD in [s for s in _raw_secrets(settings) if s]


class TestAuditNoBodyNoSecret:
    def test_send_audit_entry_excludes_body_and_password(self) -> None:
        entry = send_audit_entry(["kendra@chaosbit.dev"], "Subject line", "<id@chaosbit.dev>")
        flat = json.dumps(entry).lower()
        assert "body" not in flat
        assert "password" not in flat
        # The fields we DO want are present.
        assert entry["recipients"] == ["kendra@chaosbit.dev"]
        assert entry["subject"] == "Subject line"
        assert entry["message_id"] == "<id@chaosbit.dev>"

    async def test_full_send_audit_line_has_no_body_no_password(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[str] = []

        async def fake_send(
            settings: ComlinkSettings,
            password: str,
            message: Any,
            *,
            envelope_recipients: list[str],
        ) -> str:
            captured.append(password)
            return str(message["Message-ID"])

        monkeypatch.setattr(smtp_module, "send_message", fake_send)
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
            subject="Merger",
            body_text=_BODY,
            confirm=True,
        )
        raw_audit = (tmp_path / "audit.jsonl").read_text()
        assert _BODY not in raw_audit
        assert _PASSWORD not in raw_audit
        # The audit entry exists and is parseable JSONL.
        entries = _audit_lines(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["action"] == "send"
        assert "body" not in entries[0]
        # Sanity: the password was used (so the test path is real).
        assert captured == [_PASSWORD]


def _msg() -> Any:
    from comlink.bridge.parsing import build_message

    return build_message(
        from_addr="brandon@chaosbit.dev",
        to=["k@chaosbit.dev"],
        subject="s",
        body_text="b",
    )
