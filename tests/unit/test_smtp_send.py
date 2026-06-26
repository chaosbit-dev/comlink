"""bridge.smtp.send_message (Epic 3, Task 4): STARTTLS sequence, error mapping,
and the no-IMAP / no-Sent-APPEND invariant (§3.6).

aiosmtplib is mocked — no real network or Bridge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import aiosmtplib
import pytest

from comlink.bridge.parsing import build_message
from comlink.bridge.smtp import send_message
from comlink.errors import AuthFailed, BridgeUnavailable, ComlinkError

from ..conftest import make_settings


@dataclass
class SMTPConfig:
    """Shared fault-injection knobs and instance recorder for the fake client."""

    raise_on: str | None = None
    exc: Exception = field(default_factory=lambda: aiosmtplib.SMTPException("boom"))
    instances: list[FakeSMTP] = field(default_factory=list)


class FakeSMTP:
    """Records the STARTTLS/login/send sequence; configurable failure point."""

    def __init__(self, config: SMTPConfig, **kwargs: Any) -> None:
        self.config = config
        self.kwargs = kwargs
        self.calls: list[str] = []
        self.sent: list[tuple[str, list[str]]] = []
        config.instances.append(self)

    async def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.config.raise_on == name:
            raise self.config.exc

    async def connect(self) -> None:
        await self._step("connect")

    async def starttls(self, tls_context: Any = None) -> None:
        await self._step("starttls")

    async def login(self, username: str, password: str) -> None:
        await self._step("login")

    async def send_message(self, message: Any, *, sender: str, recipients: list[str]) -> None:
        await self._step("send_message")
        self.sent.append((sender, recipients))

    async def quit(self) -> None:
        self.calls.append("quit")


@pytest.fixture
def smtp_config(monkeypatch: pytest.MonkeyPatch) -> SMTPConfig:
    config = SMTPConfig()

    def factory(**kwargs: Any) -> FakeSMTP:
        return FakeSMTP(config, **kwargs)

    monkeypatch.setattr(aiosmtplib, "SMTP", factory)
    return config


def _msg() -> Any:
    return build_message(
        from_addr="brandon@chaosbit.dev",
        to=["kendra@chaosbit.dev"],
        subject="Hi",
        body_text="body",
    )


class TestSendMessage:
    async def test_starttls_sequence_then_send(self, smtp_config: SMTPConfig) -> None:
        settings = make_settings(username="brandon@chaosbit.dev")
        message = _msg()
        returned = await send_message(
            settings, "pw", message, envelope_recipients=["kendra@chaosbit.dev"]
        )
        assert returned == str(message["Message-ID"])
        client = smtp_config.instances[0]
        assert client.calls[:4] == ["connect", "starttls", "login", "send_message"]
        # use_tls/start_tls disabled at construction (STARTTLS upgrade in-band).
        assert client.kwargs["start_tls"] is False
        assert client.kwargs["use_tls"] is False
        assert client.sent == [("brandon@chaosbit.dev", ["kendra@chaosbit.dev"])]

    async def test_auth_error_maps_to_auth_failed(self, smtp_config: SMTPConfig) -> None:
        smtp_config.raise_on = "login"
        smtp_config.exc = aiosmtplib.SMTPAuthenticationError(535, "bad")
        settings = make_settings(username="brandon@chaosbit.dev")
        with pytest.raises(AuthFailed, match="SMTP login rejected"):
            await send_message(settings, "pw", _msg(), envelope_recipients=["k@chaosbit.dev"])

    async def test_connect_error_maps_to_bridge_unavailable(self, smtp_config: SMTPConfig) -> None:
        smtp_config.raise_on = "connect"
        smtp_config.exc = aiosmtplib.SMTPConnectError("nope")
        settings = make_settings(username="brandon@chaosbit.dev")
        with pytest.raises(BridgeUnavailable, match="SMTP"):
            await send_message(settings, "pw", _msg(), envelope_recipients=["k@chaosbit.dev"])

    async def test_other_smtp_error_is_redacted(self, smtp_config: SMTPConfig) -> None:
        smtp_config.raise_on = "send_message"
        smtp_config.exc = aiosmtplib.SMTPException("rejected for super-secret-pw")
        settings = make_settings(username="brandon@chaosbit.dev")
        with pytest.raises(ComlinkError) as excinfo:
            await send_message(
                settings,
                "super-secret-pw",
                _msg(),
                envelope_recipients=["k@chaosbit.dev"],
            )
        assert "super-secret-pw" not in str(excinfo.value)
        assert "[REDACTED]" in str(excinfo.value)
