"""Confirm-bypass attacks on send_message_impl (§7).

Tech checks `confirm is not True`, so only the literal bool True may pass.
Wrecker proves every truthy-but-not-True value is rejected BEFORE any allowlist
check, rate-limit consumption, message build, SMTP send, or audit write. A
non-True confirm must be inert: no network, no budget burn, no audit line.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.errors import SendBlocked
from comlink.guardrails import RateLimiter
from comlink.server import send_message_impl

from ..conftest import make_settings


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


def _audit_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


class _Truthy:
    """A truthy non-True object (bool(obj) is True, obj is not True)."""

    def __bool__(self) -> bool:
        return True


# Every one of these is a non-True value that an over-eager caller, a JSON
# round-trip, or a hostile crafted argument might supply. Only literal True wins.
_NON_TRUE_CONFIRMS: list[object] = [
    False,
    0,
    1,  # truthy int — must NOT pass (`is not True` catches it)
    "",
    "true",  # the string, not the bool
    "True",
    "yes",
    None,
    [True],
    _Truthy(),
    1.0,
]


class TestConfirmBypass:
    @pytest.mark.parametrize("confirm", _NON_TRUE_CONFIRMS)
    async def test_non_true_confirm_is_blocked_before_any_work(
        self, confirm: object, tmp_path: Path, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            # Deliberately empty allowlist + max_per_hour=0: if confirm were
            # evaluated AFTER allowlist/rate, an empty allowlist would let it
            # through and a zero budget would raise a *rate* error instead of a
            # *confirm* error. Forcing confirm to fire first proves ordering.
            send_allowlist="",
            send_max_per_hour=0,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        with pytest.raises(SendBlocked, match="confirm"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                limiter,
                to=["kendra@chaosbit.dev"],
                body_text="b",
                confirm=confirm,  # type: ignore[arg-type]
            )
        # No SMTP send, no audit line, no budget consumed.
        assert captured_send == []
        assert _audit_lines(tmp_path / "audit.jsonl") == []
        assert limiter.remaining_budget(0.0, max_per_hour=5) == 5

    async def test_literal_true_is_the_only_pass(
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
            to=["kendra@chaosbit.dev"],
            body_text="b",
            confirm=True,
        )
        assert len(captured_send) == 1
