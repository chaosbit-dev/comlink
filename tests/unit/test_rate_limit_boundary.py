"""Rate-limit boundary attacks (§7.1, layer 3).

Beyond Tech's Nth/N+1 happy case: exact 3600s eviction boundary (just-under
must stay blocked, just-over must free a slot), a FAILED SMTP send must not burn
budget (commit-on-success), one send to many recipients counts as ONE against
the limit (not per-recipient), and remaining_budget never goes negative.
Clock is injected — no sleeps.
"""

from __future__ import annotations

import asyncio
from typing import Any

import aiosmtplib
import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.errors import ComlinkError, SendBlocked
from comlink.guardrails import RateLimiter
from comlink.server import send_message_impl

from ..conftest import make_settings


class TestRateLimiterBoundary:
    def test_eviction_exactly_at_3600_is_inclusive(self) -> None:
        # _evict cutoff = now - 3600; pops timestamps <= cutoff. A timestamp at
        # exactly now-3600 IS evicted (<=). Prove the boundary is inclusive.
        limiter = RateLimiter()
        limiter.commit(0.0)
        # At t=3600.0 exactly, the t=0 entry hits cutoff (0 <= 0) -> evicted.
        assert limiter.remaining_budget(3600.0, max_per_hour=1) == 1
        limiter.check(3600.0, max_per_hour=1)  # no raise

    def test_just_under_window_still_blocks(self) -> None:
        limiter = RateLimiter()
        limiter.commit(0.0)
        # At t=3599.999 the entry is NOT yet evicted (0 > -0.001 cutoff).
        assert limiter.remaining_budget(3599.999, max_per_hour=1) == 0
        with pytest.raises(SendBlocked, match="rate limit"):
            limiter.check(3599.999, max_per_hour=1)

    def test_remaining_budget_never_negative_even_if_overfilled(self) -> None:
        limiter = RateLimiter()
        for _ in range(10):
            limiter.commit(100.0)
        # 10 commits against a budget of 3 must clamp at 0, not -7.
        assert limiter.remaining_budget(100.0, max_per_hour=3) == 0

    @pytest.mark.xfail(
        reason=(
            "DEFECT (LOW/MEDIUM): RateLimiter.check(now, max_per_hour=0) raises "
            "IndexError, not SendBlocked. Empty deque + `len(...) >= 0` True -> "
            "indexes self._timestamps[0] on an empty deque. COMLINK_SEND_MAX_PER_HOUR=0 "
            "('disable sends') crashes instead of returning the named guardrail error. "
            "Tech to guard max_per_hour<=0 in guardrails.RateLimiter.check."
        ),
        raises=IndexError,
        strict=True,
    )
    def test_zero_budget_blocks_immediately(self) -> None:
        # Expected per §7/§8: a guardrail block returns a named SendBlocked, never
        # an unhandled IndexError. This currently raises IndexError -> xfail.
        limiter = RateLimiter()
        with pytest.raises(SendBlocked):
            limiter.check(0.0, max_per_hour=0)


@pytest.fixture
def send_outcome(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Controllable SMTP stub: set state['fail']=True to make the send raise."""
    state: dict[str, Any] = {"fail": False, "calls": 0}

    async def fake_send(
        settings: ComlinkSettings,
        password: str,
        message: Any,
        *,
        envelope_recipients: list[str],
    ) -> str:
        state["calls"] += 1
        if state["fail"]:
            raise ComlinkError("SMTP send failed: [REDACTED]")
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return state


async def _send(settings: ComlinkSettings, limiter: RateLimiter, **kw: Any) -> Any:
    return await send_message_impl(
        settings,
        object(),  # type: ignore[arg-type]
        limiter,
        body_text="b",
        confirm=True,
        **kw,
    )


class TestRateLimitWiring:
    async def test_failed_send_does_not_consume_budget(
        self, tmp_path: Any, send_outcome: dict[str, Any]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=1,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        # First attempt fails at the SMTP layer -> no commit, budget intact.
        send_outcome["fail"] = True
        with pytest.raises(ComlinkError):
            await _send(settings, limiter, to=["kendra@chaosbit.dev"])
        # The single slot must still be available for a real send.
        send_outcome["fail"] = False
        result = await _send(settings, limiter, to=["kendra@chaosbit.dev"])
        assert result["message_id"].endswith("@chaosbit.dev>")
        assert send_outcome["calls"] == 2

    async def test_one_send_many_recipients_counts_as_one(
        self, tmp_path: Any, send_outcome: dict[str, Any]
    ) -> None:
        # 5 recipients in a single send must cost 1 budget unit, not 5.
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=1,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        await _send(
            settings,
            limiter,
            to=["a@chaosbit.dev", "b@chaosbit.dev", "c@chaosbit.dev"],
            cc=["d@chaosbit.dev"],
            bcc=["e@chaosbit.dev"],
        )
        # Budget of 1 fully consumed by the single multi-recipient send.
        assert limiter.remaining_budget(0.0, max_per_hour=1) == 0

    async def test_nth_ok_n_plus_one_blocked_through_impl(
        self, tmp_path: Any, send_outcome: dict[str, Any]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=3,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        for _ in range(3):
            await _send(settings, limiter, to=["kendra@chaosbit.dev"])
        with pytest.raises(SendBlocked, match="rate limit"):
            await _send(settings, limiter, to=["kendra@chaosbit.dev"])
        assert send_outcome["calls"] == 3  # the 4th never reached SMTP

    @pytest.mark.xfail(
        reason=(
            "DEFECT (LOW/MEDIUM): COMLINK_SEND_MAX_PER_HOUR=0 is an accepted config "
            "(no >=1 validator) and reaches RateLimiter.check, so the first send "
            "crashes with IndexError instead of a SendBlocked rate-limit error. Tech "
            "to either validate max_per_hour>=1 in config or guard it in the limiter."
        ),
        raises=IndexError,
        strict=True,
    )
    async def test_zero_max_per_hour_config_crashes_send(
        self, tmp_path: Any, send_outcome: dict[str, Any]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=0,
            audit_log=tmp_path / "audit.jsonl",
        )
        # Expected: a named SendBlocked. Actual: IndexError -> xfail.
        with pytest.raises(SendBlocked):
            await _send(settings, RateLimiter(), to=["kendra@chaosbit.dev"])

    async def test_real_aiosmtplib_failure_preserves_budget(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        # End-to-end through bridge.smtp with aiosmtplib mocked to raise on send:
        # the rate-limit commit must be skipped, leaving budget for a retry.
        class _FailingSMTP:
            def __init__(self, **kwargs: Any) -> None:
                pass

            async def connect(self) -> None: ...
            async def starttls(self, tls_context: Any = None) -> None: ...
            async def login(self, username: str, password: str) -> None: ...
            async def send_message(self, *a: Any, **k: Any) -> None:
                raise aiosmtplib.SMTPException("transient")

            async def quit(self) -> None: ...

        monkeypatch.setattr(aiosmtplib, "SMTP", lambda **k: _FailingSMTP(**k))
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=1,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()
        with pytest.raises(ComlinkError):
            await _send(settings, limiter, to=["kendra@chaosbit.dev"])
        # Budget intact after the real-path failure.
        assert limiter.remaining_budget(0.0, max_per_hour=1) == 1


class TestRateLimitConcurrency:
    """The race the remote (streamable-http) transport makes routine: two sends
    in flight at once must not both clear a budget of 1. Regression guard for the
    reserve-then-release fix — under the old check/commit split, both coroutines
    observed free budget across the await window and both committed."""

    async def test_concurrent_sends_cannot_exceed_budget_of_one(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        calls = {"n": 0}

        async def slow_send(
            settings: ComlinkSettings,
            password: str,
            message: Any,
            *,
            envelope_recipients: list[str],
        ) -> str:
            calls["n"] += 1
            # Yield control so a second in-flight send interleaves here — exactly
            # the window the old check/commit split left open between them.
            await asyncio.sleep(0)
            return str(message["Message-ID"])

        monkeypatch.setattr(smtp_module, "send_message", slow_send)
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            send_max_per_hour=1,
            audit_log=tmp_path / "audit.jsonl",
        )
        limiter = RateLimiter()

        results = await asyncio.gather(
            _send(settings, limiter, to=["kendra@chaosbit.dev"]),
            _send(settings, limiter, to=["kendra@chaosbit.dev"]),
            return_exceptions=True,
        )

        ok = [r for r in results if not isinstance(r, BaseException)]
        blocked = [r for r in results if isinstance(r, SendBlocked)]
        # Exactly one cleared the budget; the other was rate-limited atomically
        # at reserve time, before it could reach SMTP.
        assert len(ok) == 1
        assert len(blocked) == 1
        assert calls["n"] == 1
        assert limiter.remaining_budget(0.0, max_per_hour=1) == 0
