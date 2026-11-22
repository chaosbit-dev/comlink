"""Send/draft from any configured split-mode address, one global gate (comlink#14)."""

from __future__ import annotations

import json
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import comlink.bridge.smtp as smtp_module
from comlink.accounts import AccountPool
from comlink.config import ComlinkSettings, password_filename
from comlink.errors import ComlinkError, SendBlocked
from comlink.guardrails import RateLimiter
from comlink.server import save_draft_impl, send_message_impl

from ..conftest import make_settings

HELLO = "hello@chaosbit.dev"
SECURITY = "security@chaosbit.dev"
BRANDON = "brandon@chaosbit.dev"
ACCOUNTS = f"{BRANDON},{HELLO},{SECURITY}"


class FakeManager:
    def __init__(self, name: str) -> None:
        self.name = name
        self.appended: list[bytes] = []

    async def append_draft(self, raw_bytes: bytes, message_id: str) -> int:
        self.appended.append(raw_bytes)
        return 7


def make_pool(settings: ComlinkSettings) -> tuple[AccountPool, dict[str, FakeManager]]:
    fakes = {a: FakeManager(a) for a in settings.account_addresses()}
    return AccountPool(settings, managers=fakes), fakes  # type: ignore[arg-type]


def multi(tmp_path: Path, **overrides: object) -> ComlinkSettings:
    for addr in ACCOUNTS.split(","):
        (tmp_path / password_filename(addr)).write_text(f"pw-for-{addr}\n")
    values: dict[str, object] = {
        "username": "",
        "password": None,
        "accounts": ACCOUNTS,
        "password_dir": tmp_path,
        "audit_log": tmp_path / "audit.jsonl",
        "send_allowlist": "*@chaosbit.dev",
    }
    values.update(overrides)
    return make_settings(**values)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def fake_send(
        settings: ComlinkSettings,
        password: str,
        message: EmailMessage,
        *,
        envelope_recipients: list[str],
        username: str | None = None,
    ) -> str:
        calls.append({"password": password, "username": username, "message": message})
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return calls


async def send(
    settings: ComlinkSettings, pool: AccountPool, limiter: RateLimiter, **kw: Any
) -> dict[str, Any]:
    kw.setdefault("to", ["alice@chaosbit.dev"])
    return await send_message_impl(
        settings,
        pool.primary,
        limiter,
        pool=pool,
        subject="s",
        body_text="b",
        confirm=True,
        **kw,
    )


class TestFromRefusal:
    async def test_missing_refused_with_several(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        with pytest.raises(ComlinkError, match="from_address is required"):
            await send(settings, pool, RateLimiter())
        assert sent == []

    async def test_unknown_refused(self, tmp_path: Path, sent: list[dict[str, Any]]) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        with pytest.raises(ComlinkError, match="Unknown address"):
            await send(settings, pool, RateLimiter(), from_address="ceo@chaosbit.dev")
        assert sent == []

    async def test_reply_without_from_refused(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path)
        pool, fakes = make_pool(settings)
        with pytest.raises(ComlinkError, match="from_address is required"):
            await send(settings, pool, RateLimiter(), in_reply_to_uid=1, in_reply_to_folder="INBOX")
        assert all(not f.appended for f in fakes.values())
        assert sent == []

    async def test_optional_with_one_address(self, sent: list[dict[str, Any]]) -> None:
        settings = make_settings(username=HELLO, send_allowlist="*@chaosbit.dev")
        pool, _ = make_pool(settings)
        await send(settings, pool, RateLimiter())
        assert sent[0]["message"]["From"] == HELLO
        assert sent[0]["username"] == HELLO

    async def test_draft_missing_from_refused(self, tmp_path: Path) -> None:
        settings = multi(tmp_path)
        pool, fakes = make_pool(settings)
        with pytest.raises(ComlinkError, match="from_address is required"):
            await save_draft_impl(settings, pool.primary, pool=pool, to=["a@chaosbit.dev"])
        assert all(not f.appended for f in fakes.values())


class TestPerAddressLogin:
    async def test_smtp_authenticates_as_from_address(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        await send(settings, pool, RateLimiter(), from_address=" Hello@Chaosbit.dev ")
        assert sent[0]["message"]["From"] == HELLO
        assert sent[0]["username"] == HELLO
        assert sent[0]["password"] == f"pw-for-{HELLO}"

    async def test_login_called_with_address_credential(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        logins: list[tuple[str, str]] = []

        class FakeSMTP:
            async def connect(self) -> None: ...
            async def starttls(self, **_: Any) -> None: ...
            async def login(self, user: str, password: str) -> None:
                logins.append((user, password))

            async def send_message(self, *_: Any, **__: Any) -> None: ...
            async def quit(self) -> None: ...

        monkeypatch.setattr(smtp_module, "_build_client", lambda *_a, **_k: FakeSMTP())
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        await send(settings, pool, RateLimiter(), from_address=SECURITY)
        assert logins == [(SECURITY, f"pw-for-{SECURITY}")]


class TestDrafts:
    async def test_draft_saved_in_from_addresss_mailbox(self, tmp_path: Path) -> None:
        settings = multi(tmp_path)
        pool, fakes = make_pool(settings)
        await save_draft_impl(
            settings, pool.primary, pool=pool, from_address=HELLO, to=["a@chaosbit.dev"]
        )
        assert len(fakes[HELLO].appended) == 1
        assert b"From: hello@chaosbit.dev" in fakes[HELLO].appended[0]
        assert not fakes[BRANDON].appended and not fakes[SECURITY].appended


class TestGlobalGate:
    async def test_cap_counts_across_addresses(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path, send_max_per_hour=2)
        pool, _ = make_pool(settings)
        limiter = RateLimiter()
        await send(settings, pool, limiter, from_address=HELLO)
        await send(settings, pool, limiter, from_address=SECURITY)
        with pytest.raises(SendBlocked, match="rate limit"):
            await send(settings, pool, limiter, from_address=BRANDON)
        assert len(sent) == 2

    @pytest.mark.parametrize("sender", [HELLO, SECURITY])
    async def test_allowlist_applies_to_every_from_address(
        self, tmp_path: Path, sent: list[dict[str, Any]], sender: str
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        for field in ("to", "cc", "bcc"):
            with pytest.raises(SendBlocked, match="not in COMLINK_SEND_ALLOWLIST"):
                await send(
                    settings,
                    pool,
                    RateLimiter(),
                    from_address=sender,
                    **{field: ["evil@attacker.com"]},
                )
        assert sent == []

    @pytest.mark.parametrize("confirm", [False, None, 1, "true"])
    async def test_confirm_required_for_non_default_from(
        self, tmp_path: Path, sent: list[dict[str, Any]], confirm: Any
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        with pytest.raises(SendBlocked, match="confirm"):
            await send_message_impl(
                settings,
                pool.primary,
                RateLimiter(),
                pool=pool,
                from_address=HELLO,
                to=["alice@chaosbit.dev"],
                confirm=confirm,
            )
        assert sent == []

    async def test_bcc_never_in_header_for_non_default_from(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        await send(settings, pool, RateLimiter(), from_address=HELLO, bcc=["secret@chaosbit.dev"])
        raw = sent[0]["message"].as_bytes()
        assert b"secret@chaosbit.dev" not in raw
        assert sent[0]["message"]["Bcc"] is None


class TestNoSend:
    async def test_read_only_address_refused(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path, no_send_addresses=SECURITY)
        pool, _ = make_pool(settings)
        limiter = RateLimiter()
        with pytest.raises(SendBlocked, match="read-only"):
            await send(settings, pool, limiter, from_address=SECURITY)
        assert sent == []
        # No budget burnt, other addresses still send.
        assert limiter.remaining_budget(0.0, settings.send_max_per_hour) == 5
        await send(settings, pool, limiter, from_address=HELLO)
        assert len(sent) == 1

    def test_must_be_a_configured_address(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="NO_SEND_ADDRESSES"):
            multi(tmp_path, no_send_addresses="other@chaosbit.dev")

    def test_case_insensitive(self, tmp_path: Path) -> None:
        settings = multi(tmp_path, no_send_addresses=" Security@Chaosbit.dev ")
        assert not settings.send_allowed_from(SECURITY)
        assert settings.send_allowed_from(HELLO)


class TestAudit:
    async def test_audit_records_from_address_and_no_credential(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path)
        pool, _ = make_pool(settings)
        await send(settings, pool, RateLimiter(), from_address=HELLO)
        raw = settings.audit_log.read_text()
        entry = json.loads(raw.splitlines()[0])
        assert entry["from_address"] == HELLO
        assert entry["action"] == "send"
        assert "pw-for-" not in raw

    async def test_refused_send_writes_no_audit(
        self, tmp_path: Path, sent: list[dict[str, Any]]
    ) -> None:
        settings = multi(tmp_path, no_send_addresses=HELLO)
        pool, _ = make_pool(settings)
        with pytest.raises(SendBlocked):
            await send(settings, pool, RateLimiter(), from_address=HELLO)
        assert not settings.audit_log.exists()
