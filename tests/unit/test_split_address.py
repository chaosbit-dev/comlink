"""Split address mode: config, credentials, connections, fan-out (comlink#13)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from comlink.accounts import AccountPool
from comlink.config import ComlinkSettings, password_filename
from comlink.errors import AuthFailed, ComlinkError, ConfigError
from comlink.guardrails import RateLimiter
from comlink.server import (
    MAX_SEARCH_RESULTS,
    _raw_secrets,
    health_check_impl,
    list_messages_fanout_impl,
    on_account,
    search_messages_fanout_impl,
)

from ..conftest import make_settings
from .conftest import FakeBridgeState

ADDRS = ["brandon@chaosbit.dev", "kamino@chaosbit.dev", "security@chaosbit.dev"]
ACCOUNTS = ",".join(ADDRS)


def multi_settings(**overrides: object) -> ComlinkSettings:
    values: dict[str, object] = {"username": "", "password": None, "accounts": ACCOUNTS}
    values.update(overrides)
    return make_settings(**values)


class TestAccountConfig:
    def test_list_parsed_normalized(self) -> None:
        s = multi_settings(accounts=" Brandon@Chaosbit.dev , kamino@chaosbit.dev ")
        assert s.account_addresses() == ["brandon@chaosbit.dev", "kamino@chaosbit.dev"]
        assert s.username == "brandon@chaosbit.dev"  # default sender = first entry

    def test_legacy_single_address(self) -> None:
        s = make_settings(username="brandon@chaosbit.dev")
        assert s.account_addresses() == ["brandon@chaosbit.dev"]

    def test_duplicates_refused(self) -> None:
        with pytest.raises(ValidationError, match="more than once"):
            multi_settings(accounts="a@x.dev,A@x.dev")

    @pytest.mark.parametrize("bad", ["nobody", "a b@x.dev", "a@x.dev;rm", "$(id)@x.dev", "a@"])
    def test_malformed_refused(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="not a valid address"):
            multi_settings(accounts=f"a@x.dev,{bad}")

    def test_username_must_be_listed(self) -> None:
        with pytest.raises(ValidationError, match="not in COMLINK_ACCOUNTS"):
            multi_settings(username="other@x.dev")

    def test_shared_password_refused_with_several(self) -> None:
        with pytest.raises(ValidationError, match="cannot serve several"):
            multi_settings(password="shared")

    def test_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMLINK_ACCOUNTS", ACCOUNTS)
        assert ComlinkSettings().account_addresses() == ADDRS


class TestCredentials:
    def test_filename_mapping(self) -> None:
        assert password_filename("Kamino@chaosbit.dev") == "kamino_at_chaosbit.dev"

    def test_dir_one_file_per_address(self, tmp_path: Path) -> None:
        for i, addr in enumerate(ADDRS):
            (tmp_path / password_filename(addr)).write_text(f"pw-{i}\n")
        s = multi_settings(password_dir=tmp_path)
        assert [s.resolve_password(a) for a in ADDRS] == ["pw-0", "pw-1", "pw-2"]

    def test_dir_missing_file_is_config_error_without_secret(self, tmp_path: Path) -> None:
        s = multi_settings(password_dir=tmp_path)
        with pytest.raises(ConfigError, match=r"kamino_at_chaosbit\.dev"):
            s.resolve_password("kamino@chaosbit.dev")

    def test_command_gets_address_in_env(self) -> None:
        s = multi_settings(password_command='printf "pw-for-%s" "$COMLINK_ACCOUNT"')
        assert s.resolve_password("kamino@chaosbit.dev") == "pw-for-kamino@chaosbit.dev"

    def test_address_never_substituted_into_shell(self, tmp_path: Path) -> None:
        # Even a hostile address (impossible via config validation) reaches the
        # command only as data in the environment, never as shell text.
        marker = tmp_path / "pwned"
        s = multi_settings(password_command='printf "%s" "$COMLINK_ACCOUNT"')
        hostile = f"x; touch {marker}"
        assert s.resolve_password(hostile) == hostile
        assert not marker.exists()

    def test_redaction_covers_every_address(self, tmp_path: Path) -> None:
        for i, addr in enumerate(ADDRS):
            (tmp_path / password_filename(addr)).write_text(f"secret-{i}")
        s = multi_settings(password_dir=tmp_path)
        for addr in ADDRS:
            s.resolve_password(addr)
        secrets = [x for x in _raw_secrets(s) if x]
        assert {"secret-0", "secret-1", "secret-2"} <= set(secrets)

    def test_redaction_covers_every_address_via_command(self) -> None:
        s = multi_settings(password_command='printf "cmd-%s" "$COMLINK_ACCOUNT"')
        for addr in ADDRS:
            s.resolve_password(addr)
        secrets = _raw_secrets(s)
        assert all(f"cmd-{a}" in secrets for a in ADDRS)

    def test_command_stderr_redacted(self) -> None:
        s = multi_settings(password_command='echo "oops $COMLINK_ACCOUNT" >&2; exit 1')
        with pytest.raises(ConfigError) as exc:
            s.resolve_password("kamino@chaosbit.dev")
        assert "status 1" in str(exc.value)


class TestPool:
    def test_missing_address_refused_when_several(self) -> None:
        pool = AccountPool(multi_settings())
        with pytest.raises(ComlinkError, match="address is required"):
            pool.resolve(None)

    def test_unknown_address_refused(self) -> None:
        pool = AccountPool(multi_settings())
        with pytest.raises(ComlinkError, match="Unknown address"):
            pool.resolve("evil@x.dev")

    def test_case_insensitive_match(self) -> None:
        assert AccountPool(multi_settings()).resolve("KAMINO@chaosbit.dev")[0] == ADDRS[1]

    def test_single_address_optional(self) -> None:
        pool = AccountPool(make_settings(username="brandon@chaosbit.dev"))
        assert not pool.multi
        assert pool.resolve(None)[0] == "brandon@chaosbit.dev"

    async def test_single_address_payload_untagged(self) -> None:
        pool = AccountPool(make_settings())

        async def op(_imap: Any) -> dict[str, Any]:
            return {"x": 1}

        assert await on_account(pool, None, op) == {"x": 1}

    async def test_multi_payload_tagged(self) -> None:
        pool = AccountPool(multi_settings())

        async def op(_imap: Any) -> dict[str, Any]:
            return {"x": 1}

        assert await on_account(pool, "kamino@chaosbit.dev", op) == {
            "x": 1,
            "address": "kamino@chaosbit.dev",
        }

    async def test_each_address_logs_in_as_itself(
        self, bridge: FakeBridgeState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        logins: list[tuple[str, str]] = []
        original = bridge.clients  # noqa: F841 - keep fixture patched
        for addr in ADDRS:
            (tmp_path / password_filename(addr)).write_text(f"pw-{addr}")
        pool = AccountPool(multi_settings(password_dir=tmp_path))
        import comlink.bridge.imap as imap_module

        base: Any = getattr(imap_module, "IMAPClient")  # noqa: B009

        def spy_factory(*args: Any, **kwargs: Any) -> Any:
            client = base(*args, **kwargs)
            real_login = client.login

            def login(user: str, pw: str) -> None:
                logins.append((user, pw))
                real_login(user, pw)

            client.login = login
            return client

        monkeypatch.setattr(imap_module, "IMAPClient", spy_factory)
        for _addr, manager in pool.items():
            await manager.verify_connectivity()
        assert logins == [(a, f"pw-{a}") for a in ADDRS]


class FakeManager:
    """Duck-typed manager: canned summaries per address, optional failure."""

    def __init__(self, uids_dates: list[tuple[int, datetime]], fail: Exception | None = None):
        self.uids_dates = uids_dates
        self.fail = fail

    def _data(self, when: datetime) -> dict[bytes, Any]:
        envelope = SimpleNamespace(
            date=when,
            subject=b"hi",
            from_=(SimpleNamespace(name=None, route=None, mailbox=b"a", host=b"b.c"),),
            to=(),
        )
        return {b"ENVELOPE": envelope, b"FLAGS": (), b"RFC822.SIZE": 1, b"BODYSTRUCTURE": None}

    async def fetch_summary_page(
        self, folder: str, criteria: list[Any], *, limit: int, offset: int
    ) -> Any:
        if self.fail:
            raise self.fail
        # Like the real client: newest by UID, whatever the Date header says.
        ordered = sorted(self.uids_dates, key=lambda p: p[0], reverse=True)
        return (
            folder,
            len(ordered),
            [(uid, self._data(d)) for uid, d in ordered[offset : offset + limit]],
        )

    async def search_mailboxes(self, criteria: list[Any], *, folder: str | None, cap: int) -> Any:
        if self.fail:
            raise self.fail
        ordered = sorted(self.uids_dates, key=lambda p: (p[1], p[0]), reverse=True)[:cap]
        return [("INBOX", uid, self._data(d)) for uid, d in ordered]

    async def verify_connectivity(self) -> int:
        if self.fail:
            raise self.fail
        return 4


def day(n: int) -> datetime:
    return datetime(2026, 1, 1, tzinfo=UTC).replace(day=n)


def fake_pool(managers: dict[str, FakeManager]) -> tuple[ComlinkSettings, AccountPool]:
    settings = multi_settings(accounts=",".join(managers))
    return settings, AccountPool(settings, managers=managers)  # type: ignore[arg-type]


class TestFanOut:
    async def test_search_tags_and_merges_newest_first(self) -> None:
        settings, pool = fake_pool(
            {
                ADDRS[0]: FakeManager([(1, day(3)), (2, day(1))]),
                ADDRS[1]: FakeManager([(1, day(2))]),
            }
        )
        out = await search_messages_fanout_impl(settings, pool, query="x")
        assert [(m["address"], m["date"][:10]) for m in out["messages"]] == [
            (ADDRS[0], "2026-01-03"),
            (ADDRS[1], "2026-01-02"),
            (ADDRS[0], "2026-01-01"),
        ]
        assert out["total_found"] == 3 and out["errors"] == []
        json.dumps(out)

    async def test_search_cap_and_pagination(self) -> None:
        many = [(i, day(1 + i % 28)) for i in range(1, 201)]
        settings, pool = fake_pool({ADDRS[0]: FakeManager(many), ADDRS[1]: FakeManager(many)})
        pages: list[Any] = []
        offset = 0
        while True:
            out = await search_messages_fanout_impl(
                settings, pool, query="x", limit=100, offset=offset
            )
            assert len(out["messages"]) <= 100
            pages.extend((m["address"], m["uid"]) for m in out["messages"])
            if not out["has_more"]:
                break
            offset += 100
        assert out["capped"] is True
        assert len(pages) == MAX_SEARCH_RESULTS
        assert len(set(pages)) == len(pages)  # offsets stable: no dup, no gap

    async def test_search_needs_a_criterion(self) -> None:
        settings, pool = fake_pool({ADDRS[0]: FakeManager([]), ADDRS[1]: FakeManager([])})
        with pytest.raises(ComlinkError, match="at least one criterion"):
            await search_messages_fanout_impl(settings, pool)

    async def test_list_fanout_pages_are_stable(self) -> None:
        a = [(i, day(1 + i % 20)) for i in range(1, 31)]
        b = [(i, day(1 + i % 20)) for i in range(1, 31)]
        settings, pool = fake_pool({ADDRS[0]: FakeManager(a), ADDRS[1]: FakeManager(b)})
        seen: list[tuple[str, int]] = []
        for offset in (0, 25, 50):
            out = await list_messages_fanout_impl(settings, pool, limit=25, offset=offset)
            assert out["total"] == 60
            seen.extend((m["address"], m["uid"]) for m in out["messages"])
        assert len(seen) == 60 and len(set(seen)) == 60
        assert out["has_more"] is False

    async def test_list_fanout_forged_date_not_hidden(self) -> None:
        def forged() -> list[tuple[int, datetime]]:
            return [(1, datetime(2099, 1, 1, tzinfo=UTC))] + [
                (i, day(1 + i % 20)) for i in range(2, 41)
            ]

        settings, pool = fake_pool(
            {ADDRS[0]: FakeManager(forged()), ADDRS[1]: FakeManager(forged())}
        )
        seen: list[tuple[str, int]] = []
        for offset in range(0, 80, 10):
            out = await list_messages_fanout_impl(settings, pool, limit=10, offset=offset)
            seen.extend((m["address"], m["uid"]) for m in out["messages"])
        assert len(seen) == 80 and len(set(seen)) == 80
        assert (ADDRS[0], 1) in seen

    async def test_one_failing_address_leaves_others_working(self) -> None:
        settings, pool = fake_pool(
            {
                ADDRS[0]: FakeManager([], fail=AuthFailed.imap()),
                ADDRS[1]: FakeManager([(1, day(2))]),
            }
        )
        out = await search_messages_fanout_impl(settings, pool, query="x")
        assert [m["address"] for m in out["messages"]] == [ADDRS[1]]
        assert [e["address"] for e in out["errors"]] == [ADDRS[0]]
        listed = await list_messages_fanout_impl(settings, pool)
        assert len(listed["messages"]) == 1 and listed["errors"]

    async def test_unexpected_error_is_redacted(self, tmp_path: Path) -> None:
        (tmp_path / password_filename(ADDRS[0])).write_text("hunter2-secret")
        (tmp_path / password_filename(ADDRS[1])).write_text("other-secret")
        managers = {
            ADDRS[0]: FakeManager([], fail=RuntimeError("boom hunter2-secret other-secret")),
            ADDRS[1]: FakeManager([]),
        }
        settings = multi_settings(accounts=",".join(managers), password_dir=tmp_path)
        pool = AccountPool(settings, managers=managers)  # type: ignore[arg-type]
        for addr in managers:
            settings.resolve_password(addr)  # as each manager's login does
        out = await search_messages_fanout_impl(settings, pool, query="x")
        text = json.dumps(out)
        assert "hunter2-secret" not in text and "other-secret" not in text

    async def test_health_reports_per_address(self) -> None:
        settings, pool = fake_pool(
            {
                ADDRS[0]: FakeManager([], fail=AuthFailed.imap()),
                ADDRS[1]: FakeManager([]),
            }
        )
        settings = multi_settings(accounts=",".join(pool.addresses), read_only=True)
        report = await health_check_impl(
            settings,
            pool.primary,
            RateLimiter(),
            pool=pool,
        )
        by_addr = {a["address"]: a for a in report["accounts"]}
        assert by_addr[ADDRS[0]]["imap"]["ok"] is False
        assert by_addr[ADDRS[1]]["imap"]["ok"] is True
        assert report["bridge_reachable"] is True
        assert report["imap"]["ok"] is False

    async def test_health_single_address_has_no_accounts_section(self) -> None:
        settings = make_settings(read_only=True)
        managers: dict[str, Any] = {"tester@example.com": FakeManager([])}
        pool = AccountPool(settings, managers=managers)
        report = await health_check_impl(settings, pool.primary, RateLimiter(), pool=pool)
        assert "accounts" not in report


class TestToolSurface:
    async def test_tools_refuse_missing_address_when_several(self) -> None:
        from comlink.server import create_server

        server = create_server(multi_settings())
        cases: list[tuple[str, dict[str, Any]]] = [
            ("proton_get_message", {"uid": 1, "folder": "INBOX"}),
            ("proton_list_folders", {}),
            ("proton_mark_messages", {"uids": [1], "folder": "INBOX", "mark": "read"}),
            ("proton_delete_messages", {"uids": [1], "folder": "INBOX"}),
            (
                "proton_move_messages",
                {"uids": [1], "source_folder": "a", "destination_folder": "b"},
            ),
            ("proton_create_folder", {"name": "x"}),
        ]
        for name, args in cases:
            # The SDK wraps tool exceptions; the cause is Comlink's refusal.
            with pytest.raises(Exception) as excinfo:
                await server.call_tool(name, args)
            cause = excinfo.value.__cause__
            assert isinstance(cause, ComlinkError), name
            assert "address is required" in str(cause), name

    async def test_address_parameter_is_in_schema(self) -> None:
        from comlink.server import create_server

        tools = {t.name: t for t in await create_server(multi_settings()).list_tools()}
        for name in ("proton_get_message", "proton_list_messages", "proton_create_folder"):
            assert "address" in tools[name].input_schema["properties"]


class TestReviewRound1:
    def test_password_dir_refuses_path_traversal_username(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="plain address"):
            make_settings(username="../secret", password=None, password_dir=tmp_path)

    def test_redaction_never_runs_the_command(self, tmp_path: Path) -> None:
        counter = tmp_path / "n"
        s = multi_settings(password_command=f'echo x >> {counter}; printf "pw-$COMLINK_ACCOUNT"')
        _raw_secrets(s)
        _raw_secrets(s)
        assert not counter.exists()

    def test_failed_resolution_is_not_cached(self, tmp_path: Path) -> None:
        addr = ADDRS[1]
        s = multi_settings(password_dir=tmp_path)
        with pytest.raises(ConfigError):
            s.resolve_password(addr)
        assert s.redaction_password(addr) is None
        (tmp_path / password_filename(addr)).write_text("late-pw")
        assert s.resolve_password(addr) == "late-pw"
        assert s.redaction_password(addr) == "late-pw"

    async def test_redaction_refreshes_after_relogin(
        self, bridge: FakeBridgeState, tmp_path: Path
    ) -> None:
        addr = ADDRS[1]
        file = tmp_path / password_filename(addr)
        file.write_text("pw-old")
        s = multi_settings(password_dir=tmp_path)
        manager = AccountPool(s).resolve(addr)[1]
        await manager.verify_connectivity()
        assert s.redaction_password(addr) == "pw-old"
        file.write_text("pw-new")
        await manager.aclose()  # drop the connection: the next call logs in again
        await manager.verify_connectivity()
        assert s.redaction_password(addr) == "pw-new"
        assert "pw-new" in _raw_secrets(s)

    async def test_delete_resolves_address_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from comlink.server import create_server

        pool_resolve = AccountPool.resolve
        calls: list[str | None] = []

        def counting(self: AccountPool, address: str | None) -> Any:
            calls.append(address)
            return pool_resolve(self, address)

        monkeypatch.setattr(AccountPool, "resolve", counting)
        server = create_server(multi_settings())
        with pytest.raises(Exception):  # noqa: B017 - no Bridge; only the resolve count matters
            await server.call_tool(
                "proton_delete_messages",
                {"uids": [1], "folder": "INBOX", "address": ADDRS[1]},
            )
        assert calls == [ADDRS[1]]

    def test_delete_audit_entry_address_only_when_given(self) -> None:
        from comlink.guardrails import delete_audit_entry

        assert "address" not in delete_audit_entry("INBOX", [1], [])
        assert delete_audit_entry("INBOX", [1], [], address=ADDRS[1])["address"] == ADDRS[1]

    async def test_delete_tool_audits_address(self, tmp_path: Path) -> None:
        from comlink.server import delete_messages_impl

        class Mgr:
            async def move_to_trash(self, folder: str, uids: list[int]) -> Any:
                return SimpleNamespace(
                    folder=folder,
                    succeeded=uids,
                    failed=[],
                    model_dump=lambda: {"folder": folder},
                )

        settings = multi_settings(audit_log=tmp_path / "audit.jsonl")
        await delete_messages_impl(settings, Mgr(), uids=[1], folder="INBOX", address=ADDRS[1])  # type: ignore[arg-type]
        entry = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
        assert entry["address"] == ADDRS[1]
