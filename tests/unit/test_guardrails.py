"""Guardrails: audit append (Epic 2) + send allowlist / rate limit (Epic 3).

§5, §7: allowlist (layer 2) and the sliding-window rate limiter (layer 3). The
master env gate (layer 1) is enforced at registration in server.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from comlink.errors import SendBlocked
from comlink.guardrails import (
    RateLimiter,
    append_audit,
    check_allowlist,
    delete_audit_entry,
    recipient_allowed,
    send_audit_entry,
)

from ..conftest import make_settings


class TestDeleteAuditEntry:
    def test_schema_fields(self) -> None:
        entry = delete_audit_entry("INBOX", [1, 2], [3])
        assert entry["action"] == "delete"
        assert entry["folder"] == "INBOX"
        assert entry["succeeded"] == [1, 2]
        assert entry["failed"] == [3]
        assert entry["uids"] == [1, 2, 3]
        # ISO8601 timestamp, present and parseable.
        assert "T" in entry["ts"]

    def test_entry_carries_no_secrets(self) -> None:
        entry = delete_audit_entry("INBOX", [1], [])
        flat = json.dumps(entry)
        assert "password" not in flat.lower()


class TestAppendAudit:
    def test_appends_one_json_line_and_creates_dirs(self, tmp_path: Path) -> None:
        settings = make_settings(audit_log=tmp_path / "nested" / "audit.jsonl")
        ok1 = append_audit(settings, delete_audit_entry("INBOX", [1], []))
        ok2 = append_audit(settings, delete_audit_entry("INBOX", [2], []))
        assert ok1 and ok2
        path = tmp_path / "nested" / "audit.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["succeeded"] == [1]
        assert json.loads(lines[1])["succeeded"] == [2]

    def test_expanduser_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        settings = make_settings(audit_log=Path("~/.comlink/audit.jsonl"))
        assert append_audit(settings, delete_audit_entry("INBOX", [1], []))
        assert (tmp_path / ".comlink" / "audit.jsonl").exists()

    def test_write_failure_is_log_and_continue(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")

        def boom(*_args: object, **_kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(Path, "mkdir", boom)
        # Must not raise — failure is swallowed and reported via return value.
        assert append_audit(settings, delete_audit_entry("INBOX", [1], [])) is False


class TestRecipientAllowed:
    def test_empty_allowlist_permits_anyone(self) -> None:
        assert recipient_allowed("anyone@anywhere.com", []) is True

    def test_exact_match_case_insensitive(self) -> None:
        allowlist = ["kendra@chaosbit.dev"]
        assert recipient_allowed("Kendra@ChaosBit.Dev", allowlist) is True

    def test_wildcard_domain_match(self) -> None:
        allowlist = ["*@chaosbit.dev"]
        assert recipient_allowed("anyone@chaosbit.dev", allowlist) is True
        assert recipient_allowed("anyone@other.com", allowlist) is False

    def test_miss_when_not_listed(self) -> None:
        allowlist = ["kendra@chaosbit.dev"]
        assert recipient_allowed("stranger@example.com", allowlist) is False

    def test_bare_domain_is_not_a_match(self) -> None:
        # Only exact or *@domain — a bare 'chaosbit.dev' entry never matches.
        assert recipient_allowed("anyone@chaosbit.dev", ["chaosbit.dev"]) is False


class TestCheckAllowlist:
    def test_empty_allowlist_is_noop(self) -> None:
        settings = make_settings(send_allowlist="")
        check_allowlist(["whoever@anywhere.com"], settings)  # no raise

    def test_blocks_first_offender_by_name(self) -> None:
        settings = make_settings(send_allowlist="kendra@chaosbit.dev, *@chaosbit.dev")
        with pytest.raises(SendBlocked, match=r"stranger@example\.com"):
            check_allowlist(["kendra@chaosbit.dev", "stranger@example.com"], settings)

    def test_all_allowed_passes(self) -> None:
        settings = make_settings(send_allowlist="*@chaosbit.dev")
        check_allowlist(["a@chaosbit.dev", "b@chaosbit.dev"], settings)


class TestRateLimiter:
    def test_nth_send_ok_n_plus_one_blocked(self) -> None:
        limiter = RateLimiter()
        now = 1000.0
        for _ in range(3):
            limiter.check(now, max_per_hour=3)
            limiter.commit(now)
        with pytest.raises(SendBlocked, match="rate limit"):
            limiter.check(now, max_per_hour=3)

    def test_window_eviction_with_injectable_now(self) -> None:
        limiter = RateLimiter()
        # Two sends at t=0, then a third would exceed max=2...
        limiter.check(0.0, max_per_hour=2)
        limiter.commit(0.0)
        limiter.check(1.0, max_per_hour=2)
        limiter.commit(1.0)
        with pytest.raises(SendBlocked):
            limiter.check(2.0, max_per_hour=2)
        # ...but once the window slides past the first timestamp, room frees up.
        limiter.check(0.0 + 3600.5, max_per_hour=2)  # no raise (first evicted)

    def test_failed_send_does_not_burn_budget(self) -> None:
        # check() does not consume budget; only commit() does. So a check that
        # is followed by a failed send (no commit) leaves the budget intact.
        limiter = RateLimiter()
        now = 500.0
        limiter.check(now, max_per_hour=1)
        # send "fails" → no commit. A retry must still be allowed.
        limiter.check(now, max_per_hour=1)  # no raise
        limiter.commit(now)
        # Now the single slot is used; the next check blocks.
        with pytest.raises(SendBlocked):
            limiter.check(now, max_per_hour=1)

    def test_remaining_budget(self) -> None:
        limiter = RateLimiter()
        assert limiter.remaining_budget(0.0, max_per_hour=5) == 5
        limiter.commit(0.0)
        limiter.commit(0.0)
        assert limiter.remaining_budget(0.0, max_per_hour=5) == 3
        # After the window slides, budget is restored.
        assert limiter.remaining_budget(3600.5, max_per_hour=5) == 5


class TestSendAuditEntry:
    def test_schema_fields(self) -> None:
        entry = send_audit_entry(["a@b.com", "c@d.com"], "Hello", "<id@b.com>")
        assert entry["action"] == "send"
        assert entry["recipients"] == ["a@b.com", "c@d.com"]
        assert entry["subject"] == "Hello"
        assert entry["message_id"] == "<id@b.com>"
        assert "T" in entry["ts"]

    def test_no_body_or_secrets(self) -> None:
        entry = send_audit_entry(["a@b.com"], "Subj", "<id@b.com>")
        flat = json.dumps(entry).lower()
        assert "body" not in flat
        assert "password" not in flat
