"""Allowlist-bypass attacks (§7.1, layer 2).

The high-value question: can a non-allowlisted address receive mail? Two layers
to break: (1) recipient_allowed's matching logic, and (2) the wiring in
send_message_impl that must check EVERY envelope recipient (to + cc + bcc), not
just To. We also confirm what actually reaches SMTP equals what was checked
(no check-here / deliver-there mismatch).
"""

from __future__ import annotations

from typing import Any

import pytest

import comlink.bridge.smtp as smtp_module
from comlink.config import ComlinkSettings
from comlink.errors import SendBlocked
from comlink.guardrails import RateLimiter, check_allowlist, recipient_allowed
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
        calls.append({"recipients": envelope_recipients, "message": message})
        return str(message["Message-ID"])

    monkeypatch.setattr(smtp_module, "send_message", fake_send)
    return calls


# ---------------------------------------------------------------------------
# recipient_allowed matching logic — adversarial inputs
# ---------------------------------------------------------------------------


class TestRecipientAllowedAdversarial:
    @pytest.mark.parametrize(
        "addr",
        [
            "Trusted <evil@attacker.com>",  # display-name spoof
            "evil@attacker.com <kendra@chaosbit.dev>",  # addr-spec in display slot
            "kendra@chaosbit.dev <evil@attacker.com>",  # real addr in angle brackets
            "a@evil.chaosbit.dev",  # subdomain — *@chaosbit.dev must NOT match
            "a@chaosbit.dev.evil.com",  # domain as a prefix label
            "a@chaosbit-dev.com",  # near-miss domain
            "",  # empty recipient
            "kendra@chaosbit.dev evil@attacker.com",  # space-separated smuggle
            "kendra@chaosbit.dev,evil@attacker.com",  # comma smuggle
        ],
    )
    def test_wildcard_rejects_smuggle_and_spoof(self, addr: str) -> None:
        # *@chaosbit.dev is the wildcard; none of these should be allowed.
        assert recipient_allowed(addr, ["*@chaosbit.dev"]) is False

    def test_wildcard_does_not_match_subdomain(self) -> None:
        assert recipient_allowed("victim@mail.chaosbit.dev", ["*@chaosbit.dev"]) is False

    def test_exact_entry_does_not_match_display_name_form(self) -> None:
        # An exact allowlist entry only matches the bare lowercased addr — a
        # display-name-wrapped form is fail-closed (rejected), never bypasses.
        assert recipient_allowed("Kendra <kendra@chaosbit.dev>", ["kendra@chaosbit.dev"]) is False

    def test_empty_recipient_never_allowed_under_nonempty_allowlist(self) -> None:
        assert recipient_allowed("", ["*@chaosbit.dev"]) is False
        assert recipient_allowed("   ", ["kendra@chaosbit.dev"]) is False

    def test_idn_homoglyph_domain_rejected(self) -> None:
        # Cyrillic small letter o swapped for Latin 'o' in "chaosbit" --
        # a visually identical but byte-distinct domain that must NOT match the
        # allowlist. Built from an escape so the source file stays ASCII-only.
        homoglyph = "victim@cha\u043esbit.dev"  # Cyrillic o (U+043E), built from escape
        assert recipient_allowed(homoglyph, ["*@chaosbit.dev"]) is False

    def test_at_in_local_part_routes_to_allowed_domain_only(self) -> None:
        # "a@b@chaosbit.dev": rsplit('@',1) -> domain chaosbit.dev. Per RFC the
        # routing domain IS the part after the last @, so this stays in-domain.
        # Documenting that this is a deliberate match, not a bypass to attacker.com.
        assert recipient_allowed("evil@attacker.com@chaosbit.dev", ["*@chaosbit.dev"]) is True
        # The dangerous inverse — domain after last @ is the attacker — is blocked.
        assert recipient_allowed("kendra@chaosbit.dev@attacker.com", ["*@chaosbit.dev"]) is False


# ---------------------------------------------------------------------------
# check_allowlist — ALL recipients must be vetted
# ---------------------------------------------------------------------------


class TestCheckAllowlistCoversEveryone:
    def test_last_recipient_offender_is_caught(self) -> None:
        settings = make_settings(send_allowlist="*@chaosbit.dev")
        with pytest.raises(SendBlocked, match=r"stranger@example\.com"):
            check_allowlist(["a@chaosbit.dev", "b@chaosbit.dev", "stranger@example.com"], settings)

    def test_single_offender_among_many_blocks_all(self) -> None:
        settings = make_settings(send_allowlist="*@chaosbit.dev")
        recipients = [f"u{i}@chaosbit.dev" for i in range(20)]
        recipients.insert(10, "leak@evil.com")
        with pytest.raises(SendBlocked, match=r"leak@evil\.com"):
            check_allowlist(recipients, settings)


# ---------------------------------------------------------------------------
# Wiring: send_message_impl must vet to + cc + bcc, and a single offender
# anywhere blocks the whole send (no partial send to the allowed subset).
# ---------------------------------------------------------------------------


class TestEnvelopeAllowlistWiring:
    async def test_offender_only_in_cc_blocks(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked, match=r"leak@evil\.com"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["kendra@chaosbit.dev"],
                cc=["leak@evil.com"],
                body_text="b",
                confirm=True,
            )
        assert captured_send == []

    async def test_offender_only_in_bcc_blocks(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked, match=r"leak@evil\.com"):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["kendra@chaosbit.dev"],
                bcc=["leak@evil.com"],
                body_text="b",
                confirm=True,
            )
        assert captured_send == []

    async def test_allowed_to_but_offender_bcc_sends_nothing(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        # No partial send: even though To is fully allowed, the bad Bcc kills
        # the entire send. Nothing reaches SMTP.
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="kendra@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["kendra@chaosbit.dev"],
                bcc=["stranger@example.com"],
                body_text="b",
                confirm=True,
            )
        assert captured_send == []

    async def test_display_name_recipient_blocked_end_to_end(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        # A spoofed display name carrying an off-domain addr-spec must not send.
        settings = make_settings(
            username="brandon@chaosbit.dev",
            send_allowlist="*@chaosbit.dev",
            audit_log=tmp_path / "audit.jsonl",
        )
        with pytest.raises(SendBlocked):
            await send_message_impl(
                settings,
                object(),  # type: ignore[arg-type]
                RateLimiter(),
                to=["Kendra Luttrell <evil@attacker.com>"],
                body_text="b",
                confirm=True,
            )
        assert captured_send == []

    async def test_what_is_checked_is_what_is_sent(
        self, tmp_path: Any, captured_send: list[dict[str, Any]]
    ) -> None:
        # The exact deduped recipient list that passed the allowlist is the exact
        # list handed to SMTP — no transformation that could deliver elsewhere.
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
            cc=["b@chaosbit.dev"],
            bcc=["c@chaosbit.dev"],
            body_text="b",
            confirm=True,
        )
        assert captured_send[0]["recipients"] == [
            "a@chaosbit.dev",
            "b@chaosbit.dev",
            "c@chaosbit.dev",
        ]
