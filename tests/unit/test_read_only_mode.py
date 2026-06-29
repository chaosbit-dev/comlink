"""Read-only mode tool-surface gating (Epic 5, T5).

COMLINK_READ_ONLY=true must register ONLY the five read tools; every
write/organize/compose tool (and the send gate) must be invisible to the
client — registration-time, mirroring the send gate's invisibility property
(tests/unit/test_gate_invisibility.py). proton_health_check must surface the
read_only status.
"""

from __future__ import annotations

import pytest

from comlink.errors import ComlinkError
from comlink.guardrails import RateLimiter
from comlink.server import create_server, health_check_impl

from ..conftest import make_settings

READ_TOOLS = {
    "proton_health_check",
    "proton_list_folders",
    "proton_list_messages",
    "proton_search_messages",
    "proton_get_message",
}

WRITE_TOOLS = {
    "proton_move_messages",
    "proton_mark_messages",
    "proton_delete_messages",
    "proton_create_folder",
    "proton_save_draft",
}

SEND_TOOL = "proton_send_message"


async def _tool_names(**overrides: object) -> set[str]:
    server = create_server(make_settings(**overrides))
    return {t.name for t in await server.list_tools()}


class TestReadOnlyRegistration:
    async def test_default_surface_is_reads_plus_organize_plus_draft_no_send(self) -> None:
        # (read_only=False, allow_send=False): reads + organize + draft, NO send.
        names = await _tool_names(read_only=False, allow_send=False)
        assert names == READ_TOOLS | WRITE_TOOLS
        assert SEND_TOOL not in names

    @pytest.mark.parametrize(
        "overrides",
        [
            {"read_only": True},
            {"read_only": True, "allow_send": False},
            {"read_only": True, "allow_send": True},
            {"read_only": True, "allow_send": True, "send_allowlist": "*@chaosbit.dev"},
            {"read_only": True, "transport": "streamable-http"},
        ],
    )
    async def test_read_only_registers_exactly_the_five_read_tools(
        self, overrides: dict[str, object]
    ) -> None:
        # (read_only=True, *): ONLY the five read tools, nothing else — not even
        # the send tool when allow_send is also true (doubly gated).
        names = await _tool_names(**overrides)
        assert names == READ_TOOLS

    async def test_read_only_hides_every_write_and_send_tool(self) -> None:
        names = await _tool_names(read_only=True, allow_send=True, send_allowlist="*@chaosbit.dev")
        assert names.isdisjoint(WRITE_TOOLS)
        assert SEND_TOOL not in names

    async def test_send_present_when_writable_and_gate_on(self) -> None:
        # (read_only=False, allow_send=True): send present.
        names = await _tool_names(read_only=False, allow_send=True, send_allowlist="*@chaosbit.dev")
        assert SEND_TOOL in names
        assert names == READ_TOOLS | WRITE_TOOLS | {SEND_TOOL}

    async def test_read_only_overrides_send_gate(self) -> None:
        # Flipping allow_send must not surface any tool while read_only is on.
        off = await _tool_names(read_only=True, allow_send=False)
        on = await _tool_names(read_only=True, allow_send=True, send_allowlist="*@chaosbit.dev")
        assert off == on == READ_TOOLS


class _OkImap:
    async def verify_connectivity(self) -> int:
        return 7


class _DownImap:
    async def verify_connectivity(self) -> int:
        raise RuntimeError("bridge down")


class TestHealthReportReadOnlyField:
    async def test_health_report_surfaces_read_only_true(self) -> None:
        settings = make_settings(read_only=True)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["read_only"] is True

    async def test_health_report_surfaces_read_only_false(self) -> None:
        settings = make_settings(read_only=False)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["read_only"] is False


class TestHealthReportSmtpSkip:
    """Read-only deploys register no send tool, so the SMTP probe is skipped: SMTP is
    reported as 'not checked' (None), and reachability rests on IMAP alone — a skipped
    SMTP neither drags bridge_reachable down nor falsely props it up (Epic 5)."""

    async def test_read_only_skips_smtp_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # If the probe ran it would explode the test — proving it is never called.
        async def _explode(*args: object, **kwargs: object) -> None:
            raise AssertionError("SMTP probe must be skipped in read-only mode")

        monkeypatch.setattr("comlink.server.verify_smtp_connectivity", _explode)
        settings = make_settings(read_only=True)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["smtp"] is None

    async def test_read_only_reachability_follows_imap_ok(self) -> None:
        settings = make_settings(read_only=True)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["smtp"] is None
        assert report["bridge_reachable"] is True
        assert report["imap"]["ok"] is True

    async def test_read_only_skipped_smtp_does_not_prop_up_dead_imap(self) -> None:
        # IMAP down + SMTP skipped → not reachable. The skipped SMTP must not mask it.
        settings = make_settings(read_only=True)
        report = await health_check_impl(settings, _DownImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["smtp"] is None
        assert report["imap"]["ok"] is False
        assert report["bridge_reachable"] is False

    async def test_non_read_only_probes_smtp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        probed = False

        async def _probe(*args: object, **kwargs: object) -> None:
            nonlocal probed
            probed = True

        monkeypatch.setattr("comlink.server.verify_smtp_connectivity", _probe)
        settings = make_settings(read_only=False)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert probed is True
        assert report["smtp"] == {"ok": True, "error": None}
        assert report["bridge_reachable"] is True

    async def test_non_read_only_smtp_failure_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _fail(*args: object, **kwargs: object) -> None:
            raise ComlinkError("smtp unreachable")

        monkeypatch.setattr("comlink.server.verify_smtp_connectivity", _fail)
        settings = make_settings(read_only=False)
        report = await health_check_impl(settings, _OkImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["smtp"]["ok"] is False
        assert report["smtp"]["error"] == "smtp unreachable"
        # IMAP is up, so bridge is still reachable despite the SMTP failure.
        assert report["bridge_reachable"] is True
