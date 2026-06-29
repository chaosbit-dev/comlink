"""Read-only mode tool-surface gating (Epic 5, T5).

COMLINK_READ_ONLY=true must register ONLY the five read tools; every
write/organize/compose tool (and the send gate) must be invisible to the
client — registration-time, mirroring the send gate's invisibility property
(tests/unit/test_gate_invisibility.py). proton_health_check must surface the
read_only status.
"""

from __future__ import annotations

import pytest

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


class TestHealthReportReadOnlyField:
    async def test_health_report_surfaces_read_only_true(self) -> None:
        class _FakeImap:
            async def verify_connectivity(self) -> int:
                return 7

        settings = make_settings(read_only=True)
        # SMTP verify will fail (no Bridge) but health_check reports rather than raises.
        report = await health_check_impl(settings, _FakeImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["read_only"] is True

    async def test_health_report_surfaces_read_only_false(self) -> None:
        class _FakeImap:
            async def verify_connectivity(self) -> int:
                return 7

        settings = make_settings(read_only=False)
        report = await health_check_impl(settings, _FakeImap(), RateLimiter())  # type: ignore[arg-type]
        assert report["read_only"] is False
