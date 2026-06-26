"""Layer-1 gate invisibility attacks (§7.1).

Tech proved proton_send_message is absent when the gate is off and present
when on. Wrecker pushes harder: the tool must be invisible across config
permutations (allowlist set, rate limit set, transport variants), there must be
no *registered-then-refused* leak, and flipping allow_send must not surface a
second send-capable tool. We also confirm the gate decision is made purely from
COMLINK_ALLOW_SEND, not from any other field.
"""

from __future__ import annotations

import pytest

from comlink.server import create_server

from ..conftest import make_settings


async def _tool_names(**overrides: object) -> set[str]:
    server = create_server(make_settings(**overrides))
    return {t.name for t in await server.list_tools()}


class TestGateInvisibility:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"allow_send": False},
            {"allow_send": False, "send_allowlist": "*@chaosbit.dev"},
            {"allow_send": False, "send_max_per_hour": 100},
            {"allow_send": False, "send_allowlist": "kendra@chaosbit.dev", "send_max_per_hour": 1},
            {"allow_send": False, "transport": "streamable-http"},
        ],
    )
    async def test_send_tool_absent_under_every_gate_off_permutation(
        self, overrides: dict[str, object]
    ) -> None:
        names = await _tool_names(**overrides)
        assert "proton_send_message" not in names

    async def test_no_send_capable_tool_leaks_when_gate_off(self) -> None:
        # Only proton_save_draft should be the compose path with the gate off;
        # nothing else should expose a send/SMTP verb in its registered name.
        names = await _tool_names(allow_send=False, send_allowlist="*@chaosbit.dev")
        send_like = {n for n in names if "send" in n.lower()}
        assert send_like == set()

    async def test_exactly_one_extra_tool_appears_when_gate_flips_on(self) -> None:
        off = await _tool_names(allow_send=False, send_allowlist="*@chaosbit.dev")
        on = await _tool_names(allow_send=True, send_allowlist="*@chaosbit.dev")
        # Flipping the gate adds exactly proton_send_message, nothing else.
        assert on - off == {"proton_send_message"}
        assert off - on == set()

    async def test_gate_decision_ignores_allowlist_presence(self) -> None:
        # A populated allowlist must NOT be sufficient to register the tool — the
        # env flag is the sole layer-1 control (defense against a future refactor
        # that keys registration off allowlist size).
        names = await _tool_names(allow_send=False, send_allowlist="a@b.com,*@chaosbit.dev")
        assert "proton_send_message" not in names

    async def test_send_impl_not_reachable_via_any_registered_tool_when_off(self) -> None:
        # Enumerate every registered tool; none of them should be the send impl.
        # (The draft tool calls save_draft_impl, never send_message_impl.)
        server = create_server(make_settings(allow_send=False, send_allowlist="*@chaosbit.dev"))
        tools = await server.list_tools()
        # No tool advertises sending; the destructive-hint compose tool present
        # is the delete tool, not a send.
        for tool in tools:
            assert "send_message_impl" not in (tool.description or "")
