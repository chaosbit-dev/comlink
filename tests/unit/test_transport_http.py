"""streamable-http transport wiring (Epic 5, T4).

create_server must build FastMCP with the configured HTTP bind host/port, mount
path, and DNS-rebinding transport security when transport='streamable-http',
mirroring experiments/auth_probe/auth_probe.py. The stdio path stays the default
and must not pick up any HTTP settings. No real server is started here.
"""

from __future__ import annotations

import pytest

from comlink import server as server_module
from comlink.config import ComlinkSettings
from comlink.server import create_server, main

from ..conftest import make_settings


class TestStdioDefault:
    def test_transport_defaults_to_stdio(self) -> None:
        assert make_settings().transport == "stdio"

    def test_stdio_does_not_apply_http_settings(self) -> None:
        # Even with HTTP fields set, the stdio path must not pass them to FastMCP
        # (the existing stdio construction stays unchanged). FastMCP's own default
        # host is 127.0.0.1, so a 0.0.0.0 override leaking through would be visible.
        server = create_server(
            make_settings(transport="stdio", http_host="0.0.0.0", http_port=9999)
        )
        assert server.settings.host != "0.0.0.0"
        assert server.settings.port != 9999


class TestStreamableHttpBuild:
    def test_http_settings_applied(self) -> None:
        server = create_server(
            make_settings(
                transport="streamable-http",
                http_host="0.0.0.0",
                http_port=8123,
                http_path="/comlink",
            )
        )
        assert server.settings.host == "0.0.0.0"
        assert server.settings.port == 8123
        assert server.settings.streamable_http_path == "/comlink"
        assert server.settings.transport_security is not None

    def test_dns_rebinding_protection_on_when_allowed_hosts_set(self) -> None:
        server = create_server(
            make_settings(
                transport="streamable-http",
                http_allowed_hosts="comlink.chaosbit.dev, alt.chaosbit.dev",
            )
        )
        ts = server.settings.transport_security
        assert ts is not None
        assert ts.enable_dns_rebinding_protection is True
        assert ts.allowed_hosts == ["comlink.chaosbit.dev", "alt.chaosbit.dev"]
        assert ts.allowed_origins == [
            "https://comlink.chaosbit.dev",
            "https://alt.chaosbit.dev",
        ]

    def test_dns_rebinding_protection_off_when_allowed_hosts_empty(self) -> None:
        server = create_server(make_settings(transport="streamable-http", http_allowed_hosts=""))
        ts = server.settings.transport_security
        assert ts is not None
        assert ts.enable_dns_rebinding_protection is False


class TestMainWiresTransport:
    @pytest.mark.parametrize("transport", ["stdio", "streamable-http"])
    def test_main_runs_with_configured_transport(
        self, transport: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        def fake_load_settings() -> ComlinkSettings:
            return make_settings(transport=transport, http_allowed_hosts="comlink.chaosbit.dev")

        def fake_run(self: object, transport: str) -> None:
            captured["transport"] = transport

        monkeypatch.setattr(server_module, "load_settings", fake_load_settings)
        monkeypatch.setattr("mcp.server.fastmcp.FastMCP.run", fake_run)

        main()

        assert captured["transport"] == transport
