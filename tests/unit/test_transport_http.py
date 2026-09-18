"""streamable-http transport wiring (Epic 5, T4).

Under mcp 1.x, create_server passed the HTTP bind host/port, mount path and
DNS-rebinding transport security to the FastMCP *constructor*, and these tests
asserted on `server.settings.*`. mcp 2.x removed all of that from the
constructor and moved it onto streamable_http_app()/run_streamable_http_async(),
so the same guarantees are now asserted against _http_app_kwargs and against
what _run_http actually hands to streamable_http_app.

That relocation is the whole point of the coverage here: in 2.x a missing
transport_security argument does not error, it silently disables DNS-rebinding
protection. No real server is started.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from comlink import server as server_module
from comlink.config import ComlinkSettings
from comlink.server import _http_app_kwargs, create_server, main

from ..conftest import make_settings


class TestStdioDefault:
    def test_transport_defaults_to_stdio(self) -> None:
        assert make_settings().transport == "stdio"

    def test_stdio_never_builds_http_transport_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The 2.x constructor holds no HTTP state, so "did it leak into stdio?"
        # is now answered by whether the stdio path consults _http_app_kwargs.
        called: list[object] = []

        monkeypatch.setattr(server_module, "load_settings", lambda: make_settings(
            transport="stdio", http_host="0.0.0.0", http_port=9999
        ))
        monkeypatch.setattr(
            server_module, "_http_app_kwargs", lambda s: called.append(s) or {}
        )
        monkeypatch.setattr("mcp.server.mcpserver.MCPServer.run", lambda self: None)
        monkeypatch.setattr(server_module, "_run_http", lambda server, settings: None)

        main()

        assert called == []


class TestHttpAppKwargs:
    def test_host_and_mount_path_applied(self) -> None:
        kwargs = _http_app_kwargs(
            make_settings(
                transport="streamable-http",
                http_host="0.0.0.0",
                http_port=8123,
                http_path="/comlink",
            )
        )
        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["streamable_http_path"] == "/comlink"
        assert kwargs["transport_security"] is not None
        # Port is uvicorn's job; streamable_http_app() has no port parameter and
        # passing one would be a TypeError at serve time.
        assert "port" not in kwargs

    def test_dns_rebinding_protection_on_when_allowed_hosts_set(self) -> None:
        ts = _http_app_kwargs(
            make_settings(
                transport="streamable-http",
                http_allowed_hosts="comlink.chaosbit.dev, alt.chaosbit.dev",
            )
        )["transport_security"]
        assert ts.enable_dns_rebinding_protection is True
        assert ts.allowed_hosts == ["comlink.chaosbit.dev", "alt.chaosbit.dev"]
        assert ts.allowed_origins == [
            "https://comlink.chaosbit.dev",
            "https://alt.chaosbit.dev",
        ]

    def test_dns_rebinding_protection_off_when_allowed_hosts_empty(self) -> None:
        ts = _http_app_kwargs(
            make_settings(transport="streamable-http", http_allowed_hosts="")
        )["transport_security"]
        assert ts.enable_dns_rebinding_protection is False


class TestRunHttpPassesTransportSecurity:
    """Regression guard for the 2.x relocation.

    If streamable_http_app() is ever called without these kwargs the server still
    starts and every other test still passes — it just has no DNS-rebinding
    protection. This is the only test that would notice.
    """

    def test_streamable_http_app_receives_transport_security(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import uvicorn

        settings = make_settings(
            transport="streamable-http",
            http_host="0.0.0.0",
            http_path="/comlink",
            http_allowed_hosts="comlink.chaosbit.dev",
        )
        server = create_server(settings)
        captured: dict[str, Any] = {}

        def fake_app(**kwargs: Any) -> object:
            captured.update(kwargs)
            return object()

        monkeypatch.setattr(server, "streamable_http_app", fake_app)
        monkeypatch.setattr(uvicorn.Server, "run", lambda self: None)

        server_module._run_http(server, settings)

        assert captured["streamable_http_path"] == "/comlink"
        assert captured["host"] == "0.0.0.0"
        ts = captured["transport_security"]
        assert ts is not None
        assert ts.enable_dns_rebinding_protection is True
        assert ts.allowed_hosts == ["comlink.chaosbit.dev"]


class TestMainWiresTransport:
    def test_stdio_uses_mcpserver_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run(self: object) -> None:
            captured["ran"] = True

        def fake_run_http(server: object, settings: object) -> None:
            captured["http"] = True

        monkeypatch.setattr(
            server_module, "load_settings", lambda: make_settings(transport="stdio")
        )
        monkeypatch.setattr("mcp.server.mcpserver.MCPServer.run", fake_run)
        monkeypatch.setattr(server_module, "_run_http", fake_run_http)

        main()

        assert captured == {"ran": True}

    def test_streamable_http_uses_run_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        def fake_run(self: object) -> None:
            captured["ran"] = True

        def fake_run_http(server: MCPServer, settings: ComlinkSettings) -> None:
            captured["http_server"] = server
            captured["http_transport"] = settings.transport

        monkeypatch.setattr(
            server_module,
            "load_settings",
            lambda: make_settings(
                transport="streamable-http", http_allowed_hosts="comlink.chaosbit.dev"
            ),
        )
        monkeypatch.setattr("mcp.server.mcpserver.MCPServer.run", fake_run)
        monkeypatch.setattr(server_module, "_run_http", fake_run_http)

        main()

        # stdio run path must NOT be taken; _run_http gets the configured server.
        assert "ran" not in captured
        assert captured["http_transport"] == "streamable-http"
        assert isinstance(captured["http_server"], MCPServer)
