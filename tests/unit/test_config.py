"""Configuration: defaults, password resolution, TLS no-verify refusal (§5)."""

from __future__ import annotations

import ssl

import pytest
from pydantic import ValidationError

from comlink.config import ComlinkSettings, load_settings
from comlink.errors import ConfigError

from ..conftest import make_settings


class TestDefaults:
    def test_defaults_match_design_doc(self) -> None:
        settings = ComlinkSettings()
        assert settings.imap_host == "127.0.0.1"
        assert settings.imap_port == 1143
        assert settings.smtp_host == "127.0.0.1"
        assert settings.smtp_port == 1025
        assert settings.tls_mode == "verify"
        assert settings.allow_send is False
        assert settings.send_max_per_hour == 5
        assert settings.transport == "stdio"

    def test_env_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMLINK_IMAP_PORT", "2143")
        monkeypatch.setenv("COMLINK_USERNAME", "brandon")
        settings = load_settings()
        assert settings.imap_port == 2143
        assert settings.username == "brandon"


class TestPasswordResolution:
    def test_password_command_stdout_is_password(self) -> None:
        settings = make_settings(password=None, password_command="printf 'from-command\\n'")
        assert settings.resolve_password() == "from-command"

    def test_password_command_wins_over_password(self) -> None:
        settings = make_settings(password="from-env", password_command="printf 'from-command'")
        assert settings.resolve_password() == "from-command"

    def test_falls_back_to_password(self) -> None:
        settings = make_settings(password="from-env", password_command=None)
        assert settings.resolve_password() == "from-env"

    def test_command_failure_is_config_error(self) -> None:
        settings = make_settings(password=None, password_command="exit 3")
        with pytest.raises(ConfigError, match="status 3"):
            settings.resolve_password()

    def test_command_empty_output_is_config_error(self) -> None:
        settings = make_settings(password=None, password_command="true")
        with pytest.raises(ConfigError, match="no output"):
            settings.resolve_password()

    def test_command_failure_redacts_password_from_stderr(self) -> None:
        settings = make_settings(
            password="sup3r-secret",
            password_command="echo 'leaked sup3r-secret' >&2; exit 1",
        )
        with pytest.raises(ConfigError) as excinfo:
            settings.resolve_password()
        assert "sup3r-secret" not in str(excinfo.value)
        assert "[REDACTED]" in str(excinfo.value)

    def test_command_failure_redacts_command_derived_secret_from_stderr(self) -> None:
        # Epic 4 finding 2: the COMMAND is the credential source (no static password),
        # so the resolved secret is the command's stdout. A command that echoes that
        # secret to stderr before failing must not surface it — stderr is redacted
        # against the command's own stdout, not just the (here-None) static password.
        settings = make_settings(
            password=None,
            password_command="printf 'cmd-sup3r-secret'; printf 'cmd-sup3r-secret' >&2; exit 1",
        )
        with pytest.raises(ConfigError) as excinfo:
            settings.resolve_password()
        assert "cmd-sup3r-secret" not in str(excinfo.value)
        assert "[REDACTED]" in str(excinfo.value)

    def test_no_password_at_all_is_config_error(self) -> None:
        settings = make_settings(password=None, password_command=None)
        with pytest.raises(ConfigError, match="COMLINK_PASSWORD"):
            settings.resolve_password()


class TestTlsPolicy:
    def test_no_verify_refused_for_non_localhost_imap(self) -> None:
        with pytest.raises(ValidationError, match="not localhost"):
            make_settings(tls_mode="no-verify", imap_host="gonk.tailnet.example")

    def test_no_verify_refused_for_non_localhost_smtp(self) -> None:
        with pytest.raises(ValidationError, match="not localhost"):
            make_settings(tls_mode="no-verify", smtp_host="10.0.0.5")

    @pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
    def test_no_verify_allowed_for_localhost(self, host: str) -> None:
        settings = make_settings(tls_mode="no-verify", imap_host=host, smtp_host=host)
        assert settings.tls_mode == "no-verify"

    def test_verify_allowed_anywhere(self) -> None:
        settings = make_settings(tls_mode="verify", imap_host="gonk.tailnet.example")
        assert settings.imap_host == "gonk.tailnet.example"

    def test_load_settings_wraps_validation_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COMLINK_TLS_MODE", "no-verify")
        monkeypatch.setenv("COMLINK_IMAP_HOST", "192.168.1.50")
        with pytest.raises(ConfigError, match="not localhost"):
            load_settings()

    def test_no_verify_context_disables_verification(self) -> None:
        context = make_settings(tls_mode="no-verify").build_ssl_context()
        assert context.verify_mode == ssl.CERT_NONE
        assert context.check_hostname is False

    def test_verify_context_verifies(self) -> None:
        context = make_settings(tls_mode="verify").build_ssl_context()
        assert context.verify_mode == ssl.CERT_REQUIRED


class TestAllowlist:
    def test_parsed_allowlist_normalizes(self) -> None:
        settings = make_settings(send_allowlist=" Kendra@example.com, *@chaosbit.dev ,, ")
        assert settings.parsed_allowlist() == ["kendra@example.com", "*@chaosbit.dev"]

    def test_empty_allowlist(self) -> None:
        assert make_settings().parsed_allowlist() == []
