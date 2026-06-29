"""Configuration: defaults, password resolution, TLS no-verify refusal (§5)."""

from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from pydantic import ValidationError

from comlink.config import ComlinkSettings, load_settings
from comlink.errors import ConfigError

from ..conftest import make_settings

# A self-signed cert (CN=localhost, SAN localhost/127.0.0.1) — exactly what Proton
# Bridge serves. Pinned via COMLINK_TLS_CERT_PATH in verify-no-hostname tests.
_SELF_SIGNED_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIICyTCCAbGgAwIBAgIJAOQbe18/ZhwRMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0yNjA2MjkxODM2NDdaFw0zNjA2MjYxODM2NDdaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKwBVJiGjxIvdUA8Gz7WjmxWPz991ZkPV4ColTrFDzZD3+4pMxKWJWcbZiYD
lpDgtQQ1NRbCv/vrVdVweTtLycRSUBd88dVWinn9uHNEPt/lGGLy3JuKa662okQ6
22ju6qQpyTcwotdhooo55bnhNhBMdOGa0dpo7hWHfY8rj6YPqSTIDkkfi9oLoy7X
VOq3wQKBiBVyDUUv/BNKKU3F0dqL88h7ARZVCjc4k5lIs+kpYhHq9tl2AiK07AbC
o1XmAQZDG0HCUoyRg5BBgP0OKjYgqzS0hO2E4e9wk2+AtN7skIUKrP1OXYGdfGiK
ms9Go8viW324fhp2x35KxfGCJmECAwEAAaMeMBwwGgYDVR0RBBMwEYIJbG9jYWxo
b3N0hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQCkmfBUUTNkf06OlNRFdQQsS68S
+reXHKEpCZI3MAUetz8CqT2X13NScvMm2dyy6+2+VDyHMnZPOk4PePYIL+QeSSE0
Pip4/xNUKhHjdR9GaUTL7nLP4j9RPihT/+0nhKqi1G7MNyw3VVZqazz+I4IHAooT
is3OVJBM+NPgT/3vqKa0uMQKWFUTy7QFWd5AkC/ErWhis29rNpogQf+XDjelJPxV
dUjccjxX3LE3Rnn0SChDRiDe/xe9Z9zNFh8EvPV+Nt7CR1g6/k/SSJcXkbMOSoTK
+uVd6t7K3VGtpwQKYfCRgb4f7+tQ6U5pVcjS8a/sWmY2qgvzKm+x5q2K9YhZ
-----END CERTIFICATE-----
"""


def _write_self_signed_cert(tmp_path: Path) -> Path:
    cert = tmp_path / "bridge-cert.pem"
    cert.write_text(_SELF_SIGNED_CERT_PEM)
    return cert


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
        assert context.check_hostname is True


class TestVerifyNoHostname:
    """verify-no-hostname: pin the self-signed Bridge cert, skip hostname matching
    (Epic 5, design doc line 246). Required for the in-cluster proton-bridge service,
    whose cert is issued for localhost/127.0.0.1, not the service DNS name."""

    def test_context_pins_cert_and_skips_hostname(self, tmp_path: Path) -> None:
        cert = _write_self_signed_cert(tmp_path)
        context = make_settings(
            tls_mode="verify-no-hostname",
            tls_cert_path=str(cert),
            imap_host="proton-bridge.proton-bridge.svc.cluster.local",
        ).build_ssl_context()
        # Cert REQUIRED (chained to the pinned cert) but hostname matching off.
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is False
        # Exactly the pinned cert is loaded — cafile does not pull in the system CAs,
        # so the trust store holds the one pinned cert and nothing else.
        assert context.cert_store_stats()["x509"] == 1

    def test_requires_cert_path(self) -> None:
        with pytest.raises(ValidationError, match="requires COMLINK_TLS_CERT_PATH"):
            make_settings(tls_mode="verify-no-hostname", tls_cert_path=None)

    def test_allowed_for_non_localhost_host(self, tmp_path: Path) -> None:
        # Unlike no-verify, verify-no-hostname pins a cert, so it is allowed off-localhost.
        cert = _write_self_signed_cert(tmp_path)
        settings = make_settings(
            tls_mode="verify-no-hostname",
            tls_cert_path=str(cert),
            imap_host="proton-bridge.proton-bridge.svc.cluster.local",
            smtp_host="proton-bridge.proton-bridge.svc.cluster.local",
        )
        assert settings.tls_mode == "verify-no-hostname"

    def test_load_settings_via_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        cert = _write_self_signed_cert(tmp_path)
        monkeypatch.setenv("COMLINK_TLS_MODE", "verify-no-hostname")
        monkeypatch.setenv("COMLINK_TLS_CERT_PATH", str(cert))
        monkeypatch.setenv("COMLINK_IMAP_HOST", "proton-bridge.proton-bridge.svc.cluster.local")
        settings = load_settings()
        assert settings.tls_mode == "verify-no-hostname"

    def test_missing_cert_via_env_wraps_as_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("COMLINK_TLS_MODE", "verify-no-hostname")
        with pytest.raises(ConfigError, match="requires COMLINK_TLS_CERT_PATH"):
            load_settings()


class TestAllowlist:
    def test_parsed_allowlist_normalizes(self) -> None:
        settings = make_settings(send_allowlist=" Kendra@example.com, *@chaosbit.dev ,, ")
        assert settings.parsed_allowlist() == ["kendra@example.com", "*@chaosbit.dev"]

    def test_empty_allowlist(self) -> None:
        assert make_settings().parsed_allowlist() == []
