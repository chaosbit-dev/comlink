"""Configuration via environment variables (design doc §5).

All settings use the ``COMLINK_`` prefix. No secrets are ever logged.
"""

from __future__ import annotations

import ssl
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from comlink.errors import ConfigError, redact

LOCALHOST_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

_PASSWORD_COMMAND_TIMEOUT_SECONDS = 30.0


class ComlinkSettings(BaseSettings):
    """All Comlink configuration, sourced from ``COMLINK_*`` env vars."""

    model_config = SettingsConfigDict(env_prefix="COMLINK_", extra="ignore")

    imap_host: str = "127.0.0.1"
    imap_port: int = 1143
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 1025

    username: str = ""
    password: SecretStr | None = None
    password_command: str | None = None

    # DESIGN-GAP: design doc §3.4/§5 enumerate only "verify" | "no-verify". Epic 5
    # (durable K3s deploy, design doc line 246 "revisit TLS pinning against the Gonk
    # Bridge cert") needs a third mode: the Bridge cert is self-signed for
    # localhost/127.0.0.1, not the in-cluster service DNS name, so plain "verify"
    # fails hostname matching even with the cert pinned, and "no-verify" is illegal
    # off-localhost. "verify-no-hostname" pins the cert (CERT_REQUIRED against
    # COMLINK_TLS_CERT_PATH) but skips the hostname check.
    tls_mode: Literal["verify", "no-verify", "verify-no-hostname"] = "verify"
    tls_cert_path: Path | None = None
    smtp_security: Literal["starttls", "ssl"] = Field(
        default="starttls",
        description=(
            '"starttls" = connect plaintext then STARTTLS (Bridge default); '
            '"ssl" = implicit TLS on connect (for Bridge configured with SSL).'
        ),
    )

    read_only: bool = False

    allow_send: bool = False
    send_allowlist: str = ""
    send_max_per_hour: int = 5
    audit_log: Path = Path("~/.comlink/audit.jsonl")

    transport: Literal["stdio", "streamable-http"] = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    http_path: str = "/mcp"
    # Comma-separated Host allowlist for DNS-rebinding protection on the
    # streamable-http transport (design doc §2 Phase 2). Empty disables the
    # check — acceptable behind Cloudflare Access, never for bare-internet.
    http_allowed_hosts: str = ""

    @model_validator(mode="after")
    def _refuse_no_verify_off_localhost(self) -> ComlinkSettings:
        """TLS ``no-verify`` is acceptable for localhost only (design doc §3.4, §7.6)."""
        if self.tls_mode == "no-verify":
            for label, host in (("IMAP", self.imap_host), ("SMTP", self.smtp_host)):
                if host not in LOCALHOST_HOSTS:
                    raise ValueError(
                        f"COMLINK_TLS_MODE=no-verify is refused because the {label} host "
                        f"'{host}' is not localhost. Use COMLINK_TLS_MODE=verify with "
                        "COMLINK_TLS_CERT_PATH pointing at the pinned Bridge certificate."
                    )
        return self

    @model_validator(mode="after")
    def _require_cert_for_verify_no_hostname(self) -> ComlinkSettings:
        """``verify-no-hostname`` MUST pin a cert (design doc line 246, Epic 5).

        Without ``COMLINK_TLS_CERT_PATH`` the context would chain against the system
        CAs, which do not know the self-signed Bridge cert — and with the hostname
        check disabled that degrades to near-``no-verify`` blanket trust. Refuse it.
        """
        if self.tls_mode == "verify-no-hostname" and self.tls_cert_path is None:
            raise ValueError(
                "COMLINK_TLS_MODE=verify-no-hostname requires COMLINK_TLS_CERT_PATH "
                "to pin the self-signed Bridge certificate. Without a pinned cert the "
                "connection would trust any system-CA-chained certificate while skipping "
                "the hostname check. Set COMLINK_TLS_CERT_PATH to the mounted Bridge cert."
            )
        return self

    def resolve_password(self) -> str:
        """Return the Bridge app password.

        ``COMLINK_PASSWORD_COMMAND`` wins over ``COMLINK_PASSWORD``: the command is run
        through the shell and its stdout (stripped) is the password.
        """
        if self.password_command:
            try:
                # Shell execution is intentional: the command is operator-supplied
                # config (e.g. a Keychain lookup), not untrusted input.
                result = subprocess.run(
                    self.password_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=_PASSWORD_COMMAND_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ConfigError(
                    "COMLINK_PASSWORD_COMMAND timed out after "
                    f"{_PASSWORD_COMMAND_TIMEOUT_SECONDS:.0f}s. Verify the command runs "
                    "non-interactively (e.g. the Keychain item is accessible)."
                ) from exc
            if result.returncode != 0:
                # Epic 4 finding 2: when the COMMAND is the credential source,
                # self._raw_password() is None, so redacting stderr against it alone
                # would scrub nothing. The resolved secret is whatever the command
                # printed to stdout, so redact stderr against that too — a command that
                # echoes its secret to stderr before failing must not surface it here.
                stderr = redact(
                    result.stderr.strip(),
                    [self._raw_password(), result.stdout.strip()],
                )
                raise ConfigError(
                    f"COMLINK_PASSWORD_COMMAND exited with status {result.returncode}"
                    + (f": {stderr}" if stderr else "")
                    + ". Fix the command or unset it to fall back to COMLINK_PASSWORD."
                )
            password = result.stdout.strip()
            if not password:
                raise ConfigError(
                    "COMLINK_PASSWORD_COMMAND produced no output. The command must print "
                    "the Bridge app password to stdout."
                )
            return password
        if self.password is not None and self.password.get_secret_value():
            return self.password.get_secret_value()
        raise ConfigError(
            "No password configured. Set COMLINK_PASSWORD_COMMAND (preferred, e.g. a "
            "Keychain lookup) or COMLINK_PASSWORD to the Bridge app password — not the "
            "Proton account password."
        )

    def _raw_password(self) -> str | None:
        return self.password.get_secret_value() if self.password is not None else None

    def parsed_allowlist(self) -> list[str]:
        """Comma-separated allowlist → normalized list (lowercased, blanks dropped)."""
        return [item.strip().lower() for item in self.send_allowlist.split(",") if item.strip()]

    def parsed_http_allowed_hosts(self) -> list[str]:
        """Comma-separated Host allowlist → list (stripped, blanks dropped).

        Host headers are case-insensitive but preserved as written here; the
        transport-security layer compares them. Empty list disables DNS-rebinding
        protection (design doc §2 Phase 2).
        """
        return [item.strip() for item in self.http_allowed_hosts.split(",") if item.strip()]

    def build_ssl_context(self) -> ssl.SSLContext:
        """SSL context for STARTTLS against the Bridge (design doc §3.4)."""
        if self.tls_mode == "no-verify":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        cafile = str(self.tls_cert_path) if self.tls_cert_path is not None else None
        if self.tls_mode == "verify-no-hostname":
            # Pin the self-signed Bridge cert (CERT_REQUIRED, chained to cafile) but
            # skip hostname matching: Bridge issues for localhost/127.0.0.1, not the
            # in-cluster service DNS name. create_default_context leaves verify_mode at
            # CERT_REQUIRED; clearing check_hostname while CERT_REQUIRED is valid and
            # raises no error (only the inverse — CERT_NONE with check_hostname True —
            # would). cafile is guaranteed non-None by _require_cert_for_verify_no_hostname.
            context = ssl.create_default_context(cafile=cafile)
            context.check_hostname = False
            return context
        return ssl.create_default_context(cafile=cafile)


def load_settings() -> ComlinkSettings:
    """Load settings from the environment, normalizing validation errors."""
    try:
        return ComlinkSettings()
    except ValueError as exc:
        raise ConfigError(f"Invalid Comlink configuration: {exc}") from exc
