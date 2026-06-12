"""Configuration via environment variables (design doc §5).

All settings use the ``COMLINK_`` prefix. No secrets are ever logged.
"""

from __future__ import annotations

import ssl
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
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

    tls_mode: Literal["verify", "no-verify"] = "verify"
    tls_cert_path: Path | None = None

    allow_send: bool = False
    send_allowlist: str = ""
    send_max_per_hour: int = 5
    audit_log: Path = Path("~/.comlink/audit.jsonl")

    transport: Literal["stdio", "streamable-http"] = "stdio"

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
                stderr = redact(result.stderr.strip(), [self._raw_password()])
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

    def build_ssl_context(self) -> ssl.SSLContext:
        """SSL context for STARTTLS against the Bridge (design doc §3.4)."""
        if self.tls_mode == "no-verify":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        cafile = str(self.tls_cert_path) if self.tls_cert_path is not None else None
        return ssl.create_default_context(cafile=cafile)


def load_settings() -> ComlinkSettings:
    """Load settings from the environment, normalizing validation errors."""
    try:
        return ComlinkSettings()
    except ValueError as exc:
        raise ConfigError(f"Invalid Comlink configuration: {exc}") from exc
