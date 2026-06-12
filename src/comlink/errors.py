"""Error taxonomy (design doc §8) and secret redaction helpers.

Every error message tells the agent what to do next.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable

REDACTED = "[REDACTED]"


class ComlinkError(Exception):
    """Base class for all Comlink errors. The message is agent-actionable."""


class ConfigError(ComlinkError):
    """Configuration is missing or invalid (env vars, password resolution)."""


class BridgeUnavailable(ComlinkError):
    """Proton Mail Bridge is not reachable."""

    @classmethod
    def for_endpoint(cls, host: str, port: int, protocol: str = "IMAP") -> BridgeUnavailable:
        return cls(
            f"Proton Mail Bridge does not appear to be running on {host}:{port} ({protocol}). "
            "Start the Bridge app and retry."
        )


class AuthFailed(ComlinkError):
    """Bridge rejected the credentials."""

    @classmethod
    def imap(cls) -> AuthFailed:
        return cls(
            "IMAP login rejected. The Bridge app password may have rotated — open Bridge → "
            "Mailbox details and update COMLINK_PASSWORD (or the secret behind "
            "COMLINK_PASSWORD_COMMAND)."
        )

    @classmethod
    def smtp(cls) -> AuthFailed:
        return cls(
            "SMTP login rejected. The Bridge app password may have rotated — open Bridge → "
            "Mailbox details and update COMLINK_PASSWORD (or the secret behind "
            "COMLINK_PASSWORD_COMMAND)."
        )


class FolderNotFound(ComlinkError):
    """A named mailbox does not exist on the server."""

    @classmethod
    def for_name(cls, name: str, known_names: Iterable[str]) -> FolderNotFound:
        suggestions = difflib.get_close_matches(name, list(known_names), n=3, cutoff=0.5)
        hint = f"Closest matches: {', '.join(suggestions)}." if suggestions else "No close matches."
        return cls(
            f"Folder '{name}' not found. {hint} Use proton_list_folders to confirm "
            "available mailboxes."
        )


class InvalidTarget(ComlinkError):
    """Operation targeted the wrong kind of mailbox (e.g. moving into a label)."""


class SendBlocked(ComlinkError):
    """A send guardrail (gate, allowlist, or rate limit) blocked the operation."""


class UidStale(ComlinkError):
    """UIDVALIDITY changed; cached UIDs are no longer meaningful."""

    @classmethod
    def for_folder(cls, folder: str) -> UidStale:
        return cls(
            f"UID set is stale for {folder} (UIDVALIDITY changed). Re-run "
            "proton_list_messages and retry with fresh UIDs."
        )


def redact(text: str, secrets: Iterable[str | None]) -> str:
    """Scrub every secret out of *text* before it leaves the server.

    Empty/None secrets are ignored so we never replace the empty string.
    """
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def redacted_message(exc: BaseException, secrets: Iterable[str | None]) -> str:
    """Return ``str(exc)`` with all secrets scrubbed."""
    return redact(str(exc), secrets)
