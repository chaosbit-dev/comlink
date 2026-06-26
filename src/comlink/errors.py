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

    @classmethod
    def label_move(cls, name: str) -> InvalidTarget:
        return cls(
            f"'{name}' is a label, not a folder — messages can't be moved into labels. "
            "Labels coexist with folders in Proton. Use proton_label_messages (v1.1) or "
            "apply the label in a Proton client."
        )

    @classmethod
    def delete_from_protected(cls, folder: str) -> InvalidTarget:
        return cls(
            f"Refusing to delete from '{folder}': Trash and Spam are protected — delete "
            "already means 'move to Trash', and there is no further safe destination. To "
            "empty Trash or Spam, use a Proton client (web or iOS)."
        )


class SendBlocked(ComlinkError):
    """A send guardrail (gate, allowlist, or rate limit) blocked the operation.

    Each factory names the specific guardrail that fired and how to change it (§8).
    """

    @classmethod
    def not_allowlisted(cls, addr: str) -> SendBlocked:
        return cls(
            f"Recipient {addr} not in COMLINK_SEND_ALLOWLIST. Add the address (or a "
            "'*@domain' wildcard) to COMLINK_SEND_ALLOWLIST, or leave the allowlist empty "
            "to permit any recipient (not recommended)."
        )

    @classmethod
    def rate_limited(cls, max_per_hour: int, retry_after: int) -> SendBlocked:
        return cls(
            f"Send rate limit reached: {max_per_hour} message(s) per hour "
            "(COMLINK_SEND_MAX_PER_HOUR). Wait about "
            f"{retry_after} second(s) and retry, or raise COMLINK_SEND_MAX_PER_HOUR."
        )

    @classmethod
    def confirm_not_asserted(cls) -> SendBlocked:
        return cls(
            "Send blocked: confirm must be set to true to send. proton_send_message will "
            "not send without an explicit confirm=true — set it only when a human has "
            "approved this exact outbound message, or use proton_save_draft instead."
        )


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
