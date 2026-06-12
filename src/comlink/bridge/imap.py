"""IMAP connection manager and mailbox-name mapping (design doc §3, §4).

- ``imapclient`` is synchronous; every operation is offloaded with
  ``anyio.to_thread.run_sync`` and serialized behind a lock (IMAP connections
  are not concurrency-safe).
- Connects lazily, reconnects once on dropped connections.
- STARTTLS with ``verify`` (pinned cert via ``COMLINK_TLS_CERT_PATH``) or
  ``no-verify`` (localhost only, enforced at config validation).
- UIDVALIDITY rule (§3.5): UIDs are never cached across calls — every
  operation re-selects its mailbox within a single locked call.
"""

from __future__ import annotations

import contextlib
import imaplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from typing import Any, TypeVar

import anyio
import anyio.to_thread
from imapclient import IMAPClient
from imapclient.exceptions import LoginError

from comlink.config import ComlinkSettings
from comlink.errors import (
    AuthFailed,
    BridgeUnavailable,
    ComlinkError,
    ConfigError,
    FolderNotFound,
    redact,
)
from comlink.models import MailboxKind

T = TypeVar("T")

FOLDER_PREFIX = "Folders/"
LABEL_PREFIX = "Labels/"
ALL_MAIL = "All Mail"

SUMMARY_FETCH_KEYS = [b"ENVELOPE", b"FLAGS", b"RFC822.SIZE", b"BODYSTRUCTURE"]


# ---------------------------------------------------------------------------
# Mailbox-name mapping (§3.1)
# ---------------------------------------------------------------------------


def clean_mailbox_name(raw: str) -> tuple[str, MailboxKind]:
    """Bridge raw name → (clean name, kind). ``Folders/receipts`` → ``receipts``."""
    if raw.startswith(FOLDER_PREFIX):
        return raw[len(FOLDER_PREFIX) :], "folder"
    if raw.startswith(LABEL_PREFIX):
        return raw[len(LABEL_PREFIX) :], "label"
    return raw, "system"


def raw_mailbox_name(clean: str, kind: MailboxKind) -> str:
    """(clean name, kind) → Bridge raw name. Inverse of :func:`clean_mailbox_name`."""
    if kind == "folder":
        return FOLDER_PREFIX + clean
    if kind == "label":
        return LABEL_PREFIX + clean
    return clean


@dataclass(slots=True)
class MailboxEntry:
    raw: str
    name: str
    kind: MailboxKind


@dataclass(slots=True)
class MailboxStatus:
    raw: str
    name: str
    kind: MailboxKind
    message_count: int
    unread_count: int


# ---------------------------------------------------------------------------
# Search criteria (§6)
# ---------------------------------------------------------------------------


def _parse_iso_date(value: str, param: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ComlinkError(
            f"Invalid {param!r} value {value!r}: expected an ISO date like 2026-06-01."
        ) from exc


def build_search_criteria(
    *,
    query: str | None = None,
    from_: str | None = None,
    to: str | None = None,
    subject: str | None = None,
    since: str | None = None,
    before: str | None = None,
    unread_only: bool = False,
    flagged_only: bool = False,
) -> list[Any]:
    """Translate tool parameters into IMAP SEARCH criteria."""
    criteria: list[Any] = []
    if unread_only:
        criteria.append("UNSEEN")
    if flagged_only:
        criteria.append("FLAGGED")
    if query:
        criteria.extend(["TEXT", query])
    if from_:
        criteria.extend(["FROM", from_])
    if to:
        criteria.extend(["TO", to])
    if subject:
        criteria.extend(["SUBJECT", subject])
    if since:
        criteria.extend(["SINCE", _parse_iso_date(since, "since")])
    if before:
        criteria.extend(["BEFORE", _parse_iso_date(before, "before")])
    if not criteria:
        criteria.append("ALL")
    return criteria


# ---------------------------------------------------------------------------
# Connection manager
# ---------------------------------------------------------------------------


class ImapConnectionManager:
    """Lazy, lock-serialized, thread-offloaded IMAP connection to the Bridge."""

    def __init__(self, settings: ComlinkSettings) -> None:
        self._settings = settings
        self._lock = anyio.Lock()
        self._client: Any | None = None
        self._password: str | None = None

    # -- plumbing -----------------------------------------------------------

    async def _call(self, func: Callable[[Any], T]) -> T:
        """Run *func(client)* in a worker thread, holding the connection lock."""
        async with self._lock:
            return await anyio.to_thread.run_sync(self._call_sync, func)

    def _call_sync(self, func: Callable[[Any], T]) -> T:
        client = self._ensure_connected()
        try:
            return func(client)
        except (OSError, imaplib.IMAP4.abort):
            # Connection dropped — reconnect once and retry (§ Epic 0).
            self._drop()
            client = self._ensure_connected()
            return func(client)

    def _secrets(self) -> list[str | None]:
        raw = self._settings.password.get_secret_value() if self._settings.password else None
        return [self._password, raw]

    def _ensure_connected(self) -> Any:
        if self._client is not None:
            return self._client
        settings = self._settings
        if not settings.username:
            raise ConfigError(
                "COMLINK_USERNAME is not set. Set it to the Bridge username shown in "
                "Bridge → Mailbox details."
            )
        if self._password is None:
            self._password = settings.resolve_password()
        try:
            client = IMAPClient(settings.imap_host, port=settings.imap_port, ssl=False, timeout=15)
        except OSError as exc:
            raise BridgeUnavailable.for_endpoint(
                settings.imap_host, settings.imap_port, "IMAP"
            ) from exc
        try:
            client.starttls(settings.build_ssl_context())
            client.login(settings.username, self._password)
        except LoginError as exc:
            self._shutdown_quietly(client)
            raise AuthFailed.imap() from exc
        except ssl.SSLError as exc:
            self._shutdown_quietly(client)
            raise ComlinkError(
                "TLS handshake with the Bridge failed: "
                f"{redact(str(exc), self._secrets())}. If the Bridge certificate rotated, "
                "update COMLINK_TLS_CERT_PATH (Bridge → Settings → Advanced → Export TLS "
                "certificates)."
            ) from exc
        except OSError as exc:
            self._shutdown_quietly(client)
            raise BridgeUnavailable.for_endpoint(
                settings.imap_host, settings.imap_port, "IMAP"
            ) from exc
        except imaplib.IMAP4.error as exc:
            self._shutdown_quietly(client)
            raise ComlinkError(f"IMAP setup failed: {redact(str(exc), self._secrets())}") from exc
        self._client = client
        return client

    @staticmethod
    def _shutdown_quietly(client: Any) -> None:
        # Best-effort cleanup; the socket may already be gone.
        with contextlib.suppress(Exception):
            client.shutdown()

    def _drop(self) -> None:
        if self._client is not None:
            self._shutdown_quietly(self._client)
            self._client = None

    async def aclose(self) -> None:
        async with self._lock:
            await anyio.to_thread.run_sync(self._drop)

    # -- sync helpers (run inside the worker thread) -------------------------

    @staticmethod
    def _list_entries_sync(client: Any) -> list[MailboxEntry]:
        entries: list[MailboxEntry] = []
        for flags, _delimiter, raw in client.list_folders():
            if any(_flag_text(flag) == "\\noselect" for flag in flags):
                continue
            raw_name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            name, kind = clean_mailbox_name(raw_name)
            entries.append(MailboxEntry(raw=raw_name, name=name, kind=kind))
        return entries

    @classmethod
    def _resolve_sync(cls, client: Any, name: str) -> MailboxEntry:
        """Resolve a clean (or raw) mailbox name against a fresh server LIST."""
        entries = cls._list_entries_sync(client)
        for entry in entries:
            if name in (entry.name, entry.raw):
                return entry
        lowered = name.lower()
        for entry in entries:
            if lowered in (entry.name.lower(), entry.raw.lower()):
                return entry
        raise FolderNotFound.for_name(name, [entry.name for entry in entries])

    # -- operations ----------------------------------------------------------

    async def verify_connectivity(self) -> int:
        """Connect + LIST. Returns mailbox count (health check)."""

        def op(client: Any) -> int:
            return len(self._list_entries_sync(client))

        return await self._call(op)

    async def list_mailboxes(self) -> list[MailboxStatus]:
        """All selectable mailboxes with clean names, kinds, and counts."""

        def op(client: Any) -> list[MailboxStatus]:
            statuses: list[MailboxStatus] = []
            for entry in self._list_entries_sync(client):
                try:
                    status = client.folder_status(entry.raw, [b"MESSAGES", b"UNSEEN"])
                except imaplib.IMAP4.error:
                    status = {}
                statuses.append(
                    MailboxStatus(
                        raw=entry.raw,
                        name=entry.name,
                        kind=entry.kind,
                        message_count=int(status.get(b"MESSAGES", 0)),
                        unread_count=int(status.get(b"UNSEEN", 0)),
                    )
                )
            return statuses

        return await self._call(op)

    async def fetch_summary_page(
        self, folder: str, criteria: list[Any], *, limit: int, offset: int
    ) -> tuple[str, int, list[tuple[int, dict[bytes, Any]]]]:
        """Search one mailbox and fetch one page of summaries, newest-first.

        Resolution, SELECT, SEARCH, and FETCH all happen within a single locked
        call so UIDs are only ever used inside the selection that produced them
        (§3.5). Returns (clean folder name, total matches, page of fetch data).
        """

        def op(client: Any) -> tuple[str, int, list[tuple[int, dict[bytes, Any]]]]:
            entry = self._resolve_sync(client, folder)
            client.select_folder(entry.raw, readonly=True)
            uids = sorted(client.search(criteria), reverse=True)
            total = len(uids)
            page_uids = uids[offset : offset + limit]
            fetched: dict[int, dict[bytes, Any]] = (
                client.fetch(page_uids, SUMMARY_FETCH_KEYS) if page_uids else {}
            )
            return entry.name, total, [(uid, fetched.get(uid, {})) for uid in page_uids]

        return await self._call(op)

    async def search_mailboxes(
        self, criteria: list[Any], *, folder: str | None, cap: int
    ) -> list[tuple[str, int, dict[bytes, Any]]]:
        """Search sequentially across mailboxes, returning fetch data per hit.

        Default scope is every real folder and system mailbox, **excluding All
        Mail** (§3.2 — it is a virtual view that would duplicate every hit) and
        excluding labels (labelled messages already live in a real folder).
        """

        def op(client: Any) -> list[tuple[str, int, dict[bytes, Any]]]:
            if folder is not None:
                targets = [self._resolve_sync(client, folder)]
            else:
                targets = [
                    entry
                    for entry in self._list_entries_sync(client)
                    if entry.kind == "folder" or (entry.kind == "system" and entry.name != ALL_MAIL)
                ]
            results: list[tuple[str, int, dict[bytes, Any]]] = []
            for entry in targets:
                if len(results) >= cap:
                    break
                try:
                    client.select_folder(entry.raw, readonly=True)
                    uids = sorted(client.search(criteria), reverse=True)
                except imaplib.IMAP4.error:
                    continue
                budget = cap - len(results)
                page_uids = uids[:budget]
                if not page_uids:
                    continue
                fetched: dict[int, dict[bytes, Any]] = client.fetch(page_uids, SUMMARY_FETCH_KEYS)
                results.extend((entry.name, uid, fetched.get(uid, {})) for uid in page_uids)
            return results

        return await self._call(op)

    async def fetch_raw_message(self, folder: str, uid: int) -> tuple[str, bytes, Any]:
        """Fetch one full message body (BODY.PEEK — never sets ``\\Seen``)."""

        def op(client: Any) -> tuple[str, bytes, Any]:
            entry = self._resolve_sync(client, folder)
            client.select_folder(entry.raw, readonly=True)
            fetched: dict[int, dict[bytes, Any]] = client.fetch([uid], [b"BODY.PEEK[]", b"FLAGS"])
            data = fetched.get(uid)
            body = data.get(b"BODY[]") if data else None
            if not isinstance(body, bytes):
                raise ComlinkError(
                    f"UID {uid} not found in '{entry.name}'. UIDs are only valid within "
                    "the session that produced them — re-run proton_list_messages and "
                    "retry with a fresh UID."
                )
            return entry.name, body, (data or {}).get(b"FLAGS", ())

        return await self._call(op)


def _flag_text(flag: object) -> str:
    if isinstance(flag, bytes):
        return flag.decode("ascii", errors="replace").lower()
    return str(flag).lower()
