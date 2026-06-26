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
from typing import Any, Literal, TypeVar

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
    InvalidTarget,
    redact,
)
from comlink.models import BatchResult, MailboxKind, UidResult

T = TypeVar("T")

FOLDER_PREFIX = "Folders/"
LABEL_PREFIX = "Labels/"
ALL_MAIL = "All Mail"
TRASH = "Trash"
SPAM = "Spam"

# System mailboxes that proton_delete_messages refuses to delete *from* (§7.3):
# delete already means "move to Trash", so these have no safe further destination.
PROTECTED_FROM_DELETE = frozenset({TRASH, SPAM})

SUMMARY_FETCH_KEYS = [b"ENVELOPE", b"FLAGS", b"RFC822.SIZE", b"BODYSTRUCTURE"]

# Mark → (flag, add?) mapping for proton_mark_messages (§6 Organize).
SEEN_FLAG = b"\\Seen"
FLAGGED_FLAG = b"\\Flagged"
DELETED_FLAG = b"\\Deleted"
DRAFT_FLAG = b"\\Draft"
DRAFTS = "Drafts"
MarkAction = Literal["read", "unread", "flagged", "unflagged"]
_MARK_OPS: dict[MarkAction, tuple[bytes, bool]] = {
    "read": (SEEN_FLAG, True),
    "unread": (SEEN_FLAG, False),
    "flagged": (FLAGGED_FLAG, True),
    "unflagged": (FLAGGED_FLAG, False),
}


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
    delimiter: str = "/"  # hierarchy separator from LIST, used for nesting


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
        for flags, delimiter, raw in client.list_folders():
            if any(_flag_text(flag) == "\\noselect" for flag in flags):
                continue
            raw_name = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            delim = (
                delimiter.decode("ascii", errors="replace")
                if isinstance(delimiter, bytes)
                else (delimiter or "/")
            )
            name, kind = clean_mailbox_name(raw_name)
            entries.append(MailboxEntry(raw=raw_name, name=name, kind=kind, delimiter=delim))
        return entries

    @classmethod
    def _resolve_sync(cls, client: Any, name: str) -> MailboxEntry:
        """Resolve a clean (or raw) mailbox name against a fresh server LIST."""
        return cls._resolve_in(cls._list_entries_sync(client), name)

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

    # -- write operations (§6 Organize) -------------------------------------
    #
    # COPY/move strategy (Open Question 1): imapclient.move() issues an RFC 6851
    # MOVE, which is defined as COPY + STORE \Deleted + EXPUNGE of the moved
    # messages — i.e. it expunges the source. Since I could not positively
    # confirm Bridge's MOVE avoids touching the source mailbox, and no-EXPUNGE
    # is the load-bearing safety invariant of this epic (§3, §7.3), we use
    # explicit COPY + STORE \Deleted and rely on Bridge/Proton to reconcile the
    # \Deleted source copies. expunge() is never called anywhere in this codebase.

    def _copy_and_mark_deleted(
        self, client: Any, source: MailboxEntry, destination_raw: str, uids: list[int]
    ) -> BatchResult:
        """COPY uids from the (selected) source into *destination_raw*, then flag
        the source copies \\Deleted. Per-UID so partial failures are reported.

        Three subtleties, each load-bearing:

        - COPY and the \\Deleted STORE are caught separately (§6 truthfulness). A
          *failed COPY* is a real failure (the message did not move) and leaves
          NO \\Deleted on the source — no orphaned delete. A *succeeded COPY*
          means the message DID move; if the follow-up \\Deleted STORE then
          fails, the redundant un-deleted source copy is harmless (Bridge
          reconciles \\Deleted lazily and we never expunge), so the UID is
          reported ok=True with a warning rather than failed. Reporting it failed
          would invite a retry → a second copy in the destination.
        - ``OSError``/``IMAP4.abort`` (a dropped/aborted connection) is caught
          *inside the loop* (§3.5). If it escaped, ``_call_sync`` would reconnect
          and replay the entire op, re-COPYing UIDs already moved in attempt 1 →
          duplicate messages. The reconnect-replay is safe only for idempotent
          reads, not partial mutations; a mid-batch drop is recorded as a per-UID
          failure so the dropped UIDs are reported truthfully and never replayed.
        - On a connection drop the cached client is now stale, so subsequent
          UIDs in the same batch will also fail. We drop it once detected so the
          next *tool call* reconnects cleanly.
        """
        result = BatchResult(folder=source.name)
        for uid in uids:
            try:
                client.copy([uid], destination_raw)
            except imaplib.IMAP4.error as exc:
                # COPY failed: the message did NOT move and the source has no
                # \Deleted flag set. A true per-UID failure.
                result.failed.append(
                    UidResult(uid=uid, ok=False, error=redact(str(exc), self._secrets()))
                )
                continue
            except (OSError, imaplib.IMAP4.abort) as exc:
                # Connection dropped on COPY: do NOT let this escape to the
                # reconnect-replay path (would duplicate already-moved UIDs).
                self._drop()
                result.failed.append(
                    UidResult(uid=uid, ok=False, error=redact(str(exc), self._secrets()))
                )
                continue
            # COPY succeeded — the message moved. The \Deleted STORE is best-effort.
            try:
                client.add_flags([uid], [DELETED_FLAG], silent=True)
            except imaplib.IMAP4.error as exc:
                result.succeeded.append(uid)
                result.warnings.append(
                    UidResult(
                        uid=uid,
                        ok=True,
                        warning=(
                            "Message was copied to the destination but the source could not "
                            f"be flagged \\Deleted: {redact(str(exc), self._secrets())}. The "
                            "move succeeded; the leftover source copy is harmless and reconciles "
                            "server-side. Do NOT retry — retrying would create a duplicate."
                        ),
                    )
                )
            except (OSError, imaplib.IMAP4.abort) as exc:
                self._drop()
                result.succeeded.append(uid)
                result.warnings.append(
                    UidResult(
                        uid=uid,
                        ok=True,
                        warning=(
                            "Message was copied to the destination but the connection dropped "
                            f"before the source could be flagged \\Deleted: "
                            f"{redact(str(exc), self._secrets())}. The move succeeded; the "
                            "leftover source copy is harmless. Do NOT retry — retrying would "
                            "create a duplicate."
                        ),
                    )
                )
            else:
                result.succeeded.append(uid)
        return result

    async def move_messages(self, source: str, destination: str, uids: list[int]) -> BatchResult:
        """Move messages from *source* into *destination* (a folder, never a label).

        Rejects label destinations before any server call (§3.3): "moving" into a
        label is really applying it, which is a different operation.
        """

        def op(client: Any) -> BatchResult:
            entries = self._list_entries_sync(client)
            source_entry = self._resolve_in(entries, source)
            dest_entry = self._resolve_in(entries, destination)
            if dest_entry.kind == "label":
                raise InvalidTarget.label_move(dest_entry.name)
            client.select_folder(source_entry.raw, readonly=False)
            return self._copy_and_mark_deleted(client, source_entry, dest_entry.raw, uids)

        return await self._call(op)

    async def mark_messages(self, folder: str, uids: list[int], mark: MarkAction) -> BatchResult:
        """Add or remove the \\Seen / \\Flagged flag on *uids*. Idempotent."""
        flag, add = _MARK_OPS[mark]

        def op(client: Any) -> BatchResult:
            entry = self._resolve_sync(client, folder)
            client.select_folder(entry.raw, readonly=False)
            result = BatchResult(folder=entry.name)
            for uid in uids:
                try:
                    if add:
                        client.add_flags([uid], [flag], silent=True)
                    else:
                        client.remove_flags([uid], [flag], silent=True)
                except imaplib.IMAP4.error as exc:
                    result.failed.append(
                        UidResult(uid=uid, ok=False, error=redact(str(exc), self._secrets()))
                    )
                else:
                    result.succeeded.append(uid)
            return result

        return await self._call(op)

    async def move_to_trash(self, folder: str, uids: list[int]) -> BatchResult:
        """Delete = move to Trash (§7.3). Refuses to delete from Trash or Spam."""

        def op(client: Any) -> BatchResult:
            entries = self._list_entries_sync(client)
            source_entry = self._resolve_in(entries, folder)
            if source_entry.kind == "system" and source_entry.name in PROTECTED_FROM_DELETE:
                raise InvalidTarget.delete_from_protected(source_entry.name)
            trash_entry = self._resolve_in(entries, TRASH)
            client.select_folder(source_entry.raw, readonly=False)
            return self._copy_and_mark_deleted(client, source_entry, trash_entry.raw, uids)

        return await self._call(op)

    async def create_mailbox(
        self, name: str, kind: MailboxKind, parent: str | None = None
    ) -> tuple[str, str | None]:
        """Create a folder or label under the correct namespace (§3.1).

        Returns (raw mailbox name created, clean parent name or None). Labels
        cannot be nested. Folder nesting under *parent* uses the server's LIST
        delimiter captured per entry.
        """

        def op(client: Any) -> tuple[str, str | None]:
            entries = self._list_entries_sync(client)
            parent_clean: str | None = None
            if parent is not None:
                parent_entry = self._resolve_in(entries, parent)
                if parent_entry.kind != "folder":
                    raise InvalidTarget(
                        f"'{parent_entry.name}' is a {parent_entry.kind}, not a folder — "
                        "only folders can have subfolders. Pass a folder as parent or omit it."
                    )
                # DESIGN-GAP (Open Question 2): nest using the server LIST delimiter
                # on the parent's raw name (already namespaced). The flat path is
                # the verified one; this branch is gated behind the server-side
                # delimiter rather than guessing.
                raw = f"{parent_entry.raw}{parent_entry.delimiter}{name}"
                parent_clean = parent_entry.name
            else:
                raw = raw_mailbox_name(name, kind)
            existing = {entry.raw for entry in entries} | {entry.name for entry in entries}
            if raw in existing:
                raise InvalidTarget(
                    f"A {kind} named '{name}' already exists. Pick a different name or use "
                    "the existing one (see proton_list_folders)."
                )
            try:
                client.create_folder(raw)
            except imaplib.IMAP4.error as exc:
                message = redact(str(exc), self._secrets())
                if "exist" in message.lower():
                    raise InvalidTarget(
                        f"A {kind} named '{name}' already exists. Pick a different name or "
                        "use the existing one (see proton_list_folders)."
                    ) from exc
                raise ComlinkError(
                    f"Bridge refused to create {kind} '{name}': {message}. Folder/label names "
                    "must be valid Proton mailbox names."
                ) from exc
            return raw, parent_clean

        return await self._call(op)

    async def append_draft(self, raw_bytes: bytes, message_id: str) -> int:
        """APPEND *raw_bytes* to Drafts with the \\Draft flag; return its UID.

        UID recovery does NOT rely on APPENDUID (Echo intel: Bridge's APPEND
        response is not a reliable source for the new UID). Instead the message
        already carries a unique Message-ID (set at build time in
        :func:`build_message`); within the SAME locked op we SELECT Drafts and
        SEARCH ``HEADER Message-ID <id>``, returning the highest matching UID.
        The Drafts mailbox is resolved via LIST rather than hardcoded so the
        Bridge's actual raw name is used.
        """

        def op(client: Any) -> int:
            entry = self._resolve_in(self._list_entries_sync(client), DRAFTS)
            client.append(entry.raw, raw_bytes, flags=[DRAFT_FLAG])
            client.select_folder(entry.raw, readonly=True)
            uids = client.search(["HEADER", "Message-ID", message_id])
            if not uids:
                raise ComlinkError(
                    "Draft was appended to Drafts but could not be located by its "
                    "Message-ID afterwards. Check the Drafts mailbox in a Proton client; "
                    "do not retry blindly (a retry may create a duplicate draft)."
                )
            return max(int(uid) for uid in uids)

        return await self._call(op)

    @classmethod
    def _resolve_in(cls, entries: list[MailboxEntry], name: str) -> MailboxEntry:
        """Resolve a clean (or raw) name against an already-fetched LIST."""
        for entry in entries:
            if name in (entry.name, entry.raw):
                return entry
        lowered = name.lower()
        for entry in entries:
            if lowered in (entry.name.lower(), entry.raw.lower()):
                return entry
        raise FolderNotFound.for_name(name, [entry.name for entry in entries])


def _flag_text(flag: object) -> str:
    if isinstance(flag, bytes):
        return flag.decode("ascii", errors="replace").lower()
    return str(flag).lower()
