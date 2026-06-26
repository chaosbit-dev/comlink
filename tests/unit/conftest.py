"""Shared unit-test fakes and fixtures.

These behavioral fakes (`FakeBridgeState`, `FakeIMAPClient`), the `bridge`
fixture, and the `make_manager` factory are used by more than one unit-test
module (the manager tests and the Epic 2 organize/adversarial tests). They live
here so the `bridge` fixture is discovered by pytest rather than imported into
each module — importing a fixture and then using it as a test parameter trips
Ruff's F811 (redefinition) in the consuming module.
"""

from __future__ import annotations

import imaplib
from dataclasses import dataclass, field
from typing import Any

import pytest
from imapclient.exceptions import LoginError

import comlink.bridge.imap as imap_module
from comlink.bridge.imap import ImapConnectionManager

from ..conftest import make_settings

DEFAULT_FOLDERS: list[tuple[tuple[bytes, ...], str]] = [
    ((), "INBOX"),
    ((), "Sent"),
    ((), "All Mail"),
    ((), "Folders/receipts"),
    ((), "Labels/news"),
    ((b"\\Noselect",), "Folders"),
]


@dataclass
class FakeBridgeState:
    folders: list[tuple[tuple[bytes, ...], str]] = field(
        default_factory=lambda: list(DEFAULT_FOLDERS)
    )
    counts: dict[str, tuple[int, int]] = field(default_factory=dict)
    search_uids: dict[str, list[int]] = field(default_factory=dict)
    raw_messages: dict[tuple[str, int], bytes] = field(default_factory=dict)
    refuse_connection: bool = False
    fail_login: bool = False
    drop_ops: int = 0  # raise OSError on this many subsequent operations
    clients: list[FakeIMAPClient] = field(default_factory=list)
    # Write-op recorders + fault injection (Epic 2).
    copies: list[tuple[list[int], str]] = field(default_factory=list)
    moves: list[tuple[list[int], str]] = field(default_factory=list)
    expunges: int = 0
    added_flags: list[tuple[list[int], list[bytes]]] = field(default_factory=list)
    removed_flags: list[tuple[list[int], list[bytes]]] = field(default_factory=list)
    created_folders: list[str] = field(default_factory=list)
    fail_copy_uids: set[int] = field(default_factory=set)
    create_error: str | None = None
    # APPEND recorder (Epic 3 drafts): (mailbox, raw_bytes, flags).
    appended: list[tuple[str, bytes, list[bytes]]] = field(default_factory=list)
    # Message-ID → UIDs the next HEADER Message-ID search should return.
    message_id_uids: dict[str, list[int]] = field(default_factory=dict)
    # UIDs whose COPY raises an IMAP error carrying this text (redaction probe).
    copy_error_text: dict[int, str] = field(default_factory=dict)
    # UIDs whose COPY raises OSError mid-loop (connection-drop probe, §3.5).
    drop_on_copy_uids: set[int] = field(default_factory=set)
    # UIDs whose \Deleted add_flags raises this IMAP error text (COPY-ok/STORE-fail).
    store_error_text: dict[int, str] = field(default_factory=dict)


class FakeIMAPClient:
    def __init__(self, state: FakeBridgeState) -> None:
        self.state = state
        self.selected: str | None = None
        self.selects: list[tuple[str, bool]] = []
        self.starttls_called = False
        self.logged_in = False
        self.shutdown_called = False

    def _maybe_drop(self) -> None:
        if self.state.drop_ops > 0:
            self.state.drop_ops -= 1
            raise OSError("connection dropped")

    def starttls(self, ssl_context: object) -> None:
        self.starttls_called = True

    def login(self, username: str, password: str) -> None:
        if self.state.fail_login:
            raise LoginError("LOGIN command error: BAD credentials")
        self.logged_in = True

    def list_folders(self) -> list[tuple[tuple[bytes, ...], bytes, str]]:
        self._maybe_drop()
        return [(flags, b"/", name) for flags, name in self.state.folders]

    def folder_status(self, name: str, what: list[bytes]) -> dict[bytes, int]:
        messages, unseen = self.state.counts.get(name, (0, 0))
        return {b"MESSAGES": messages, b"UNSEEN": unseen}

    def select_folder(self, name: str, readonly: bool = False) -> dict[bytes, Any]:
        self._maybe_drop()
        self.selected = name
        self.selects.append((name, readonly))
        return {}

    def search(self, criteria: list[Any]) -> list[int]:
        assert self.selected is not None
        if len(criteria) == 3 and criteria[0] == "HEADER" and criteria[1] == "Message-ID":
            return list(self.state.message_id_uids.get(criteria[2], []))
        return list(self.state.search_uids.get(self.selected, []))

    def append(self, mailbox: str, raw_bytes: bytes, flags: list[bytes] | None = None) -> str:
        self.state.appended.append((mailbox, raw_bytes, list(flags or [])))
        return "OK"

    def fetch(self, uids: list[int], keys: list[bytes]) -> dict[int, dict[bytes, Any]]:
        assert self.selected is not None
        result: dict[int, dict[bytes, Any]] = {}
        for uid in uids:
            if b"BODY.PEEK[]" in keys:
                raw = self.state.raw_messages.get((self.selected, uid))
                if raw is not None:
                    result[uid] = {b"BODY[]": raw, b"FLAGS": (b"\\Seen",)}
            else:
                result[uid] = {b"FLAGS": (), b"RFC822.SIZE": 100 + uid}
        return result

    def copy(self, uids: list[int], destination: str) -> None:
        assert self.selected is not None
        if any(uid in self.state.drop_on_copy_uids for uid in uids):
            raise OSError("connection dropped during COPY")
        for uid in uids:
            text = self.state.copy_error_text.get(uid)
            if text is not None:
                raise imaplib.IMAP4.error(text)
        if any(uid in self.state.fail_copy_uids for uid in uids):
            raise imaplib.IMAP4.error("COPY failed: over quota")
        self.state.copies.append((list(uids), destination))

    def move(self, uids: list[int], destination: str) -> None:
        # Recorded only so the no-EXPUNGE guard test can assert move() is unused.
        self.state.moves.append((list(uids), destination))

    def expunge(self, *args: Any, **kwargs: Any) -> None:
        # No-EXPUNGE is the load-bearing invariant of Epic 2 (§3, §7.3). This must
        # never be called; if production code ever invokes it, fail loudly.
        self.state.expunges += 1
        raise AssertionError("expunge() must never be called (no-EXPUNGE invariant)")

    def add_flags(self, uids: list[int], flags: list[bytes], silent: bool = False) -> None:
        assert self.selected is not None
        for uid in uids:
            text = self.state.store_error_text.get(uid)
            if text is not None:
                raise imaplib.IMAP4.error(text)
        self.state.added_flags.append((list(uids), list(flags)))

    def remove_flags(self, uids: list[int], flags: list[bytes], silent: bool = False) -> None:
        assert self.selected is not None
        self.state.removed_flags.append((list(uids), list(flags)))

    def create_folder(self, name: str) -> str:
        if self.state.create_error is not None:
            raise imaplib.IMAP4.error(self.state.create_error)
        self.state.created_folders.append(name)
        self.state.folders.append(((), name))
        return "OK"

    def shutdown(self) -> None:
        self.shutdown_called = True

    def logout(self) -> None:
        self.shutdown_called = True


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch) -> FakeBridgeState:
    state = FakeBridgeState()

    def factory(host: str, port: int = 143, ssl: bool = True, timeout: int | None = None) -> Any:
        if state.refuse_connection:
            raise ConnectionRefusedError("connection refused")
        client = FakeIMAPClient(state)
        state.clients.append(client)
        return client

    monkeypatch.setattr(imap_module, "IMAPClient", factory)
    return state


def make_manager() -> ImapConnectionManager:
    return ImapConnectionManager(make_settings())
