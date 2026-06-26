"""Server-level organize impls: batch-limit enforcement, audit-on-delete,
refusal-without-audit, payload shape (Epic 2, §6, §7.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from comlink.errors import ComlinkError, InvalidTarget
from comlink.models import BatchResult, UidResult
from comlink.server import (
    MAX_BATCH_UIDS,
    create_folder_impl,
    delete_messages_impl,
    mark_messages_impl,
    move_messages_impl,
)

from ..conftest import make_settings


class FakeManager:
    """Stands in for ImapConnectionManager at the impl layer."""

    def __init__(self) -> None:
        self.move_calls: list[tuple[str, str, list[int]]] = []
        self.trash_calls: list[tuple[str, list[int]]] = []
        self.mark_calls: list[tuple[str, list[int], str]] = []
        self.create_calls: list[tuple[str, str, str | None]] = []
        self.trash_raises: Exception | None = None

    async def move_messages(self, source: str, dest: str, uids: list[int]) -> BatchResult:
        self.move_calls.append((source, dest, uids))
        return BatchResult(folder=source, succeeded=list(uids))

    async def mark_messages(self, folder: str, uids: list[int], mark: str) -> BatchResult:
        self.mark_calls.append((folder, uids, mark))
        return BatchResult(folder=folder, succeeded=list(uids))

    async def move_to_trash(self, folder: str, uids: list[int]) -> BatchResult:
        if self.trash_raises is not None:
            raise self.trash_raises
        self.trash_calls.append((folder, uids))
        return BatchResult(
            folder=folder,
            succeeded=uids[:-1] if len(uids) > 1 else list(uids),
            failed=[UidResult(uid=uids[-1], ok=False, error="boom")] if len(uids) > 1 else [],
        )

    async def create_mailbox(
        self, name: str, kind: str, parent: str | None = None
    ) -> tuple[str, str | None]:
        self.create_calls.append((name, kind, parent))
        raw = f"Folders/{name}" if kind == "folder" else f"Labels/{name}"
        return raw, parent


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


class TestBatchLimits:
    async def test_move_rejects_over_limit(self) -> None:
        manager = FakeManager()
        with pytest.raises(ComlinkError, match=f"max {MAX_BATCH_UIDS}"):
            await move_messages_impl(
                manager,  # type: ignore[arg-type]
                uids=list(range(MAX_BATCH_UIDS + 1)),
                source_folder="INBOX",
                destination_folder="receipts",
            )
        assert manager.move_calls == []

    async def test_empty_uids_rejected(self) -> None:
        manager = FakeManager()
        with pytest.raises(ComlinkError, match="at least one UID"):
            await mark_messages_impl(manager, uids=[], folder="INBOX", mark="read")  # type: ignore[arg-type]


class TestMovePayload:
    async def test_move_payload_shape(self) -> None:
        manager = FakeManager()
        payload = await move_messages_impl(
            manager,  # type: ignore[arg-type]
            uids=[1, 2],
            source_folder="INBOX",
            destination_folder="receipts",
        )
        assert payload["folder"] == "INBOX"
        assert payload["succeeded"] == [1, 2]
        assert payload["destination"] == "receipts"


class TestMarkPayload:
    async def test_mark_payload_includes_mark(self) -> None:
        manager = FakeManager()
        payload = await mark_messages_impl(manager, uids=[5], folder="INBOX", mark="flagged")  # type: ignore[arg-type]
        assert payload["mark"] == "flagged"
        assert manager.mark_calls == [("INBOX", [5], "flagged")]


class TestDeleteAudit:
    async def test_successful_delete_writes_one_audit_entry(self, tmp_path: Path) -> None:
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = FakeManager()
        payload = await delete_messages_impl(
            settings,
            manager,
            uids=[1, 2],
            folder="INBOX",  # type: ignore[arg-type]
        )
        assert payload["destination"] == "Trash"
        entries = _read_audit(tmp_path / "audit.jsonl")
        assert len(entries) == 1
        assert entries[0]["action"] == "delete"
        assert entries[0]["folder"] == "INBOX"
        assert entries[0]["succeeded"] == [1]
        assert entries[0]["failed"] == [2]

    async def test_refused_delete_writes_no_audit_entry(self, tmp_path: Path) -> None:
        settings = make_settings(audit_log=tmp_path / "audit.jsonl")
        manager = FakeManager()
        manager.trash_raises = InvalidTarget.delete_from_protected("Trash")
        with pytest.raises(InvalidTarget, match="protected"):
            await delete_messages_impl(
                settings,
                manager,
                uids=[1],
                folder="Trash",  # type: ignore[arg-type]
            )
        assert _read_audit(tmp_path / "audit.jsonl") == []


class TestCreateFolder:
    async def test_folder_payload(self) -> None:
        manager = FakeManager()
        payload = await create_folder_impl(manager, name="puppy", kind="folder")  # type: ignore[arg-type]
        assert payload == {
            "name": "puppy",
            "kind": "folder",
            "raw": "Folders/puppy",
            "parent": None,
        }

    async def test_parent_with_label_rejected(self) -> None:
        manager = FakeManager()
        with pytest.raises(ComlinkError, match="Labels cannot be nested"):
            await create_folder_impl(manager, name="x", kind="label", parent="receipts")  # type: ignore[arg-type]
        assert manager.create_calls == []
