"""Mailbox-name mapping round-trips (§3.1, §9)."""

from __future__ import annotations

import pytest

from comlink.bridge.imap import clean_mailbox_name, raw_mailbox_name
from comlink.models import MailboxKind


@pytest.mark.parametrize(
    ("raw", "name", "kind"),
    [
        ("Folders/receipts", "receipts", "folder"),
        ("Folders/puppy/vet", "puppy/vet", "folder"),
        ("Labels/newsletter", "newsletter", "label"),
        ("INBOX", "INBOX", "system"),
        ("Sent", "Sent", "system"),
        ("Drafts", "Drafts", "system"),
        ("Trash", "Trash", "system"),
        ("Spam", "Spam", "system"),
        ("Archive", "Archive", "system"),
        ("All Mail", "All Mail", "system"),
        ("Starred", "Starred", "system"),
    ],
)
def test_clean_mailbox_name(raw: str, name: str, kind: MailboxKind) -> None:
    assert clean_mailbox_name(raw) == (name, kind)


@pytest.mark.parametrize(
    "raw",
    [
        "Folders/receipts",
        "Folders/a/b/c",
        "Labels/work",
        "INBOX",
        "All Mail",
    ],
)
def test_round_trip_raw_to_clean_to_raw(raw: str) -> None:
    name, kind = clean_mailbox_name(raw)
    assert raw_mailbox_name(name, kind) == raw


@pytest.mark.parametrize(
    ("name", "kind", "raw"),
    [
        ("receipts", "folder", "Folders/receipts"),
        ("newsletter", "label", "Labels/newsletter"),
        ("INBOX", "system", "INBOX"),
    ],
)
def test_raw_mailbox_name(name: str, kind: MailboxKind, raw: str) -> None:
    assert raw_mailbox_name(name, kind) == raw


def test_folder_named_like_a_label_does_not_collide() -> None:
    # A Proton folder literally named "Labels" comes through as Folders/Labels.
    assert clean_mailbox_name("Folders/Labels") == ("Labels", "folder")
    assert raw_mailbox_name("Labels", "folder") == "Folders/Labels"
