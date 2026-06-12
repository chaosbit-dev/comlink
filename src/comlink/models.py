"""Pydantic I/O models (design doc §4, §6)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MailboxKind = Literal["folder", "label", "system"]


class ComlinkModel(BaseModel):
    """Base model with house-standard config."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)


class MailboxInfo(ComlinkModel):
    """A mailbox as presented to the model: clean name plus kind (§3.1)."""

    name: str
    kind: MailboxKind
    message_count: int
    unread_count: int


class MessageFlags(ComlinkModel):
    read: bool = False
    flagged: bool = False
    answered: bool = False


class MessageSummary(ComlinkModel):
    """Envelope summary returned by list/search tools (§6)."""

    uid: int
    folder: str
    from_: str = Field(alias="from", default="")
    to: list[str] = Field(default_factory=list)
    subject: str = ""
    date: str | None = None
    flags: MessageFlags = Field(default_factory=MessageFlags)
    has_attachments: bool = False
    size: int = 0


class AttachmentInfo(ComlinkModel):
    """Attachment metadata only — never content (§6, non-goal §1)."""

    filename: str
    content_type: str
    size: int


class MessageDetail(ComlinkModel):
    """Full message view returned by proton_get_message (§6)."""

    uid: int
    folder: str
    from_: str = Field(alias="from", default="")
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date: str | None = None
    flags: MessageFlags = Field(default_factory=MessageFlags)
    body: str = ""
    body_offset: int = 0
    body_total_chars: int = 0
    truncated: bool = False
    next_body_offset: int | None = None
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    list_unsubscribe: str | None = None
    headers: dict[str, str] | None = None


class SendGateStatus(ComlinkModel):
    enabled: bool
    allowlist_size: int
    max_per_hour: int
    remaining_this_hour: int


class EndpointStatus(ComlinkModel):
    ok: bool
    error: str | None = None


class HealthReport(ComlinkModel):
    """proton_health_check output (§6 Diagnostics)."""

    bridge_reachable: bool
    imap: EndpointStatus
    smtp: EndpointStatus
    account: str
    folder_count: int | None = None
    send_gate: SendGateStatus
