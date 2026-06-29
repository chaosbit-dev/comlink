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


class UidResult(ComlinkModel):
    """Per-UID outcome of an organize op. Captures partial success (§6 Organize).

    ``error`` carries failure text on ``ok=False`` entries (e.g. a failed COPY).
    ``warning`` carries an advisory note on ``ok=True`` entries — used when an op
    succeeded in its load-bearing step but a best-effort follow-up did not (e.g.
    COPY succeeded but the source ``\\Deleted`` flag could not be set; the move
    still happened, so the UID is reported ok with a warning rather than failed,
    which would invite a duplicate-creating retry — §6 truthfulness, §3.5).
    """

    uid: int
    ok: bool
    error: str | None = None
    warning: str | None = None


class BatchResult(ComlinkModel):
    """Aggregate of a per-UID organize op over one folder.

    ``succeeded``/``failed`` are kept separate so partial success is never
    collapsed to a single boolean (§6 Organize, §10 Epic 2 acceptance).
    ``warnings`` holds ``ok=True`` UidResults whose primary step succeeded but a
    best-effort follow-up did not; those UIDs are also present in ``succeeded``
    (the move happened) — the warning is advisory only, never a failure.
    """

    folder: str
    succeeded: list[int] = Field(default_factory=list)
    failed: list[UidResult] = Field(default_factory=list)
    warnings: list[UidResult] = Field(default_factory=list)


class FolderCreated(ComlinkModel):
    """Result of proton_create_folder (§6 Organize)."""

    name: str
    kind: MailboxKind
    raw: str
    parent: str | None = None


class DraftCreated(ComlinkModel):
    """Result of proton_save_draft (§6 Compose).

    ``bcc_dropped`` surfaces a deliberate data-loss semantic: a draft has no SMTP
    envelope, and build_message never serializes a Bcc header (so Bcc can't leak to
    To/Cc recipients — §6, Bcc-never-in-header). A draft saved with a Bcc-only
    recipient therefore cannot carry that recipient anywhere, so it is dropped rather
    than silently swallowed. This field lists ONLY the genuinely-dropped Bcc
    addresses: a Bcc address that is also a To or Cc recipient is still delivered via
    its visible header and is excluded from the list (case-insensitive match,
    de-duplicated within Bcc, original order preserved). The list is empty when no
    Bcc recipient is lost. The caller can warn the user or re-send via
    proton_send_message, which honors Bcc through the envelope. The draft is never
    rejected over Bcc.
    """

    uid: int
    folder: str = "Drafts"
    subject: str = ""
    message_id: str
    bcc_dropped: list[str] = Field(default_factory=list)


class SendResult(ComlinkModel):
    """Result of proton_send_message (§6 Compose, §7 gated send)."""

    message_id: str
    recipients: list[str] = Field(default_factory=list)


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
    # When true, only the five read tools are registered; all write/organize/
    # compose tools (including the send gate) are invisible to the client (§7.1
    # registration-time gating, mirrored for read-only mode).
    read_only: bool = False
    send_gate: SendGateStatus
