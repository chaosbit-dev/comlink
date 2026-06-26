"""RFC 5322 builder + reply-header derivation (Epic 3, Task 2; §6 Compose).

Pure functions, no I/O: build_message and reply_headers_from.
"""

from __future__ import annotations

from comlink.bridge.parsing import build_message, parse_email, reply_headers_from


class TestBuildMessage:
    def test_single_part_text_plain_with_headers(self) -> None:
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["kendra@chaosbit.dev"],
            cc=["mom@example.com"],
            bcc=[],
            subject="Dinner",
            body_text="What's the plan?",
        )
        assert msg.get_content_type() == "text/plain"
        assert not msg.is_multipart()
        assert msg["From"] == "brandon@chaosbit.dev"
        assert msg["To"] == "kendra@chaosbit.dev"
        assert msg["Cc"] == "mom@example.com"
        assert msg["Subject"] == "Dinner"
        assert msg.get_content().strip() == "What's the plan?"

    def test_message_id_and_date_set_at_build_time(self) -> None:
        # stdlib does NOT auto-populate these — we set them explicitly (Echo intel).
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["a@b.com"],
            subject="x",
            body_text="y",
        )
        assert msg["Message-ID"] is not None
        # Message-ID domain is derived from the sender address.
        assert msg["Message-ID"].endswith("@chaosbit.dev>")
        assert msg["Date"] is not None

    def test_message_id_domain_from_named_address(self) -> None:
        msg = build_message(
            from_addr="Brandon Luttrell <brandon@chaosbit.dev>",
            to=["a@b.com"],
            subject="x",
            body_text="y",
        )
        assert msg["Message-ID"].endswith("@chaosbit.dev>")

    def test_unicode_subject_is_encoded(self) -> None:
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["a@b.com"],
            subject="Café — résumé ☕",
            body_text="body",
        )
        raw = msg.as_bytes()
        # Header must be ASCII-safe on the wire (RFC 2047 encoded).
        assert raw.isascii()
        # And round-trips back to the original Unicode.
        reparsed = parse_email(raw)
        assert str(reparsed["Subject"]) == "Café — résumé ☕"

    def test_no_bcc_header_in_serialized_bytes(self) -> None:
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["a@b.com"],
            bcc=["secret@hidden.com"],
            subject="x",
            body_text="y",
        )
        raw = msg.as_bytes()
        assert b"Bcc" not in raw
        assert b"secret@hidden.com" not in raw
        assert msg["Bcc"] is None

    def test_reply_headers_passed_through(self) -> None:
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["a@b.com"],
            subject="Re: x",
            body_text="y",
            in_reply_to="<parent@example.com>",
            references="<root@example.com> <parent@example.com>",
        )
        assert msg["In-Reply-To"] == "<parent@example.com>"
        assert msg["References"] == "<root@example.com> <parent@example.com>"


def _parent(message_id: str, subject: str, references: str | None = None) -> bytes:
    lines = [
        "From: someone@example.com",
        "To: brandon@chaosbit.dev",
        f"Subject: {subject}",
        f"Message-ID: {message_id}",
    ]
    if references is not None:
        lines.append(f"References: {references}")
    return ("\r\n".join(lines) + "\r\n\r\nparent body\r\n").encode()


class TestReplyHeadersFrom:
    def test_in_reply_to_is_parent_message_id(self) -> None:
        reply = reply_headers_from(_parent("<parent@example.com>", "Hello"))
        assert reply.in_reply_to == "<parent@example.com>"

    def test_references_chain_appends_parent_when_chain_exists(self) -> None:
        reply = reply_headers_from(
            _parent("<parent@example.com>", "Hello", references="<root@example.com>")
        )
        assert reply.references == "<root@example.com> <parent@example.com>"

    def test_references_is_just_parent_when_no_chain(self) -> None:
        reply = reply_headers_from(_parent("<parent@example.com>", "Hello"))
        assert reply.references == "<parent@example.com>"

    def test_single_re_prefix_added(self) -> None:
        reply = reply_headers_from(_parent("<p@example.com>", "Hello"))
        assert reply.subject == "Re: Hello"

    def test_existing_re_prefix_not_doubled(self) -> None:
        reply = reply_headers_from(_parent("<p@example.com>", "Re: Hello"))
        assert reply.subject == "Re: Hello"

    def test_re_prefix_case_insensitive_reused(self) -> None:
        reply = reply_headers_from(_parent("<p@example.com>", "RE: Hello"))
        assert reply.subject == "RE: Hello"

    def test_missing_message_id_yields_none(self) -> None:
        raw = b"From: x@example.com\r\nSubject: Hi\r\n\r\nbody\r\n"
        reply = reply_headers_from(raw)
        assert reply.in_reply_to is None
        assert reply.references is None
        assert reply.subject == "Re: Hi"
