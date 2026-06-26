"""Reply-header derivation edge cases (RFC 5322 §3.6.4; §6 Compose).

Tech covered single Re:, existing-Re reuse, case-insensitive reuse, chain
append, and missing Message-ID. Wrecker adds the doubling/whitespace variants,
long chains, References-without-Message-ID, and empty-subject replies, plus the
end-to-end build_message wiring of derived headers.
"""

from __future__ import annotations

from comlink.bridge.parsing import build_message, reply_headers_from


def _parent(
    message_id: str | None = None,
    subject: str | None = None,
    references: str | None = None,
) -> bytes:
    lines = ["From: someone@example.com", "To: brandon@chaosbit.dev"]
    if subject is not None:
        lines.append(f"Subject: {subject}")
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    if references is not None:
        lines.append(f"References: {references}")
    return ("\r\n".join(lines) + "\r\n\r\nparent body\r\n").encode()


class TestReplySubjectEdges:
    def test_lowercase_re_reused_not_doubled(self) -> None:
        assert reply_headers_from(_parent("<p@x>", "re: Hi")).subject == "re: Hi"

    def test_re_with_extra_whitespace_reused(self) -> None:
        # Leading whitespace + spaced colon still counts as an existing Re:.
        assert reply_headers_from(_parent("<p@x>", "  RE:  Hi")).subject == "RE:  Hi"

    def test_already_doubled_re_is_not_collapsed_but_no_third_added(self) -> None:
        # DESIGN NOTE: Comlink never ADDS a second Re:; an existing prefix (even a
        # parent-authored "Re: Re:") is left as-is. The guarantee is "don't add
        # doubling", not "normalize the parent's doubling". No THIRD Re: appears.
        result = reply_headers_from(_parent("<p@x>", "Re: Re: Hi")).subject
        assert result == "Re: Re: Hi"
        assert result.count("Re:") == 2

    def test_empty_subject_reply_is_bare_re(self) -> None:
        assert reply_headers_from(_parent("<p@x>", "")).subject == "Re:"

    def test_missing_subject_header_reply_is_bare_re(self) -> None:
        assert reply_headers_from(_parent("<p@x>", None)).subject == "Re:"


class TestReplyChainEdges:
    def test_long_chain_appends_parent_at_end(self) -> None:
        chain = "<r1@x> <r2@x> <r3@x> <r4@x>"
        result = reply_headers_from(_parent("<p@x>", "Hi", chain))
        assert result.references == f"{chain} <p@x>"

    def test_references_without_message_id_keeps_chain_no_in_reply_to(self) -> None:
        # Parent has References but no Message-ID: References survives, but there
        # is no In-Reply-To to set (you can't reference a message with no id).
        result = reply_headers_from(_parent(None, "Hi", "<r1@x> <r2@x>"))
        assert result.references == "<r1@x> <r2@x>"
        assert result.in_reply_to is None

    def test_no_message_id_no_references_yields_nones(self) -> None:
        result = reply_headers_from(_parent(None, "Hi", None))
        assert result.in_reply_to is None
        assert result.references is None
        assert result.subject == "Re: Hi"


class TestReplyHeadersWiredIntoBuild:
    def test_derived_headers_land_in_built_message(self) -> None:
        reply = reply_headers_from(_parent("<p@x>", "Hi", "<r1@x>"))
        msg = build_message(
            from_addr="brandon@chaosbit.dev",
            to=["someone@example.com"],
            subject=reply.subject,
            body_text="ok",
            in_reply_to=reply.in_reply_to,
            references=reply.references,
        )
        assert msg["In-Reply-To"] == "<p@x>"
        assert msg["References"] == "<r1@x> <p@x>"
        assert msg["Subject"] == "Re: Hi"
