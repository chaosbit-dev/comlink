"""Error taxonomy and redaction (§7.4, §8)."""

from __future__ import annotations

from comlink.errors import (
    REDACTED,
    AuthFailed,
    BridgeUnavailable,
    FolderNotFound,
    UidStale,
    redact,
    redacted_message,
)


class TestRedaction:
    def test_redact_scrubs_secret(self) -> None:
        assert redact("login failed for pw=hunter2!", ["hunter2!"]) == (
            f"login failed for pw={REDACTED}"
        )

    def test_redact_scrubs_multiple_occurrences_and_secrets(self) -> None:
        out = redact("a=s1 b=s2 c=s1", ["s1", "s2"])
        assert "s1" not in out
        assert "s2" not in out
        assert out == f"a={REDACTED} b={REDACTED} c={REDACTED}"

    def test_redact_ignores_empty_and_none_secrets(self) -> None:
        assert redact("untouched", [None, ""]) == "untouched"

    def test_redacted_message_from_exception(self) -> None:
        exc = RuntimeError("IMAP said: bad password 'p@ss'")
        assert "p@ss" not in redacted_message(exc, ["p@ss"])


class TestTaxonomyMessages:
    def test_bridge_unavailable_is_actionable(self) -> None:
        err = BridgeUnavailable.for_endpoint("127.0.0.1", 1143)
        assert "127.0.0.1:1143" in str(err)
        assert "Start the Bridge" in str(err)

    def test_auth_failed_mentions_rotation_and_env_var(self) -> None:
        err = AuthFailed.imap()
        assert "rotated" in str(err)
        assert "COMLINK_PASSWORD" in str(err)

    def test_folder_not_found_includes_fuzzy_suggestions(self) -> None:
        err = FolderNotFound.for_name("recipts", ["receipts", "recipes", "INBOX"])
        message = str(err)
        assert "'recipts' not found" in message
        assert "receipts" in message
        assert "recipes" in message
        assert "proton_list_folders" in message

    def test_folder_not_found_without_close_matches(self) -> None:
        err = FolderNotFound.for_name("zzz", ["INBOX", "Sent"])
        assert "No close matches" in str(err)

    def test_uid_stale_names_folder_and_recovery(self) -> None:
        err = UidStale.for_folder("INBOX")
        assert "INBOX" in str(err)
        assert "proton_list_messages" in str(err)
