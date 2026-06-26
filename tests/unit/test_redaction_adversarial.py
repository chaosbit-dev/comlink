"""Adversarial attacks on secret redaction (§7.4, Epic 4 redaction audit).

The redaction helper must scrub the Bridge password out of anything that leaves
the server WITHOUT crashing or partial-leaking on hostile password shapes: empty,
one char, a substring of a normal word, regex metacharacters, and the sentinel
"[REDACTED]" itself. The COMLINK_PASSWORD_COMMAND-derived secret must also reach
the redaction set (and _raw_secrets must never raise, even when the command
fails).
"""

from __future__ import annotations

from comlink.errors import REDACTED, redact, redacted_message
from comlink.server import _raw_secrets

from ..conftest import make_settings


class TestRedactHostilePasswordShapes:
    def test_empty_password_is_never_replaced(self) -> None:
        # An empty secret must never become replace("") -> catastrophe.
        assert redact("auth failed", [""]) == "auth failed"

    def test_one_char_password_scrubs_without_crashing(self) -> None:
        # Over-redacts (every 'a' goes) but must not crash or leak the char.
        out = redact("banana auth=a failed", ["a"])
        assert "a" not in out.replace(REDACTED, "")
        assert REDACTED in out

    def test_password_that_is_substring_of_a_word_does_not_crash(self) -> None:
        # 'cat' inside 'category' — over-redaction is acceptable; a crash/leak is not.
        out = redact("category error for cat", ["cat"])
        assert REDACTED in out

    def test_regex_metacharacter_password_is_literal_not_a_pattern(self) -> None:
        # str.replace is literal; a regex-special password must not be interpreted
        # (no re.error) and must be scrubbed verbatim.
        pw = r".*+?[](){}|^$\\"
        text = f"server said bad creds: {pw} end"
        out = redact(text, [pw])
        assert pw not in out
        assert REDACTED in out

    def test_password_with_newlines_and_unicode(self) -> None:
        pw = "p\n@ss🎈word"
        out = redact(f"leak<{pw}>here", [pw])
        assert pw not in out
        assert REDACTED in out

    def test_password_equal_to_redaction_sentinel_is_documented(self) -> None:
        # INFORMATIONAL (not a real-world leak): if the password literally were the
        # sentinel string, replace is a no-op, so the value survives — but it is
        # byte-identical to a normal redaction marker, so no information is exposed
        # to an observer. Documented so the behavior is explicit, not surprising.
        out = redact(f"creds were {REDACTED}", [REDACTED])
        assert out == f"creds were {REDACTED}"

    def test_redacted_message_never_raises_on_hostile_shapes(self) -> None:
        for pw in ("", "a", r"[a-z]+", REDACTED, "🎈"):
            exc = RuntimeError(f"boom {pw}")
            # Must not raise; that is the whole guarantee.
            assert isinstance(redacted_message(exc, [pw]), str)


class TestCommandDerivedRedactionSet:
    def test_resolved_command_secret_enters_redaction_set_with_stderr_noise(self) -> None:
        # The command prints the secret to stdout (the resolved password) and noise
        # to stderr; _raw_secrets must still capture the stdout secret for scrubbing.
        secret = "keychain-derived-pw-7Q"
        settings = make_settings(
            username="x@y.com",
            password=None,
            password_command=f"printf %s {secret}; printf noise 1>&2",
        )
        secrets = [s for s in _raw_secrets(settings) if s]
        assert secret in secrets

    def test_raw_secrets_swallows_failing_command_and_never_raises(self) -> None:
        # A command that exits non-zero must not blow up redaction-set assembly;
        # the set is simply best-effort (may lack the secret, never throws).
        settings = make_settings(
            username="x@y.com",
            password=None,
            password_command="printf oops 1>&2; exit 3",
        )
        # The whole point: no exception escapes.
        secrets = _raw_secrets(settings)
        assert isinstance(secrets, list)

    def test_command_secret_scrubbed_from_error_even_with_static_password_none(self) -> None:
        # Parity with the static-password path: a surfaced error echoing the
        # command-derived secret must be scrubbed though settings.password is None.
        secret = "cmd-only-secret-42"
        settings = make_settings(
            username="x@y.com",
            password=None,
            password_command=f"printf %s {secret}",
        )
        exc = RuntimeError(f"bridge said: bad creds {secret}")
        out = redacted_message(exc, _raw_secrets(settings))
        assert secret not in out
        assert REDACTED in out


def test_both_static_and_command_secrets_scrubbed_together() -> None:
    # When both are configured the command wins as the live credential, but BOTH
    # must be in the redaction set so neither can survive into surfaced text.
    static_pw = "static-side-pw"
    cmd_secret = "command-side-pw"
    settings = make_settings(
        username="x@y.com",
        password=static_pw,
        password_command=f"printf %s {cmd_secret}",
    )
    text = f"leak {static_pw} and {cmd_secret} both"
    out = redact(text, _raw_secrets(settings))
    assert static_pw not in out
    assert cmd_secret not in out
