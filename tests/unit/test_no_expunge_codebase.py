"""Static guard: no EXPUNGE / RFC6851 MOVE anywhere in production code (§3, §7.3).

The no-EXPUNGE invariant is load-bearing for Epic 2: delete = move to Trash,
and the source \\Deleted copies are reconciled by Bridge/Proton, never expunged
by Comlink. The behavioral fakes assert expunge() is never *called*; this test
asserts it is never even *written* — a defense against a future refactor that
swaps the explicit COPY + STORE for imapclient's move()/expunge().
"""

from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "comlink"

# Patterns that would indicate an expunge or RFC6851 MOVE was introduced.
# We match attribute/method calls (".expunge(", ".move("), and the EXPUNGE verb
# in any string that could be sent to the server.
_FORBIDDEN = [
    re.compile(r"\.expunge\s*\("),
    re.compile(r"\.uid_expunge\s*\("),
    re.compile(r"\.move\s*\("),
    re.compile(r"\bEXPUNGE\b"),
]


def _python_sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _strip_comment_explaining_the_ban(line: str) -> str:
    # The imap.py docstring/comment legitimately *mentions* MOVE/EXPUNGE to
    # explain why they are avoided. Drop comment text so prose doesn't trip the
    # grep; only live code matters.
    if "#" in line:
        line = line[: line.index("#")]
    return line


def test_no_expunge_or_rfc6851_move_in_production_code() -> None:
    offenders: list[str] = []
    for path in _python_sources():
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = _strip_comment_explaining_the_ban(raw)
            for pattern in _FORBIDDEN:
                if pattern.search(code):
                    rel = path.relative_to(SRC.parent.parent)
                    offenders.append(f"{rel}:{lineno}: {raw.strip()}")
    assert offenders == [], (
        "No-EXPUNGE invariant violated — production code references EXPUNGE or "
        "RFC6851 MOVE:\n" + "\n".join(offenders)
    )


def test_imap_module_uses_explicit_copy_plus_deleted_flag() -> None:
    # Positive assertion: the move strategy is the documented COPY + STORE
    # \Deleted, so the grep guard above isn't passing vacuously.
    source = (SRC / "bridge" / "imap.py").read_text(encoding="utf-8")
    assert ".copy(" in source
    assert "DELETED_FLAG" in source
    assert "add_flags" in source
