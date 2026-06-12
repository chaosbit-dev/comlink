"""Integration-test fixtures (design doc §9).

These tests talk to a *live* Proton Mail Bridge on the local machine. They are
marked ``integration`` and excluded from the default ``pytest`` run (see
``[tool.pytest.ini_options]`` in ``pyproject.toml``). They require real Bridge
credentials in the environment:

    COMLINK_USERNAME, and one of COMLINK_PASSWORD / COMLINK_PASSWORD_COMMAND
    (plus COMLINK_TLS_MODE=no-verify or a pinned COMLINK_TLS_CERT_PATH).

Run them explicitly once credentials are available::

    uv run pytest -m integration

Any test whose required config is missing skips rather than fails.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from comlink.bridge.imap import ImapConnectionManager
from comlink.config import ComlinkSettings, load_settings

# A folder that is expected to exist on every Proton account and to contain at
# least one message for the read tests. INBOX is the safe default; override with
# COMLINK_TEST_SEED_FOLDER if a dedicated seed folder is set up.
DEFAULT_SEED_FOLDER = "INBOX"


@pytest.fixture(scope="session")
def settings() -> ComlinkSettings:
    """Load live settings; skip the whole integration suite if unconfigured."""
    try:
        loaded = load_settings()
    except Exception as exc:
        pytest.skip(f"Comlink not configured for integration tests: {exc}")
    if not loaded.username:
        pytest.skip("COMLINK_USERNAME not set; skipping live Bridge integration tests.")
    try:
        loaded.resolve_password()
    except Exception as exc:
        pytest.skip(f"No Bridge password available: {exc}")
    return loaded


@pytest.fixture
async def imap(settings: ComlinkSettings) -> AsyncIterator[ImapConnectionManager]:
    manager = ImapConnectionManager(settings)
    try:
        yield manager
    finally:
        await manager.aclose()


@pytest.fixture(scope="session")
def seed_folder() -> str:
    import os

    return os.environ.get("COMLINK_TEST_SEED_FOLDER", DEFAULT_SEED_FOLDER)
